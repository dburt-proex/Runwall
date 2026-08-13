"""Operator authentication, TOTP, and the split-key model.

**Split keys, and why.** If one token both requests decisions and approves them,
then an agent that reads that token off disk can approve its own actions -- and
the ledger will attribute the approval to a human. Two keys, with different
lifetimes and different storage:

    client.token    lets a caller ASK for a decision. The hook needs it, so it
                    must be readable by the agent's principal. It can do nothing
                    else: no approve, no disarm, no policy change, no ledger read.
    approval.key    authenticates the console. Never handed to a hook, and under
                    `runwall harden` it is ACL'd away from the agent's account
                    entirely.

So the worst case from a stolen client token is an agent that can ask questions
it already knows the answers to.

**TOTP is attribution, not access prevention.** Step-up binds a named operator to
a privileged decision so the ledger records who authorised what. It is not a
barrier against a process already running as that operator.

Both primitives are stdlib: scrypt for passwords, HMAC-SHA1 for RFC 6238. A
security tool that pulls in transitive dependencies to hash a password has
enlarged its own attack surface to save twenty lines.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time

SESSION_TTL_S = 3600
STEP_UP_TTL_S = 120        # a step-up authorises one decision, not a shift
MAX_FAILED = 5
LOCKOUT_S = 300


# --------------------------------------------------------------------------
# TOTP (RFC 6238)
# --------------------------------------------------------------------------

def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_at(secret_b32: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def verify_totp(secret_b32: str, code: str, *, window: int = 1, period: int = 30) -> bool:
    """Constant-time check across a +/-1 step window for clock skew.

    Note the residual risk this cannot address: a local administrator can set the
    system clock, and every time-based control on this machine -- TOTP windows,
    time-boxed disarm, grant expiry -- moves with it. That is an argument for
    `runwall harden` and an external time source, not something a wider window
    fixes.
    """
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    counter = int(time.time() // period)
    return any(hmac.compare_digest(totp_at(secret_b32, counter + drift), code)
               for drift in range(-window, window + 1))


def provisioning_uri(secret_b32: str, account: str, issuer: str = "Runwall") -> str:
    return (f"otpauth://totp/{issuer}:{account}?secret={secret_b32}"
            f"&issuer={issuer}&algorithm=SHA1&digits=6&period=30")


# --------------------------------------------------------------------------
# Passwords
# --------------------------------------------------------------------------

# n=2^15,r=8 needs 128*n*r = 32 MiB. OpenSSL's default maxmem is exactly 32 MiB
# and rejects the allocation, so it must be raised explicitly -- without this,
# every login raises "memory limit exceeded" and the console is unreachable.
_SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1, "dklen": 32, "maxmem": 96 * 1024 * 1024}


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, dk_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), **_SCRYPT)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, AttributeError):
        return False


# --------------------------------------------------------------------------
# Key material on disk
# --------------------------------------------------------------------------

def _atomic_write(path: str, data: str, *, private: bool) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    if private:
        try:
            os.chmod(path, 0o600)
        except OSError:
            # POSIX modes are advisory on Windows. Real protection for these
            # files comes from the ACLs applied by `runwall harden`, not here.
            pass


def ensure_client_token(state_dir: str) -> str:
    path = os.path.join(state_dir, "client.token")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            tok = f.read().strip()
            if tok:
                return tok
    tok = secrets.token_urlsafe(32)
    _atomic_write(path, tok, private=False)
    return tok


def ensure_approval_key(state_dir: str) -> str:
    path = os.path.join(state_dir, "approval.key")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_urlsafe(32)
    _atomic_write(path, key, private=True)
    return key


# --------------------------------------------------------------------------
# Operator record + sessions
# --------------------------------------------------------------------------

class OperatorStore:
    """One operator. Multi-operator is a deliberate non-goal for v1."""

    def __init__(self, state_dir: str) -> None:
        self.path = os.path.join(state_dir, "operator.json")
        self.state_dir = state_dir
        self._lock = threading.Lock()
        self._sessions: dict[str, dict] = {}
        self._failed = 0
        self._locked_until = 0.0

    # -- enrollment --------------------------------------------------------

    def enrolled(self) -> bool:
        return os.path.exists(self.path)

    def enroll(self, operator_id: str, password: str, sitekey: str) -> dict:
        """Create the operator record. Returns the TOTP secret and its URI.

        ``sitekey`` is a phrase the operator chooses and the console then
        displays on every approval card. An approval prompt rendered by
        something other than the real console will not know it, which makes a
        spoofed prompt visibly wrong rather than merely suspicious.
        """
        secret = new_totp_secret()
        record = {
            "operator_id": operator_id,
            "password": hash_password(password),
            "totp_secret": secret,
            "sitekey": sitekey,
            "enrolled_at": time.time(),
        }
        _atomic_write(self.path, json.dumps(record, indent=2), private=True)
        return {"totp_secret": secret,
                "uri": provisioning_uri(secret, operator_id),
                "sitekey": sitekey}

    def _load(self) -> dict | None:
        if not os.path.exists(self.path):
            return None
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    def sitekey(self) -> str:
        rec = self._load()
        return rec.get("sitekey", "") if rec else ""

    # -- login -------------------------------------------------------------

    def login(self, operator_id: str, password: str, totp: str) -> tuple[str | None, str]:
        """Password AND TOTP. Returns (session_token, message)."""
        with self._lock:
            if time.time() < self._locked_until:
                return None, f"locked out for {int(self._locked_until - time.time())}s"

        rec = self._load()
        if not rec:
            return None, "no operator enrolled - run `runwall enroll`"

        # Every factor is evaluated, then combined. Short-circuiting with `and`
        # meant a wrong operator id returned before the ~100 ms scrypt
        # derivation ran, so the id was enumerable by timing despite the
        # deliberately uniform failure message below.
        id_ok = hmac.compare_digest(rec["operator_id"], operator_id)
        pw_ok = verify_password(password, rec["password"])
        totp_ok = verify_totp(rec["totp_secret"], totp)
        ok = id_ok & pw_ok & totp_ok
        if not ok:
            with self._lock:
                self._failed += 1
                if self._failed >= MAX_FAILED:
                    self._locked_until = time.time() + LOCKOUT_S
                    self._failed = 0
                    return None, f"too many failures - locked out for {LOCKOUT_S}s"
            # One message for every failure mode: which factor was wrong is not
            # information an attacker gets for free.
            return None, "invalid credentials"

        with self._lock:
            self._failed = 0
            token = secrets.token_urlsafe(32)
            self._sessions[token] = {"operator_id": operator_id,
                                     "issued": time.time(),
                                     "last_seen": time.time(),
                                     "step_up_until": 0.0}
        return token, "authenticated"

    def logout(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def session(self, token: str) -> dict | None:
        with self._lock:
            s = self._sessions.get(token or "")
            if not s:
                return None
            if time.time() - s["issued"] > SESSION_TTL_S:
                self._sessions.pop(token, None)
                return None
            s["last_seen"] = time.time()
            return dict(s)

    def operator_present(self, within_s: int = 300) -> bool:
        """Is a human actually watching? Decides whether REVIEW can block."""
        with self._lock:
            now = time.time()
            return any(now - s["last_seen"] < within_s
                       and now - s["issued"] < SESSION_TTL_S
                       for s in self._sessions.values())

    # -- step-up -----------------------------------------------------------

    def step_up(self, token: str, totp: str) -> tuple[bool, str]:
        """Re-assert presence with a fresh TOTP for one privileged decision."""
        rec = self._load()
        if not rec:
            return False, "no operator enrolled"
        with self._lock:
            s = self._sessions.get(token or "")
        if not s:
            return False, "not authenticated"
        if not verify_totp(rec["totp_secret"], totp):
            return False, "invalid code"
        with self._lock:
            self._sessions[token]["step_up_until"] = time.time() + STEP_UP_TTL_S
        return True, "step-up authenticated"

    def has_step_up(self, token: str) -> bool:
        with self._lock:
            s = self._sessions.get(token or "")
            return bool(s and time.time() < s.get("step_up_until", 0))

    def consume_step_up(self, token: str) -> None:
        """Single-use. A step-up authorises one action, not a window of them."""
        with self._lock:
            if token in self._sessions:
                self._sessions[token]["step_up_until"] = 0.0
