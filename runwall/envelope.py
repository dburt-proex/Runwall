"""The ActionEnvelope -- what the governor actually decides on.

Everything security-relevant that can go wrong before a rule ever runs happens
here. A rule that greps for ``rm -rf`` is worth nothing if the caller can write
``rm$([char]32)-rf``, base64 the command, or point at ``PROGRA~1`` instead of
``Program Files``. Classification quality is bounded by normalization quality,
so normalization is treated as the security control and the rules are treated
as policy expressed over its output.

Two views of every action are kept, and both are recorded:

    raw         exactly what the harness handed us -- the evidence
    normalized  decoded, NFC-folded, path-canonicalized -- what rules match on

Rules match on ``normalized``. The ledger stores both, because a decision that
cannot be re-derived from the evidence is not auditable.

Bounded, not complete. Deobfuscation is adversarial and unbounded in principle;
``deep_decode`` runs a fixed number of passes and stops. When it stops with
layers still evidently remaining, that fact is itself a finding -- see
``residual_encoding``. Unexplained obfuscation is signal, not noise.
"""
from __future__ import annotations

import base64
import binascii
import ctypes
import os
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

# A payload larger than this is refused outright. Rejecting on size is not an
# optimization: an oversized envelope is the cheapest way to push the governor
# past the harness's hook timeout, and a hook that times out is a hook that
# fails open. Refuse fast instead.
MAX_PAYLOAD_BYTES = 512 * 1024
MAX_DECODE_PASSES = 4
# 12 rather than 16: `rm -rf /etc` base64-encodes to 15 characters before
# padding, and a threshold that misses short destructive payloads is a
# threshold tuned for the wrong side of the trade.
MIN_B64_LEN = 12


# --------------------------------------------------------------------------
# Text normalization
# --------------------------------------------------------------------------

_PS_ENCODED = re.compile(
    r"-(?:enc|e|ec|encoded|encodedcommand)\s+([A-Za-z0-9+/=]{%d,})" % MIN_B64_LEN,
    re.IGNORECASE,
)
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % MIN_B64_LEN)
_HEX_ESCAPE = re.compile(r"(?:\\x|%|\$\{?0x)([0-9a-fA-F]{2})", re.IGNORECASE)
_PS_CHAR = re.compile(r"\[char\]\s*(\d{1,3})", re.IGNORECASE)
_PS_BACKTICK = re.compile(r"`(.)")
# Collapse 'Rem'+'ove-Item' to Remove-Item, consuming the surrounding quotes as
# well as the join. Leaving the outer quotes in place would produce 'remove-item',
# which no longer matches a rule anchored on a word boundary -- the obfuscation
# would survive the deobfuscation pass.
_CONCAT = re.compile(r"'([^']*)'\s*\+\s*'([^']*)'|\"([^\"]*)\"\s*\+\s*\"([^\"]*)\"")
# r''m -- empty quotes wedged inside a word to break up a token.
_EMPTY_QUOTES = re.compile(r"(?<=\w)(''|\"\")(?=\w)")
_WS = re.compile(r"\s+")


def _ascii_ratio(s: str) -> float:
    """Fraction of characters that are ordinary ASCII text.

    Deliberately NOT `str.isprintable`. UTF-8 bytes decoded as UTF-16LE produce
    CJK codepoints, and those *are* printable -- so a printability test happily
    accepts the wrong decoding and returns garbage. Since the payloads we care
    about are commands, and commands are ASCII, scoring on ASCII-ness is what
    actually distinguishes the right decoding from the wrong one.
    """
    if not s:
        return 0.0
    ok = sum(1 for ch in s if (32 <= ord(ch) < 127) or ch in "\r\n\t")
    return ok / len(s)


def _try_b64(blob: str) -> str | None:
    """Decode a base64 blob, choosing the encoding that yields the most text.

    PowerShell's -EncodedCommand is UTF-16LE; most other payloads are UTF-8.
    Both are tried and the better-scoring result wins, rather than taking the
    first that merely parses -- taking the first is how a double-encoded payload
    resolves to plausible-looking garbage and slips past every rule downstream.
    """
    padded = blob + "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None

    best, best_score = None, 0.0
    for encoding in ("utf-8", "utf-16-le"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        score = _ascii_ratio(text)
        if score > best_score:
            best, best_score = text, score

    if best is not None and best_score > 0.85 and len(best.strip()) > 2:
        return best
    return None


def _decode_pass(text: str) -> str:
    """One deobfuscation pass. Idempotent when there is nothing left to decode."""
    # PowerShell -EncodedCommand: replace the flag and its blob with the payload,
    # so the decoded command sits inline where rules will see it.
    def _sub_encoded(m: re.Match) -> str:
        decoded = _try_b64(m.group(1))
        return f" {decoded} " if decoded else m.group(0)

    text = _PS_ENCODED.sub(_sub_encoded, text)

    # Bare base64 blobs anywhere in the payload.
    def _sub_blob(m: re.Match) -> str:
        decoded = _try_b64(m.group(0))
        return f" {decoded} " if decoded else m.group(0)

    text = _B64_BLOB.sub(_sub_blob, text)

    # [char]47 -> "/"   percent/hex escapes -> literal
    text = _PS_CHAR.sub(lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), text)
    text = _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)

    # PowerShell backtick escaping (rm`-rf) and string-concat splitting
    # ('Rem'+'ove-Item') are pure obfuscation -- collapse both.
    text = _PS_BACKTICK.sub(r"\1", text)
    text = _CONCAT.sub(lambda m: "".join(g for g in m.groups() if g is not None), text)
    text = _EMPTY_QUOTES.sub("", text)
    return text


def deep_decode(text: str, max_passes: int = MAX_DECODE_PASSES) -> tuple[str, int]:
    """Iteratively deobfuscate. Returns (decoded, passes_used)."""
    passes = 0
    for _ in range(max_passes):
        nxt = _decode_pass(text)
        if nxt == text:
            break
        text = nxt
        passes += 1
    return text, passes


def residual_encoding(text: str) -> bool:
    """True if decoding stopped with obvious encoding still present.

    Reaching the pass ceiling with recognisable base64 still in the payload
    means we ran out of budget, not that the payload was clean. That is a
    finding in its own right: unexplained layered encoding in an agent-issued
    command has no legitimate use that a plain command would not serve.
    """
    return bool(_B64_BLOB.search(text) and _try_b64(_B64_BLOB.search(text).group(0)))


def normalize_text(text: str) -> str:
    """NFC-fold, decode, collapse whitespace, casefold. The rule-matching view.

    Unicode normalization matters because the classifier and the executor must
    agree on what the string IS. Windows resolves NFD and NFC to the same file;
    a naive regex does not. Normalize once, here, and let every rule match the
    same bytes the OS will act on.
    """
    if not text:
        return ""
    text = unicodedata.normalize("NFC", text)
    text, _ = deep_decode(text)
    text = unicodedata.normalize("NFC", text)
    return _WS.sub(" ", text).strip().casefold()


# --------------------------------------------------------------------------
# Path canonicalization
# --------------------------------------------------------------------------

_UNC_SELF = re.compile(r"^\\\\(?:localhost|127\.0\.0\.1|\.)\\([a-z])\$", re.IGNORECASE)


def _long_path(p: str) -> str:
    """Expand an 8.3 short name (PROGRA~1) to its long form via Win32."""
    if os.name != "nt":
        return p
    try:
        GetLongPathNameW = ctypes.windll.kernel32.GetLongPathNameW
        buf = ctypes.create_unicode_buffer(32768)
        n = GetLongPathNameW(p, buf, 32768)
        return buf.value if n else p
    except (AttributeError, OSError):
        return p


def canonical_path(p: str) -> str:
    """Resolve a path to the single form rules and ACLs both agree on.

    Every transformation here corresponds to a real bypass of a string-matching
    denylist: environment indirection, 8.3 short names, the \\\\?\\ prefix,
    UNC-to-self (\\\\localhost\\C$), junctions and symlinks, and Windows'
    silent stripping of trailing dots and spaces.

    This reduces string-level evasion. It does not close the TOCTOU window --
    the path can be replaced with a junction between decision and execution.
    Only deciding on an open handle closes that, which a PreToolUse hook cannot
    do because it does not perform the operation. Treat path decisions as
    advisory against an active attacker and back them with ACLs.
    """
    if not p:
        return ""
    p = os.path.expandvars(os.path.expanduser(str(p)))
    p = unicodedata.normalize("NFC", p)

    if p.startswith("\\\\?\\UNC\\"):
        p = "\\\\" + p[8:]
    elif p.startswith("\\\\?\\"):
        p = p[4:]

    m = _UNC_SELF.match(p)
    if m:
        p = f"{m.group(1)}:" + p[m.end():]

    # Windows discards trailing dots and spaces in path components; a denylist
    # that does not will miss "policy.yml." pointing at "policy.yml".
    # A leading double separator is what makes a path UNC. Splitting on
    # [\\/]+ and rejoining with a single os.sep silently converted
    # \\server\share into \server\share -- a root-relative local path, not the
    # remote path the OS would actually act on, so every comparison downstream
    # was made against the wrong target.
    unc = p[:2] in ("\\\\", "//")
    parts = re.split(r"[\\/]+", p)
    parts = [seg.rstrip(" .") if i or not re.match(r"^[a-zA-Z]:$", seg) else seg
             for i, seg in enumerate(parts)]
    p = os.sep.join(parts)
    if unc:
        p = os.sep * 2 + p.lstrip("\\/")

    p = _long_path(p)
    p_before_realpath = p
    try:
        p = os.path.realpath(p)
    except (OSError, ValueError):
        pass
    # On POSIX, realpath may collapse a leading "//" to "/", but a UNC path
    # must keep exactly two leading separators to remain a network path.
    # Restore from the pre-resolve form rather than stripping slashes from the
    # potentially-resolved absolute path, which may have a different host.
    if unc and not (p.startswith("\\\\") or p.startswith("//")):
        p = os.sep * 2 + p_before_realpath.lstrip("/\\")
    return os.path.normcase(os.path.normpath(p))


# --------------------------------------------------------------------------
# The envelope
# --------------------------------------------------------------------------

# Which parameter of which tool carries the thing that actually happens. Used to
# extract command text and target paths without the agent telling us where to
# look.
_TEXT_PARAMS = ("command", "content", "new_string", "prompt", "query", "url", "pattern")
_PATH_PARAMS = ("file_path", "path", "notebook_path", "cwd")

# The action/content split. A shell command IS the action, so its text is what
# the action does. A file's contents are DATA the action stores -- prose that
# happens to mention `.env` is not an attempt to read `.env`.
#
# Collapsing the two means a document describing a threat model trips the threat
# rules, and security documentation becomes unwritable while the wall is armed.
# That is not a hypothetical: it blocked a write to an unrelated file and is the
# reason this split exists. False positives are security failures here, because
# every over-block trains the operator toward disarming.
_ACTION_PARAMS = ("command", "url", "query", "pattern")
_CONTENT_PARAMS = ("content", "new_string", "prompt")
_WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")

# Path-shaped tokens inside free text (a shell command names its targets in the
# command string, not in a path parameter). Matching *canonicalized tokens*
# rather than substrings is the difference between a usable rule and a rule that
# fires on "webhook.site" because it contains "hook" -- a false positive rate
# like that trains the operator to click approve, which is a security failure
# dressed as a usability one.
_PATH_TOKEN = re.compile(
    # absolute, drive-qualified, ./ ../ or ~/ prefixed
    r"""(?:[a-zA-Z]:[\\/]|\.{1,2}[\\/]|~[\\/]|(?<![\w:/])[\\/])[^\s'"<>|;&,)]{1,300}"""
    # bare relative path carrying a separator -- `policy/default.yml`, with no
    # `./` prefix, is how a denylist keyed on prefixed paths gets walked around
    r"""|(?<![\w.:/\\-])[\w.-]{1,80}(?:[\\/][\w.-]{1,80}){1,12}"""
    # bare filename with a telling extension
    r"""|(?<![\w.])[\w.-]{1,80}\.(?:json|ya?ml|jsonl|token|key|anchor|env|pem|"""
    r"""cfg|ini|toml|db|sqlite|sh|ps1|py|js)(?![\w])""")


def extract_paths(text: str) -> list[str]:
    """Canonicalized path-like tokens found in free text."""
    if not text:
        return []
    out: list[str] = []
    for m in _PATH_TOKEN.finditer(text):
        token = m.group(0).strip().rstrip(".,;:")
        # A URL is not a filesystem path; treating it as one is how "//" in
        # "https://" ends up canonicalized into a bogus local path.
        if "://" in token or token.startswith("//"):
            continue
        cp = canonical_path(token)
        if cp and cp not in out:
            out.append(cp)
    return out[:64]


@dataclass
class ActionEnvelope:
    """One proposed action, normalized. The unit the governor decides on."""

    envelope_id: str
    seq: int
    ts: str
    session_id: str
    agent_id: str
    harness: str
    tool: str
    raw_params: dict[str, Any]
    cwd: str = ""
    user_turn_id: str = ""

    # Derived at construction -- never supplied by the caller.
    text: str = ""
    normalized: str = ""
    # Action text only -- excludes file contents. Rules that reason about what
    # an action DOES match on this; only injection rules, which are about what
    # gets stored for the next reader, scan `normalized`.
    normalized_action: str = ""
    # Folded but NOT deobfuscated. Some signals live in the encoding itself --
    # a 30-character base64 DNS label is evidence of a covert channel, and
    # successfully decoding it destroys exactly the structure that made it
    # suspicious. Rules that reason about *how* something is encoded match on
    # this view; rules that reason about what it does match on `normalized`.
    normalized_raw: str = ""
    paths: list[str] = field(default_factory=list)
    text_paths: list[str] = field(default_factory=list)
    decode_passes: int = 0
    residual_encoding: bool = False
    oversized: bool = False

    @classmethod
    def from_hook_payload(cls, payload: dict, *, envelope_id: str, seq: int, ts: str,
                          agent_id: str = "unknown") -> "ActionEnvelope":
        """Build from a Claude Code PreToolUse hook payload.

        Note what is NOT read from the payload: the action label. The agent
        controls the shape of its own tool call, so any label it supplies is
        attacker-controlled input to the gate lookup. The label is derived
        server-side in ``classify.py`` from the normalized text instead.
        """
        params = payload.get("tool_input") or {}
        env = cls(
            envelope_id=envelope_id,
            seq=seq,
            ts=ts,
            session_id=str(payload.get("session_id") or ""),
            agent_id=agent_id,
            harness=str(payload.get("harness") or "claude-code"),
            tool=str(payload.get("tool_name") or "unknown"),
            raw_params=params if isinstance(params, dict) else {"_": params},
            cwd=str(payload.get("cwd") or ""),
            user_turn_id=str(payload.get("user_turn_id") or ""),
        )
        env._derive()
        return env

    def _derive(self) -> None:
        blob = repr(self.raw_params)
        if len(blob.encode("utf-8", "ignore")) > MAX_PAYLOAD_BYTES:
            self.oversized = True
            self.text = blob[:2000]
            self.normalized = normalize_text(self.text)
            return

        chunks: list[str] = []
        for key in _TEXT_PARAMS:
            val = self.raw_params.get(key)
            if isinstance(val, str):
                chunks.append(val)
        # Path parameters belong in the matched text too. A Write whose danger
        # lives entirely in its destination -- sitecustomize.py, .bashrc, a Run
        # key -- carries nothing incriminating in its content, and a rule that
        # only ever sees `content` is blind to exactly those cases.
        for key in _PATH_PARAMS:
            val = self.raw_params.get(key)
            if isinstance(val, str) and val.strip():
                chunks.append(val)
        if not chunks:
            # Unknown tool shape: fall back to every string value present, so a
            # new or renamed parameter cannot smuggle a payload past the rules
            # simply by not being on the known list.
            chunks = [v for v in self.raw_params.values() if isinstance(v, str)]

        self.text = "\n".join(chunks)
        decoded, passes = deep_decode(unicodedata.normalize("NFC", self.text))
        self.decode_passes = passes
        self.residual_encoding = residual_encoding(decoded)
        self.normalized = normalize_text(self.text)
        self.normalized_raw = _WS.sub(
            " ", unicodedata.normalize("NFC", self.text)).strip().casefold()

        action_chunks = [v for k, v in self.raw_params.items()
                         if k in _ACTION_PARAMS and isinstance(v, str)]
        action_chunks += [v for k, v in self.raw_params.items()
                          if k in _PATH_PARAMS and isinstance(v, str)]
        if not action_chunks and not any(k in _CONTENT_PARAMS for k in self.raw_params):
            # Unknown tool shape with nothing recognisably content-like: treat
            # the whole payload as action text rather than exempting it.
            action_chunks = [v for v in self.raw_params.values() if isinstance(v, str)]
        self.normalized_action = normalize_text("\n".join(action_chunks))

        seen: list[str] = []
        for key in _PATH_PARAMS:
            val = self.raw_params.get(key)
            if isinstance(val, str) and val.strip():
                cp = canonical_path(val)
                if cp and cp not in seen:
                    seen.append(cp)
        self.paths = seen
        # Only mine ACTION text for paths. Pulling them out of file contents is
        # what made a document about `.env` indistinguishable from a write to
        # `.env`.
        action_source, _ = deep_decode(unicodedata.normalize("NFC", "\n".join(action_chunks)))
        self.text_paths = [p for p in extract_paths(action_source) if p not in seen]

    def all_paths(self) -> list[str]:
        """Declared parameters plus paths named in action text."""
        return self.paths + self.text_paths

    def target_paths(self) -> list[str]:
        """Paths this action acts ON, as opposed to paths it merely names.

        For a write tool the target is the declared `file_path`; anything inside
        `content` is data. For a shell command the targets genuinely live in the
        command string, so both sources count.
        """
        if self.tool in _WRITE_TOOLS:
            return list(self.paths)
        return self.all_paths()

    def to_dict(self) -> dict:
        return {
            "envelope_id": self.envelope_id,
            "seq": self.seq,
            "ts": self.ts,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "harness": self.harness,
            "tool": self.tool,
            "cwd": self.cwd,
            "user_turn_id": self.user_turn_id,
            "raw_params": self.raw_params,
            "normalized": self.normalized,
            "normalized_raw": self.normalized_raw,
            "paths": self.paths,
            "text_paths": self.text_paths,
            "decode_passes": self.decode_passes,
            "residual_encoding": self.residual_encoding,
            "oversized": self.oversized,
        }
