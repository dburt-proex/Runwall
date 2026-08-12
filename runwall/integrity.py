"""Tamper-evidence for the decision ledger.

Deliberately byte-identical to DaxxerOS Local's ``daxxer/integrity.py``: the same
canonical serialization, the same SHA-256 construction, the same GENESIS value.
Runwall reimplements rather than imports it so the two systems have no runtime
coupling -- but ``tests/test_integrity_parity.py`` asserts the two produce the
same hash for the same event, so a divergence is a test failure, not a silent
incompatibility. One verifier can walk either chain.

What a hash chain buys, precisely: an append-only file is only append-only by
convention; any text editor can rewrite it. Each event embeds the SHA-256 of
(previous hash + its own canonical payload), so altering, reordering or deleting
any historical event breaks every hash downstream of it.

What it does NOT buy: prevention. An attacker who can write the file can also
recompute the whole chain in milliseconds. Detection only survives if the chain
HEAD lives somewhere the attacker cannot rewrite -- see ``anchor_head`` and the
``harden`` command. Until then this is tamper-evident against accident and
casual edit, not against a determined same-privilege attacker. Say so; do not
let the presence of a hash chain imply more than it delivers.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading

GENESIS = "0" * 64


def canonical(event: dict) -> str:
    """Deterministic serialization of an event, excluding its own hash fields."""
    payload = {k: v for k, v in event.items() if k not in ("hash", "prev_hash")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def event_hash(prev_hash: str, event: dict) -> str:
    return hashlib.sha256((prev_hash + canonical(event)).encode("utf-8")).hexdigest()


def last_hash(path: str) -> str:
    """Hash of the final event in the log, or GENESIS if the log is empty."""
    if not os.path.exists(path):
        return GENESIS
    tail = GENESIS
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                tail = json.loads(line).get("hash") or tail
            except json.JSONDecodeError:
                continue
    return tail


def verify(path: str):
    """Walk the chain. Returns (ok: bool, checked: int, problems: list[str])."""
    problems: list[str] = []
    if not os.path.exists(path):
        return True, 0, ["decision ledger does not exist yet (nothing to verify)"]

    prev = GENESIS
    checked = 0
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                problems.append(f"line {lineno}: unparseable JSON ({exc})")
                return False, checked, problems

            checked += 1
            stored = event.get("hash")
            if stored is None:
                problems.append(
                    f"line {lineno}: event without hash "
                    f"(decision_id={event.get('decision_id')}) - unverifiable"
                )
                return False, checked, problems

            if event.get("prev_hash") != prev:
                problems.append(
                    f"line {lineno}: chain break - prev_hash does not match preceding "
                    f"event (decision_id={event.get('decision_id')})"
                )
                return False, checked, problems

            if event_hash(prev, event) != stored:
                problems.append(
                    f"line {lineno}: TAMPERED - content does not match its hash "
                    f"(decision_id={event.get('decision_id')})"
                )
                return False, checked, problems
            prev = stored

    return True, checked, problems


# --------------------------------------------------------------------------
# Monotonic sequence
# --------------------------------------------------------------------------
# Ordering must not depend on the wall clock. A local administrator can set the
# system clock backwards, which would let a forged event be inserted with a
# plausible earlier timestamp AND would break TOTP windows and time-boxed
# disarm. The sequence counter is therefore persisted separately and only ever
# increases -- a decreasing seq in the ledger is itself evidence of tampering.

_seq_lock = threading.Lock()


def next_seq(state_dir: str) -> int:
    """Return a strictly increasing sequence number, persisted across restarts."""
    path = os.path.join(state_dir, "seq")
    with _seq_lock:
        current = 0
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    current = int(f.read().strip() or 0)
            except (ValueError, OSError):
                # A corrupt counter must never silently restart at zero -- that
                # would let an attacker replay sequence numbers. Jump forward
                # past any plausible prior value instead.
                current = _highest_seq_seen(state_dir)
        nxt = current + 1
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(str(nxt))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return nxt


def _highest_seq_seen(state_dir: str) -> int:
    """Recover the counter from the ledger itself when the counter file is lost."""
    ledger = os.path.join(state_dir, "gate_decisions.jsonl")
    highest = 0
    if not os.path.exists(ledger):
        return highest
    with open(ledger, encoding="utf-8") as f:
        for line in f:
            try:
                highest = max(highest, int(json.loads(line).get("seq") or 0))
            except (json.JSONDecodeError, ValueError, TypeError):
                continue
    return highest


# --------------------------------------------------------------------------
# Head anchoring
# --------------------------------------------------------------------------


def anchor_head(anchor_path: str, head: str, seq: int, ledger_path: str = "") -> None:
    """Record the current chain head where the agent's principal cannot rewrite it.

    In the default (unhardened) deployment this is an ordinary file and provides
    no real protection -- it is written anyway so that the hardened deployment is
    a permissions change rather than a code change. ``runwall harden`` ACLs this
    path to the governor's service account; from that point a rewritten ledger
    no longer matches the anchor and ``verify`` reports the divergence.

    The anchored ledger path is stored alongside the head. The anchor lives at a
    fixed location while the ledger path depends on whether DaxxerOS Local is
    present, so without this an environment change would make ``check_anchor``
    compare a head against a completely different file and report tampering. A
    false tamper alarm is exactly as corrosive as a missed one -- it is the
    alarm people learn to ignore.
    """
    os.makedirs(os.path.dirname(anchor_path), exist_ok=True)
    tmp = anchor_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"head": head, "seq": seq,
                   "ledger": os.path.normcase(os.path.abspath(ledger_path))
                   if ledger_path else ""}, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, anchor_path)


def check_anchor(anchor_path: str, ledger_path: str):
    """Compare the ledger's head against the anchor. Returns (ok, message)."""
    if not os.path.exists(anchor_path):
        return True, "no anchor recorded yet"
    try:
        with open(anchor_path, encoding="utf-8") as f:
            anchor = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        return False, f"anchor unreadable: {exc}"

    anchored_ledger = anchor.get("ledger") or ""
    current = os.path.normcase(os.path.abspath(ledger_path))
    if anchored_ledger and anchored_ledger != current:
        # Not a tamper signal: the anchor describes a ledger we are not looking
        # at. Say so precisely instead of raising an alarm nobody can action.
        return True, (f"anchor describes a different ledger "
                      f"({anchored_ledger}) - not applicable to {current}")

    head = last_hash(ledger_path)
    if anchor.get("head") != head:
        return False, (
            "ANCHOR MISMATCH - the ledger head does not match the last anchored "
            "head. The ledger has been truncated or rewritten since it was last "
            f"anchored (anchored seq={anchor.get('seq')})."
        )
    return True, "anchor matches ledger head"
