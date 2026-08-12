"""The decision ledger -- hash-chained, redacted at write, never silent.

Every decision lands here, including ALLOW. A ledger that records only refusals
answers "what did Runwall block?" but not "what did this agent do?", and the
second question is the one a compliance review actually asks.

Two disciplines carried over from ``daxxer/audit.py``, both deliberate:

**Never fail silently.** A write that cannot be made durable raises. An audit
control that swallows its own failure is worse than no audit control, because it
manufactures confidence. When the ledger cannot be written the perimeter drops
to SAFE rather than continuing to decide without recording.

**Redact at write, not at read.** Tool parameters carry API keys, tokens and
connection strings. Once a secret is in an append-only hash-chained file it
cannot be removed without breaking the chain -- so the redaction has to happen
before the bytes land, and a redaction is recorded as a marker so a reviewer can
see that something was removed rather than wondering whether the field was empty.

The ledger is consequently the highest-value file on the machine: it holds
prompts, paths and arguments across every governed session. It is treated as
sensitive data in its own right -- reads are gated and export counts as an
egress event.
"""
from __future__ import annotations

import json
import os
import re
import threading

from . import integrity

# Redaction patterns. Over-redaction is cheap; under-redaction is permanent.
_REDACTIONS = [
    (re.compile(r"(?i)\b(sk-[a-z0-9]{16,}|ghp_[a-z0-9]{20,}|gho_[a-z0-9]{20,}|"
                r"github_pat_[a-z0-9_]{20,}|xox[baprs]-[a-z0-9-]{10,})"), "API_KEY"),
    (re.compile(r"(?i)\bAKIA[0-9A-Z]{16}\b"), "AWS_ACCESS_KEY"),
    (re.compile(r"(?i)\b(bearer)\s+[a-z0-9._\-]{16,}"), "BEARER_TOKEN"),
    (re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)"
                r"\s*[=:]\s*[\"']?([^\s\"'&;]{6,})"), "SECRET_ASSIGNMENT"),
    (re.compile(r"(?i)\b[a-z0-9._%+-]+:[^\s@/]{6,}@[a-z0-9.-]+"), "URL_CREDENTIALS"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     "PRIVATE_KEY"),
]

_MAX_FIELD = 4000


class LedgerUnwritable(RuntimeError):
    """The ledger could not be durably written. The caller must drop to SAFE."""


def redact(value):
    """Recursively redact secrets. Returns (value, markers)."""
    markers: list[str] = []

    def _scrub(v):
        if isinstance(v, str):
            out = v
            for pat, label in _REDACTIONS:
                if pat.search(out):
                    markers.append(label)
                    out = pat.sub(f"[REDACTED:{label}]", out)
            if len(out) > _MAX_FIELD:
                markers.append("TRUNCATED")
                out = out[:_MAX_FIELD] + f"...[truncated {len(out) - _MAX_FIELD} chars]"
            return out
        if isinstance(v, dict):
            return {k: _scrub(x) for k, x in v.items()}
        if isinstance(v, list):
            return [_scrub(x) for x in v]
        return v

    return _scrub(value), sorted(set(markers))


class Ledger:
    def __init__(self, path: str, state_dir: str) -> None:
        self.path = path
        self.state_dir = state_dir
        self.anchor = os.path.join(state_dir, "chain.anchor")
        self.spool_path = os.path.join(state_dir, "spool.jsonl")
        self._lock = threading.Lock()

    # -- writing -----------------------------------------------------------

    def append(self, decision: dict, *, kind: str = "gate_decision") -> dict:
        """Append one hash-chained event. Raises LedgerUnwritable on failure."""
        payload, markers = redact(decision)
        event = {
            "kind": kind,
            "decision_id": payload.get("decision_id"),
            "seq": payload.get("seq"),
            "timestamp": payload.get("ts"),
            "session_id": payload.get("session_id"),
            "agent_id": payload.get("agent_id"),
            "tool": payload.get("tool"),
            "action": payload.get("action"),
            "route": payload.get("route"),
            "score": payload.get("score"),
            "perimeter_state": payload.get("perimeter_state"),
            "blast": payload.get("blast"),
            "findings": payload.get("findings"),
            "reasons": payload.get("reasons"),
            "operator": payload.get("operator"),
            "taint": payload.get("taint"),
            "latency_ms": payload.get("latency_ms"),
            "envelope": payload.get("envelope"),
            "redactions": markers,
        }
        with self._lock:
            try:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                prev = integrity.last_hash(self.path)
                event["prev_hash"] = prev
                event["hash"] = integrity.event_hash(prev, event)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                integrity.anchor_head(self.anchor, event["hash"],
                                      event.get("seq") or 0, self.path)
            except OSError as exc:
                raise LedgerUnwritable(
                    f"decision {event.get('decision_id')} could not be written to "
                    f"{self.path}: {exc}. The perimeter drops to SAFE rather than "
                    f"deciding without recording."
                ) from exc
        return event

    def note(self, kind: str, detail: dict) -> dict:
        """Record a non-decision event: state change, canary, disarm, gap marker."""
        return self.append({
            "decision_id": detail.get("decision_id", f"{kind}_{integrity.GENESIS[:8]}"),
            "seq": detail.get("seq", 0),
            "ts": detail.get("ts"),
            "session_id": detail.get("session_id", ""),
            "agent_id": detail.get("agent_id", "governor"),
            "tool": kind,
            "action": kind,
            "route": detail.get("route", "ALLOW"),
            "score": 0,
            "reasons": detail.get("reasons", []),
            "perimeter_state": detail.get("perimeter_state", ""),
            "operator": detail.get("operator"),
            "envelope": detail.get("envelope", {}),
        }, kind=kind)

    # -- degraded-mode spool ------------------------------------------------

    def spool(self, record: dict) -> None:
        """Park an event written while the governor was unreachable.

        Spooled events are NOT chained -- they were produced without access to
        the chain head. They are ingested later behind an explicit gap marker so
        the ledger reads "N events reconstructed from spool", never as if the
        chain had been continuous.
        """
        os.makedirs(self.state_dir, exist_ok=True)
        with open(self.spool_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def ingest_spool(self) -> int:
        if not os.path.exists(self.spool_path):
            return 0
        with open(self.spool_path, encoding="utf-8") as f:
            records = [json.loads(l) for l in f if l.strip()]
        if not records:
            return 0
        self.note("spool_gap_open", {"reasons": [
            f"{len(records)} events were recorded while the governor was unreachable; "
            f"they were not chained at the time of writing and are reproduced below"]})
        for rec in records:
            self.append(rec, kind="spooled_decision")
        self.note("spool_gap_close", {"reasons": [f"{len(records)} spooled events ingested"]})
        os.replace(self.spool_path, self.spool_path + ".ingested")
        return len(records)

    # -- reading -----------------------------------------------------------

    def verify(self):
        """Chain walk plus anchor comparison.

        The anchor status is always reported, not only on failure: "the anchor
        matched" and "there was no anchor to match" are different facts, and an
        operator reading a clean verification should be able to tell which one
        they are looking at.
        """
        ok, checked, problems = integrity.verify(self.path)
        anchor_ok, anchor_msg = integrity.check_anchor(self.anchor, self.path)
        problems.append(anchor_msg)
        if not anchor_ok:
            ok = False
        return ok, checked, problems

    def read(self, *, limit: int = 200, route: str | None = None,
             session_id: str | None = None, action: str | None = None,
             since_seq: int = 0) -> list[dict]:
        if not os.path.exists(self.path):
            return []
        out: list[dict] = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if route and e.get("route") != route:
                    continue
                if session_id and e.get("session_id") != session_id:
                    continue
                if action and e.get("action") != action:
                    continue
                if since_seq and (e.get("seq") or 0) <= since_seq:
                    continue
                out.append(e)
        return out[-limit:] if limit else out

    def stats(self) -> dict:
        events = self.read(limit=0)
        by_route: dict[str, int] = {}
        by_action: dict[str, int] = {}
        for e in events:
            by_route[e.get("route", "?")] = by_route.get(e.get("route", "?"), 0) + 1
            by_action[e.get("action", "?")] = by_action.get(e.get("action", "?"), 0) + 1
        return {
            "total": len(events),
            "by_route": by_route,
            "by_action": dict(sorted(by_action.items(), key=lambda kv: -kv[1])[:15]),
            "path": self.path,
        }
