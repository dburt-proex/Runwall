"""Blocking approvals, and the grant that keeps them from becoming a trap.

The naive design -- block the tool call, wait for a click, deny on timeout --
fails in a specific and predictable way: the operator steps away, a long task
dies at minute forty-four, and the operator responds by disarming the wall
permanently. A control that punishes the user for using it does not survive
contact with a real workday.

So a timeout does not deny the *work*, it ends the *wait*. The pending approval
stays live in the console. When the operator eventually approves, approval does
not resurrect a dead call -- it issues a **grant** keyed on the intent
fingerprint. The agent's natural retry then matches the grant and proceeds
immediately. The human decision still happened, still gated the action, and is
still attributed in the ledger; it simply stopped being coupled to a socket
staying open.

Grants are deliberately narrow:
  * keyed on normalized intent, not on literal payload
  * scoped to one session
  * time-boxed, single-use unless explicitly issued as a standing grant
  * never issuable for the always-denied classes

The same fingerprint powers verdict-shopping detection in ``session.py``. One
notion of "the same intent" serves both, which is what keeps them consistent:
a mutated retry cannot simultaneously be a new action for denial purposes and
the same action for grant purposes.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from .session import intent_fingerprint
from .state import ALWAYS_DENIED

PENDING, APPROVED, DENIED, SUSPENDED, EXPIRED = (
    "PENDING", "APPROVED", "DENIED", "SUSPENDED", "EXPIRED")


@dataclass
class PendingApproval:
    approval_id: str
    fingerprint: str
    session_id: str
    agent_id: str
    tool: str
    action: str
    summary: str
    blast: dict
    findings: list
    reasons: list
    created: float = field(default_factory=time.time)
    status: str = PENDING
    operator: str = ""
    decided_at: float = 0.0
    note: str = ""
    _event: threading.Event = field(default_factory=threading.Event, repr=False)

    def wait(self, timeout: float) -> str:
        """Block until decided or the wait budget expires."""
        self._event.wait(timeout)
        return self.status

    def resolve(self, status: str, operator: str, note: str = "") -> None:
        self.status = status
        self.operator = operator
        self.note = note
        self.decided_at = time.time()
        self._event.set()

    def age(self) -> float:
        return time.time() - self.created

    def to_dict(self) -> dict:
        return {
            "approval_id": self.approval_id,
            "fingerprint": self.fingerprint,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "action": self.action,
            "summary": self.summary,
            "blast": self.blast,
            "findings": self.findings,
            "reasons": self.reasons,
            "status": self.status,
            "operator": self.operator,
            "note": self.note,
            "age_s": round(self.age(), 1),
            "created": self.created,
            "requires_totp": bool(self.blast.get("is_high")),
        }


@dataclass
class Grant:
    fingerprint: str
    session_id: str
    operator: str
    expires: float
    uses_left: int
    reason: str

    def live(self) -> bool:
        return time.time() < self.expires and self.uses_left != 0

    def to_dict(self) -> dict:
        return {"fingerprint": self.fingerprint, "session_id": self.session_id,
                "operator": self.operator, "reason": self.reason,
                "uses_left": self.uses_left,
                "remaining_s": max(0, int(self.expires - time.time()))}


class ApprovalBroker:
    def __init__(self) -> None:
        self._pending: dict[str, PendingApproval] = {}
        self._grants: dict[str, Grant] = {}
        self._lock = threading.Lock()
        self._counter = 0

    # -- grants ------------------------------------------------------------

    def find_grant(self, env, action: str) -> Grant | None:
        """A live grant matching this intent, if the action may be granted at all."""
        if action in ALWAYS_DENIED:
            return None
        fp = intent_fingerprint(env)
        with self._lock:
            g = self._grants.get(f"{env.session_id}:{fp}")
            if g and g.live():
                return g
            if g:
                self._grants.pop(f"{env.session_id}:{fp}", None)
        return None

    def consume_grant(self, grant: Grant) -> None:
        with self._lock:
            if grant.uses_left > 0:
                grant.uses_left -= 1

    def issue_grant(self, pending: PendingApproval, *, operator: str, seconds: int,
                    uses: int, reason: str) -> Grant | None:
        if pending.action in ALWAYS_DENIED:
            return None
        g = Grant(fingerprint=pending.fingerprint, session_id=pending.session_id,
                  operator=operator, expires=time.time() + max(30, seconds),
                  uses_left=uses, reason=reason)
        with self._lock:
            self._grants[f"{pending.session_id}:{pending.fingerprint}"] = g
        return g

    def grants(self) -> list[dict]:
        with self._lock:
            return [g.to_dict() for g in self._grants.values() if g.live()]

    # -- pending -----------------------------------------------------------

    def open(self, env, decision) -> PendingApproval:
        with self._lock:
            self._counter += 1
            approval_id = f"ap_{int(time.time())}_{self._counter}"
        pending = PendingApproval(
            approval_id=approval_id,
            fingerprint=intent_fingerprint(env),
            session_id=env.session_id,
            agent_id=env.agent_id,
            tool=env.tool,
            action=decision.action,
            summary=_summarize(env),
            blast=decision.blast,
            findings=decision.findings,
            reasons=decision.reasons,
        )
        with self._lock:
            self._pending[approval_id] = pending
        return pending

    def get(self, approval_id: str) -> PendingApproval | None:
        with self._lock:
            return self._pending.get(approval_id)

    def queue(self) -> list[dict]:
        with self._lock:
            items = [p for p in self._pending.values()
                     if p.status in (PENDING, SUSPENDED)]
        return [p.to_dict() for p in sorted(items, key=lambda p: -p.created)]

    def expire_stale(self, hard_ceiling_s: int) -> int:
        """Suspended past the ceiling is a refusal. Nothing waits forever."""
        n = 0
        with self._lock:
            for p in self._pending.values():
                if p.status in (PENDING, SUSPENDED) and p.age() > hard_ceiling_s:
                    p.resolve(EXPIRED, "system",
                              f"no decision within {hard_ceiling_s}s hard ceiling")
                    n += 1
        return n

    def prune(self, keep_seconds: int = 86400) -> None:
        cutoff = time.time() - keep_seconds
        with self._lock:
            for k in [k for k, p in self._pending.items()
                      if p.status not in (PENDING, SUSPENDED) and p.created < cutoff]:
                self._pending.pop(k, None)

    def stats(self) -> dict:
        with self._lock:
            items = list(self._pending.values())
        decided = [p for p in items if p.decided_at]
        latencies = sorted(p.decided_at - p.created for p in decided)
        median = latencies[len(latencies) // 2] if latencies else 0.0
        return {
            "pending": sum(1 for p in items if p.status == PENDING),
            "suspended": sum(1 for p in items if p.status == SUSPENDED),
            "approved": sum(1 for p in items if p.status == APPROVED),
            "denied": sum(1 for p in items if p.status == DENIED),
            "expired": sum(1 for p in items if p.status == EXPIRED),
            "median_latency_s": round(median, 1),
            # Sub-two-second medians mean the operator is not reading the cards.
            # Surfaced as a security metric, not a performance one.
            "rubber_stamp_risk": bool(latencies and median < 2.0 and len(latencies) >= 5),
            "live_grants": len([g for g in self._grants.values() if g.live()]),
        }


def _summarize(env) -> str:
    """A short human-readable description. The console shows blast radius and
    diff alongside this -- an operator reading raw command strings all day is an
    operator who stops reading."""
    for key in ("command", "file_path", "path", "url", "pattern", "query"):
        val = env.raw_params.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()[:300]
    return f"{env.tool} with {len(env.raw_params)} parameter(s)"
