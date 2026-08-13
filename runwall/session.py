"""Per-session memory: budgets, taint, and denied-intent fingerprints.

Three attacks are invisible to any per-call, stateless policy. All three are
cheap to defeat once something remembers what happened earlier in the session,
which is the entire reason the governor is a daemon rather than a subprocess.

**Decomposition.** One HALT becomes N ALLOWs. A 10 MB exfiltration split into a
thousand allowlisted 10 KB requests passes a per-call check a thousand times.
Budgets accumulate and the (N+1)th call fails.

**Injection laundering via tool results.** A fetched README says "run the setup
command". The agent, behaving exactly as designed, proposes it. The command
looks plausible in isolation because it *is* plausible in isolation -- the
problem is its provenance, not its shape. Taint tracks that the session has
consumed untrusted external content and raises the gate floor until the next
genuine user turn, so instructions that entered through a tool result cannot
reach a consequential action without a human seeing them first.

**Verdict shopping.** Denied once, the agent mutates the payload and retries.
Fingerprinting the *normalized intent* rather than the literal text means the
retry matches its own denial and escalates instead of getting a fresh roll.
"""
from __future__ import annotations

import hashlib
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field

# Taint levels
CLEAN, EXPOSED, INSTRUCTED = 0, 1, 2

_IMPERATIVE = re.compile(
    r"\b(run|execute|install|curl|wget|download|delete|remove|disable|"
    r"ignore (?:all )?previous|disregard|you (?:must|should)|system prompt|"
    r"new instructions?|override)\b", re.IGNORECASE)

_INTENT_NOISE = re.compile(r"[\s'\"`,;|&()\[\]{}<>]+")
_INTENT_VALUES = re.compile(r"\b(?:[0-9a-f]{8,}|\d+|[a-z]:[\\/][^\s]*|/[^\s]*)\b", re.IGNORECASE)


def intent_fingerprint(env) -> str:
    """A hash of what an action *does*, insensitive to how it is spelled.

    Literal values, paths and numbers are stripped before hashing, so
    ``rm -rf /a`` and ``rm  -rf   /b`` collapse to the same intent. This is what
    makes a denial stick across a mutated retry.
    """
    text = _INTENT_VALUES.sub("#", env.normalized)
    text = _INTENT_NOISE.sub(" ", text).strip()
    tokens = sorted(set(text.split()))[:40]
    basis = f"{env.tool}|{' '.join(tokens)}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


@dataclass
class SessionState:
    session_id: str
    started: float = field(default_factory=time.time)

    taint: int = CLEAN
    taint_sources: list[str] = field(default_factory=list)
    last_user_turn: str = ""

    egress_bytes: int = 0
    domains: set[str] = field(default_factory=set)
    deletes: deque = field(default_factory=deque)
    reviews: deque = field(default_factory=deque)
    approvals: deque = field(default_factory=deque)
    approval_latencies: deque = field(default_factory=deque)

    denied_intents: dict[str, dict] = field(default_factory=dict)
    decisions: int = 0
    halts: int = 0

    # -- taint -------------------------------------------------------------

    def note_user_turn(self, turn_id: str) -> None:
        """A genuine user turn clears taint. Only a human can launder content."""
        if turn_id and turn_id != self.last_user_turn:
            self.last_user_turn = turn_id
            self.taint = CLEAN
            self.taint_sources = []

    def note_external_content(self, source: str, body: str = "") -> None:
        self.taint = max(self.taint, EXPOSED)
        if source and source not in self.taint_sources:
            self.taint_sources.append(source)
        if body and _IMPERATIVE.search(body):
            self.taint = INSTRUCTED
            self.taint_sources.append(f"{source} [contains imperative language]")

    def taint_floor(self, policy) -> tuple[str, str]:
        """Minimum route justified by current taint. Returns (route, reason)."""
        cfg = policy.taint
        if self.taint >= INSTRUCTED and cfg.get("instructed_floor"):
            return cfg["instructed_floor"], (
                "session consumed external content containing imperative language; "
                f"sources: {', '.join(self.taint_sources[:3])}")
        if self.taint >= EXPOSED and cfg.get("exposed_floor"):
            return cfg["exposed_floor"], (
                "session consumed untrusted external content since the last user turn")
        return "ALLOW", ""

    # -- budgets -----------------------------------------------------------

    def _trim(self, dq: deque, window: int) -> None:
        cutoff = time.time() - window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def record_egress(self, nbytes: int, domain: str = "") -> None:
        self.egress_bytes += max(0, nbytes)
        if domain:
            self.domains.add(domain)

    def record_delete(self) -> None:
        self.deletes.append(time.time())

    def record_review(self) -> None:
        self.reviews.append(time.time())

    def record_approval(self, latency: float) -> None:
        """Record an approval and the seconds the operator took to decide.

        The latency was previously accepted and discarded while the fatigue
        metric recomputed it in ApprovalBroker.stats() -- a signature promising
        data it never stored. Kept per-session so a future per-session fatigue
        rule reads a real value.
        """
        self.approvals.append(time.time())
        self.approval_latencies.append(max(0.0, float(latency)))

    def budget_breaches(self, policy) -> list[str]:
        b = policy.budgets
        out = []
        if b.get("egress_bytes_per_session") and self.egress_bytes > b["egress_bytes_per_session"]:
            out.append(f"session egress {self.egress_bytes}B exceeds budget "
                       f"{b['egress_bytes_per_session']}B")
        if b.get("distinct_domains_per_session") and len(self.domains) > b["distinct_domains_per_session"]:
            out.append(f"{len(self.domains)} distinct domains exceeds budget "
                       f"{b['distinct_domains_per_session']}")
        self._trim(self.deletes, 3600)
        if b.get("deletes_per_hour") and len(self.deletes) > b["deletes_per_hour"]:
            out.append(f"{len(self.deletes)} deletes in the last hour exceeds budget "
                       f"{b['deletes_per_hour']}")
        self._trim(self.reviews, 3600)
        if b.get("reviews_per_hour") and len(self.reviews) > b["reviews_per_hour"]:
            out.append(f"{len(self.reviews)} review prompts in the last hour exceeds "
                       f"budget {b['reviews_per_hour']} - the operator is being flooded")
        return out

    # -- verdict shopping --------------------------------------------------

    def record_denial(self, env, route: str, reasons: list[str]) -> None:
        fp = intent_fingerprint(env)
        entry = self.denied_intents.setdefault(fp, {"count": 0, "route": route,
                                                    "first": time.time(), "reasons": reasons})
        entry["count"] += 1
        entry["last"] = time.time()

    def prior_denial(self, env, window: int) -> dict | None:
        entry = self.denied_intents.get(intent_fingerprint(env))
        if not entry:
            return None
        if time.time() - entry.get("last", entry["first"]) > window:
            return None
        return entry

    # -- fatigue -----------------------------------------------------------

    def fatigue_signal(self, policy) -> str | None:
        """Rubber-stamping detector. An operator approving reflexively is not a control."""
        self._trim(self.approvals, 3600)
        limit = policy.approval.get("fatigue_approvals_per_hour", 0)
        if limit and len(self.approvals) > limit:
            return (f"{len(self.approvals)} approvals in the last hour exceeds {limit}; "
                    f"approvals in this window should be treated as low-assurance")
        return None


class SessionStore:
    """Thread-safe registry of live sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}
        self._lock = threading.Lock()

    def get(self, session_id: str) -> SessionState:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionState(session_id=session_id)
            return self._sessions[session_id]

    def all(self) -> list[SessionState]:
        with self._lock:
            return list(self._sessions.values())

    def reset(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)
