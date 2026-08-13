"""The CASA gate -- the single place a route is decided.

Inherits CASA's model exactly: ALLOW / REVIEW / HALT, no DENY, HALT never
silently downgraded. Inherits Diffwall's scoring exactly: additive, capped at
100, ``halted = any(f.halt) or score >= thresholds.halt``, routed by thresholds.
A Runwall score and a Diffwall score mean the same thing.

Three deliberate tightenings over ``daxxer/governance.py``, each a correction
that surfaced in adversarial review rather than a matter of taste:

1. ``strictest`` resolves an unknown gate value to **HALT**, not REVIEW. Daxxer
   treats an uninterpretable value as needing review; a value we cannot parse
   should be assumed to be the worst thing it could be.

2. **REVIEW with no operator present becomes HALT** after a grace period.
   Fail-closed to REVIEW is only fail-closed while somebody is watching. At
   3 a.m. an unattended REVIEW is an indefinite pause that an agent can retry
   around, so an unattended REVIEW resolves to a refusal.

3. **The action label is derived server-side.** ``classify.classify`` computes
   it from the normalized envelope; there is no field through which an agent
   could supply one.

Disarm is a *cap*, not a floor, and it cannot reach HALT. A disarm that could
authorise dismantling the wall would not be a control with an off switch; it
would be an off switch.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import blast as blast_mod
from . import classify
from .rules import Finding, evaluate_all
from .state import ALWAYS_DENIED, DISARMED, MAINTAINABLE

ALLOW, REVIEW, HALT = "ALLOW", "REVIEW", "HALT"
_SEVERITY = {ALLOW: 0, REVIEW: 1, HALT: 2}


def strictest(*gates: str) -> str:
    """Most restrictive of the supplied gates. Unknown values resolve to HALT."""
    if any(g not in _SEVERITY for g in gates if g is not None):
        return HALT
    known = [g for g in gates if g in _SEVERITY]
    return max(known, key=lambda g: _SEVERITY[g]) if known else HALT


def route_from_score(findings: list[Finding], thresholds: dict) -> tuple[str, int, bool]:
    """Diffwall's scoring, unchanged. Returns (route, score, halted)."""
    score = min(100, sum(f.score for f in findings))
    halted = any(f.halt for f in findings) or score >= thresholds["halt"]
    route = HALT if halted else (REVIEW if score >= thresholds["review"] else ALLOW)
    return route, score, halted


@dataclass
class Decision:
    decision_id: str
    seq: int
    ts: str
    envelope_id: str
    session_id: str
    agent_id: str
    harness: str
    tool: str
    action: str
    route: str
    score: int
    thresholds: dict
    findings: list[dict] = field(default_factory=list)
    blast: dict = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    perimeter_state: str = "ARMED"
    maintenance: dict | None = None
    taint: int = 0
    budgets_breached: list[str] = field(default_factory=list)
    prior_denial: dict | None = None
    operator: dict | None = None
    latency_ms: int = 0
    envelope: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "seq": self.seq,
            "ts": self.ts,
            "envelope_id": self.envelope_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "harness": self.harness,
            "tool": self.tool,
            "action": self.action,
            "route": self.route,
            "score": self.score,
            "thresholds": self.thresholds,
            "findings": self.findings,
            "blast": self.blast,
            "reasons": self.reasons,
            "perimeter_state": self.perimeter_state,
            "maintenance": self.maintenance,
            "taint": self.taint,
            "budgets_breached": self.budgets_breached,
            "prior_denial": self.prior_denial,
            "operator": self.operator,
            "latency_ms": self.latency_ms,
            "envelope": self.envelope,
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def decide(env, policy, session, perimeter, *, operator_present: bool = False) -> Decision:
    """Evaluate one envelope. This is the chokepoint; nothing else decides a route."""
    t0 = time.perf_counter()
    reasons: list[str] = []

    findings = evaluate_all(env, policy, session)
    action = classify.classify(env, findings, policy)

    score_route, score, halted = route_from_score(findings, policy.thresholds)
    if halted:
        reasons.append(f"score {score} with {sum(1 for f in findings if f.halt)} halting finding(s)")
    elif score:
        reasons.append(f"score {score} against thresholds {policy.thresholds}")

    action_route = policy.gate_for_action(action)
    if action_route != ALLOW:
        reasons.append(f"action '{action}' is gated {action_route} by policy")

    br = blast_mod.compute(env, policy, findings)
    blast_route = blast_mod.floor_route(br)
    if blast_route != ALLOW:
        reasons.append(
            f"blast radius floor {blast_route}: scope={br.scope} "
            f"reversibility={br.reversibility} propagation={br.propagation} "
            f"confidence={br.confidence:.2f}")
    for note in br.notes:
        reasons.append(f"blast: {note}")

    taint_route, taint_reason = session.taint_floor(policy)
    if taint_reason:
        reasons.append(f"taint floor {taint_route}: {taint_reason}")

    breaches = session.budget_breaches(policy)
    budget_route = ALLOW
    if breaches:
        budget_route = policy.budgets.get("breach_route", REVIEW)
        reasons.extend(f"budget: {b}" for b in breaches)

    # Verdict shopping: a near-identical intent already refused in this session
    # escalates rather than being re-evaluated from scratch.
    prior = session.prior_denial(env, policy.approval.get("denial_memory_seconds", 3600))
    denial_route = ALLOW
    if prior:
        denial_route = HALT
        reasons.append(
            f"this intent was already refused {prior['count']}x in this session "
            f"(first {int(time.time() - prior['first'])}s ago) - retrying a refused "
            f"intent with a mutated payload escalates")

    perimeter_route, perimeter_reason = perimeter.floor(action, env.cwd)
    if perimeter_reason:
        reasons.append(perimeter_reason)

    route = strictest(score_route, action_route, blast_route, taint_route,
                      budget_route, denial_route, perimeter_route)

    # An unattended REVIEW is not a pause, it is an indefinite block an agent can
    # retry around. Resolve it to a refusal and say why.
    if route == REVIEW and not operator_present and policy.approval.get("unattended_review_halts"):
        route = HALT
        reasons.append("REVIEW required but no operator is connected - "
                       "unattended review resolves to refusal")

    # Disarm caps, never below HALT, never for the always-denied classes.
    # A maintenance window lifts exactly two action classes -- edits and reads of
    # Runwall's own source -- and nothing else. Unlike disarm it CAN reach a
    # HALT, because these actions are HALT by default and the window exists
    # precisely to make them reachable. Everything sealed stays sealed:
    # `maintenance_allows` returns None for any action outside MAINTAINABLE, so
    # the ledger, the chain anchor, key material and the harness config are
    # untouched by this branch.
    if action in MAINTAINABLE:
        m = perimeter.maintenance_allows(action)
        if m:
            route = ALLOW
            reasons.append(
                f"maintenance window opened by {m['operator']} "
                f"({m['remaining_s']}s remaining, action {m['actions']} of this "
                f"window): {m['reason']}")

    if perimeter.state == DISARMED and route != HALT and action not in ALWAYS_DENIED:
        # disarm_covers(), not disarm_info(): a disarm scoped to one project must
        # not relax anything in another. The scope field is only a control if
        # every path that grants relief consults it.
        d = perimeter.disarm_covers(env.cwd)
        if d:
            route = ALLOW
            reasons.append(f"perimeter disarmed by {d['operator']} "
                           f"({d['remaining_s']}s remaining, scope "
                           f"{d['scope'] or '<all>'}) - route capped to ALLOW")

    if route == HALT:
        session.record_denial(env, route, reasons)
        session.halts += 1
    if route == REVIEW:
        session.record_review()
    session.decisions += 1

    fatigue = session.fatigue_signal(policy)
    if fatigue:
        reasons.append(f"fatigue: {fatigue}")

    return Decision(
        decision_id=f"rw_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}",
        seq=env.seq,
        ts=_now_iso(),
        envelope_id=env.envelope_id,
        session_id=env.session_id,
        agent_id=env.agent_id,
        harness=env.harness,
        tool=env.tool,
        action=action,
        route=route,
        score=score,
        thresholds=dict(policy.thresholds),
        findings=[f.to_dict() for f in findings],
        blast=br.to_dict(),
        reasons=reasons,
        perimeter_state=perimeter.state,
        maintenance=perimeter.maintenance_info(),
        taint=session.taint,
        budgets_breached=breaches,
        prior_denial=prior,
        latency_ms=int((time.perf_counter() - t0) * 1000),
        envelope=env.to_dict(),
    )
