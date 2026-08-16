"""The switch -- and the degradation ladder underneath it.

A two-state on/off switch is the wrong model, for a reason worth stating: a hard
fail-closed on daemon-down makes the machine unusable the first time the
governor crashes, and a user who cannot work will disarm the wall permanently.
An unusable control gets removed, so an unusable control provides no protection.
The ladder keeps the machine usable at every rung while never silently allowing
the actions that matter.

    ARMED     full mediation
    DEGRADED  governor unreachable -> the hook falls back to a cached signed
              policy and a reduced rule set. Destructive, credential, egress and
              self-protection classes still DENY; read-class actions proceed and
              are spooled for later ingestion with an explicit gap marker, so
              the ledger records "N events reconstructed from spool" rather than
              a silent hole.
    SAFE      policy hash mismatch, ledger unwritable, or disk pressure -> the
              agent goes read-only. Still useful for planning, and honest about
              why.
    DISARMED  requires TOTP and a typed reason, scoped to one project,
              time-boxed, auto-rearms. There is no permanent off switch.

Two invariants hold at every rung:

  * Never auto-allow on timeout. A hook that hangs into the harness's timeout is
    a hook that fails open, which is why the hook's own deadline is set strictly
    below it.
  * "Governor down" and "governor killed" must never look the same. Heartbeats
    carry a monotonic sequence; a gap is an alarm, not silence.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field

ARMED, DEGRADED, SAFE, DISARMED = "ARMED", "DEGRADED", "SAFE", "DISARMED"

# Actions that are refused at every rung except a scoped, authenticated DISARM.
# This is the reduced rule set the cached-policy fallback enforces.
ALWAYS_DENIED = frozenset({
    "modify_governor", "read_governor_files", "touch_sealed_surface",
    "modify_harness_config", "terminate_governor",
    "launch_ungoverned_harness", "read_governor_secrets",
    "destroy_data", "destroy_storage", "rewrite_history",
})

# What a maintenance window lifts, and only that. Changing how the wall DECIDES
# is maintenance; rewriting what it RECORDED, reading the keys that authenticate
# the operator, or removing the enforcement hook are not -- those would make the
# window an off switch wearing a lab coat.
MAINTAINABLE = frozenset({"modify_governor", "read_governor_files"})

# Never liftable, by disarm or maintenance or anything else.
SEALED = ALWAYS_DENIED - MAINTAINABLE

# Actions still permitted in SAFE. Read-only: enough to plan, not enough to act.
SAFE_ALLOWED = frozenset({"read_local_file", "search_local", "list_directory"})


@dataclass
class Maintenance:
    """An authenticated window in which Runwall's own source may be edited.

    Exists because the alternative was worse. Without it the only way to patch
    or audit Runwall is to uninstall the enforcement hook entirely, and a
    security tool that must be fully removed to be maintained will eventually be
    left removed. Trading a narrow, authenticated, time-boxed, loudly-logged
    window for that outcome is the better bargain.

    Deliberately narrower than a disarm:
      * lifts only MAINTAINABLE -- Runwall's code and policy, nothing else
      * the ledger, chain anchor, key material and harness config stay sealed
      * every ordinary rule still applies to every other action
      * requires the governor to be RUNNING, so there is no on-disk grant an
        agent could forge; a stopped governor means no maintenance, which is
        also why DEGRADED refuses as before
    """

    reason: str
    operator: str
    until: float
    granted_at: float = field(default_factory=time.time)
    actions: int = 0

    def active(self) -> bool:
        return time.time() < self.until

    def to_dict(self) -> dict:
        return {"reason": self.reason, "operator": self.operator,
                "until": self.until, "actions": self.actions,
                "remaining_s": max(0, int(self.until - time.time()))}


@dataclass
class Disarm:
    reason: str
    scope: str
    operator: str
    until: float

    def active(self) -> bool:
        return time.time() < self.until

    def covers(self, cwd: str) -> bool:
        """Scoped to a project path. A global disarm is not offered.

        Compares on a path boundary, not a string prefix. Bare `startswith`
        meant a scope of ``C:\\proj`` also covered ``C:\\project2`` and
        ``C:\\proj-secrets`` -- unrelated repositories silently receiving relief
        the operator never granted.
        """
        if self.scope in ("", "*"):
            return True
        scope = os.path.normcase(os.path.normpath(self.scope)).replace("\\", "/")
        here = os.path.normcase(os.path.normpath(cwd or "")).replace("\\", "/")
        return here == scope or here.startswith(scope.rstrip("/") + "/")

    def to_dict(self) -> dict:
        return {"reason": self.reason, "scope": self.scope, "operator": self.operator,
                "until": self.until, "remaining_s": max(0, int(self.until - time.time()))}


class Perimeter:
    """Holds the current rung and the reasons it is there."""

    def __init__(self, state_dir: str) -> None:
        self.state_dir = state_dir
        self._lock = threading.Lock()
        self._state = ARMED
        self._reasons: list[str] = []
        self._disarm: Disarm | None = None
        self._maintenance: Maintenance | None = None
        self._heartbeat_seq = 0
        self._last_heartbeat = time.time()
        self.spooled = 0
        self.canary_failures = 0

    # -- rung ---------------------------------------------------------------

    @property
    def state(self) -> str:
        with self._lock:
            if self._disarm and not self._disarm.active():
                self._disarm = None
                self._reasons = [r for r in self._reasons if not r.startswith("disarmed:")]
            if self._disarm:
                return DISARMED
            return self._state

    def reasons(self) -> list[str]:
        with self._lock:
            return list(self._reasons)

    def set_state(self, state: str, reason: str) -> None:
        with self._lock:
            if state != self._state:
                self._state = state
                self._reasons = [reason] if reason else []
            elif reason and reason not in self._reasons:
                self._reasons.append(reason)
        self._persist()

    def to_safe(self, reason: str) -> None:
        self.set_state(SAFE, reason)

    def rearm(self) -> None:
        with self._lock:
            self._state = ARMED
            self._reasons = []
            self._disarm = None
        self._persist()

    # -- disarm -------------------------------------------------------------

    def disarm(self, *, reason: str, scope: str, operator: str, seconds: int) -> Disarm:
        """Scoped, time-boxed, auto-rearming. Callers must have passed step-up TOTP."""
        d = Disarm(reason=reason, scope=scope, operator=operator,
                   until=time.time() + max(60, seconds))
        with self._lock:
            self._disarm = d
            self._reasons.append(f"disarmed: {reason}")
        self._persist()
        return d

    def disarm_info(self) -> dict | None:
        with self._lock:
            return self._disarm.to_dict() if self._disarm and self._disarm.active() else None

    # -- maintenance --------------------------------------------------------

    def begin_maintenance(self, *, reason: str, operator: str,
                          seconds: int) -> Maintenance:
        """Open a maintenance window. Callers must have passed step-up TOTP.

        Capped at one hour. A maintenance window long enough to forget about is
        a disarm, and this is deliberately not that.
        """
        m = Maintenance(reason=reason, operator=operator,
                        until=time.time() + max(60, min(3600, seconds)))
        with self._lock:
            self._maintenance = m
        self._persist()
        return m

    def end_maintenance(self) -> None:
        with self._lock:
            self._maintenance = None
        self._persist()

    def maintenance_info(self) -> dict | None:
        with self._lock:
            if self._maintenance and self._maintenance.active():
                return self._maintenance.to_dict()
            self._maintenance = None
        return None

    def maintenance_allows(self, action: str) -> dict | None:
        """The active window, but only for actions it is permitted to lift."""
        if action not in MAINTAINABLE:
            return None
        with self._lock:
            if self._maintenance and self._maintenance.active():
                self._maintenance.actions += 1
                return self._maintenance.to_dict()
            self._maintenance = None
        return None

    def disarm_covers(self, cwd: str) -> dict | None:
        """The active disarm ONLY if it covers this working directory.

        `disarm_info()` answers "is a disarm active anywhere", which is the right
        question for display and the wrong one for a gate decision. Callers that
        relax a route must use this instead -- using the former is what made the
        scope field security theatre on the cap path.
        """
        with self._lock:
            if self._disarm and self._disarm.active() and self._disarm.covers(cwd):
                return self._disarm.to_dict()
        return None

    # -- heartbeat ----------------------------------------------------------

    def heartbeat(self) -> int:
        with self._lock:
            self._heartbeat_seq += 1
            self._last_heartbeat = time.time()
            return self._heartbeat_seq

    def heartbeat_age(self) -> float:
        with self._lock:
            return time.time() - self._last_heartbeat

    # -- floor --------------------------------------------------------------

    def floor(self, action: str, cwd: str = "") -> tuple[str, str]:
        """Minimum route this rung imposes on this action."""
        state = self.state

        if state == DISARMED:
            d = self.disarm_info()
            if d and self._disarm and self._disarm.covers(cwd):
                # Even disarmed, the wall will not help dismantle itself. A
                # disarm that could authorise removing the disarm mechanism is
                # not a control with an off switch, it is an off switch.
                if action in ALWAYS_DENIED:
                    return "HALT", (f"disarmed, but '{action}' is refused at every rung "
                                    f"(scope={d['scope']})")
                return "ALLOW", f"perimeter disarmed by {d['operator']}: {d['reason']}"
            return "ALLOW", "disarm does not cover this working directory"

        if state == SAFE:
            if action in SAFE_ALLOWED:
                return "ALLOW", ""
            return "HALT", ("perimeter is in SAFE (" + "; ".join(self.reasons()) +
                            ") - only read actions are permitted")

        if state == DEGRADED:
            if action in ALWAYS_DENIED:
                return "HALT", "governor degraded - dangerous action classes are refused"
            if action in SAFE_ALLOWED:
                return "ALLOW", ""
            return "REVIEW", "governor degraded - non-read actions require review"

        return "ALLOW", ""

    # -- persistence --------------------------------------------------------

    def _persist(self) -> None:
        try:
            os.makedirs(self.state_dir, exist_ok=True)
            path = os.path.join(self.state_dir, "perimeter.json")
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.snapshot(), f, indent=2)
            os.replace(tmp, path)
        except OSError:
            # Losing the cached snapshot must not take the governor down; the
            # in-memory rung is authoritative while the process lives.
            pass

    def snapshot(self) -> dict:
        return {
            "state": self.state,
            "reasons": self.reasons(),
            "disarm": self.disarm_info(),
            "maintenance": self.maintenance_info(),
            "heartbeat_seq": self._heartbeat_seq,
            "heartbeat_age_s": round(self.heartbeat_age(), 1),
            "spooled_events": self.spooled,
            "canary_failures": self.canary_failures,
        }
