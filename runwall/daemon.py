"""The governor daemon.

Deliberately stdlib-only. A policy enforcement point that pulls a web framework
and its transitive dependency tree into the process has enlarged the attack
surface it exists to reduce, and `pip install` failing is not an acceptable
reason for a security control to be absent. ThreadingHTTPServer plus a routing
table is roughly a hundred lines more code and a great deal less to trust.

Threading matters here beyond throughput: a REVIEW blocks its calling thread
while an operator decides, so single-threaded serving would let one pending
approval freeze every other agent on the machine.
"""
from __future__ import annotations

import json
import mimetypes
import os
import queue
import threading
import time
import traceback
import urllib.parse
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import CONSOLE_DIR, DEFAULT_HOST, DEFAULT_PORT, __version__
from . import auth as auth_mod
from . import classify, integrity, policy as policy_mod
from .approvals import APPROVED, DENIED, SUSPENDED, ApprovalBroker
from .envelope import ActionEnvelope
from .gate import ALLOW, HALT, REVIEW, decide
from .ledger import Ledger, LedgerUnwritable
from .session import SessionStore
from .state import ARMED, DEGRADED, SAFE, Perimeter


class Governor:
    """All governor state. One instance per process."""

    def __init__(self, *, root: str, policy_path: str, manifest_path: str,
                 state_dir: str) -> None:
        self.root = root
        self.state_dir = state_dir
        os.makedirs(state_dir, exist_ok=True)

        self.policy = policy_mod.load(policy_path, root, classify.known_actions(),
                                      manifest_path)
        self.perimeter = Perimeter(state_dir)
        self.ledger = Ledger(self.policy.ledger_path(), state_dir)
        self.sessions = SessionStore()
        self.approvals = ApprovalBroker()
        self.operators = auth_mod.OperatorStore(state_dir)

        self.client_token = auth_mod.ensure_client_token(state_dir)
        self.approval_key = auth_mod.ensure_approval_key(state_dir)

        self.started = time.time()
        self.decisions = 0
        self._subscribers: list[queue.Queue] = []
        self._sub_lock = threading.Lock()

        if not self.policy.pinned:
            if "MISMATCH" in self.policy.pin_message:
                # Running on rules that do not match what was pinned is exactly
                # the situation SAFE exists for.
                self.perimeter.to_safe(self.policy.pin_message)
            else:
                self.perimeter.set_state(ARMED, self.policy.pin_message)

        ingested = self.ledger.ingest_spool()
        if ingested:
            self.perimeter.spooled = ingested

        self.ledger.note("governor_start", {
            "ts": _now(),
            "reasons": [f"runwall {__version__} started",
                        f"policy sha256={self.policy.sha256[:16]}",
                        self.policy.pin_message,
                        f"{len(self.policy.gate_matrix)} gated actions"],
            "perimeter_state": self.perimeter.state,
        })
        threading.Thread(target=self._housekeeping, daemon=True).start()

    # -- pub/sub -----------------------------------------------------------

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=256)
        with self._sub_lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._sub_lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def broadcast(self, kind: str, data: dict) -> None:
        msg = {"kind": kind, "data": data, "ts": _now()}
        with self._sub_lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(msg)
            except queue.Full:
                # A stalled console must never slow the decision path.
                pass

    # -- the decision path -------------------------------------------------

    def handle_decide(self, payload: dict) -> dict:
        deadline = float(payload.get("deadline_s") or 8.0)
        session = self.sessions.get(str(payload.get("session_id") or "default"))

        if payload.get("user_turn_id"):
            session.note_user_turn(str(payload["user_turn_id"]))

        env = ActionEnvelope.from_hook_payload(
            payload,
            envelope_id=f"env_{uuid.uuid4().hex[:12]}",
            seq=integrity.next_seq(self.state_dir),
            ts=_now(),
            agent_id=str(payload.get("agent_id") or "claude-code"),
        )

        operator_present = self.operators.operator_present()
        decision = decide(env, self.policy, session, self.perimeter,
                          operator_present=operator_present)

        # A live grant from a previous human approval short-circuits REVIEW.
        # HALT is never short-circuited -- a grant cannot reach it.
        if decision.route == REVIEW:
            grant = self.approvals.find_grant(env, decision.action)
            if grant:
                self.approvals.consume_grant(grant)
                decision.route = ALLOW
                decision.operator = {"id": grant.operator, "method": "standing_grant",
                                     "reason": grant.reason}
                decision.reasons.append(
                    f"matched a live grant issued by {grant.operator} "
                    f"({grant.to_dict()['remaining_s']}s remaining)")

        if decision.route == REVIEW:
            decision = self._await_operator(env, decision, session, deadline)

        self._record(decision)
        self.decisions += 1
        return _decision_response(decision)

    def _await_operator(self, env, decision, session, deadline: float):
        """Block the call while a human decides. Timeout ends the wait, not the work."""
        pending = self.approvals.open(env, decision)
        self.broadcast("approval_opened", pending.to_dict())

        # Stay strictly inside the hook's deadline. Hanging past it would let the
        # harness stop waiting and proceed -- fail-closed becoming fail-open.
        budget = max(1.0, min(deadline - 1.5, self.policy.approval["timeout_seconds"]))
        status = pending.wait(budget)

        if status == APPROVED:
            decision.route = ALLOW
            decision.operator = {"id": pending.operator, "method": "approval",
                                 "at": pending.decided_at, "note": pending.note}
            decision.reasons.append(f"approved by {pending.operator}")
            session.record_approval(pending.decided_at - pending.created)
        elif status == DENIED:
            decision.route = HALT
            decision.operator = {"id": pending.operator, "method": "denial",
                                 "at": pending.decided_at, "note": pending.note}
            decision.reasons.append(f"denied by {pending.operator}: {pending.note}")
            session.record_denial(env, HALT, decision.reasons)
        else:
            # Nobody answered in time. Suspend rather than deny: the card stays
            # live, and a later approval issues a grant that the agent's retry
            # will match. The work is not killed; only this wait is.
            pending.status = SUSPENDED
            decision.route = HALT
            decision.reasons.append(
                f"no operator decision within {budget:.0f}s - call refused and the "
                f"request SUSPENDED in the console. Approving it there issues a "
                f"grant that a retry will match.")
            self.broadcast("approval_suspended", pending.to_dict())
        return decision

    def _record(self, decision) -> None:
        try:
            self.ledger.append(decision.to_dict())
        except LedgerUnwritable as exc:
            self.perimeter.to_safe(str(exc))
            self.broadcast("state_changed", self.perimeter.snapshot())
        self.broadcast("decision", _feed_item(decision))

    # -- operator actions --------------------------------------------------

    def resolve_approval(self, approval_id: str, *, approve: bool, operator: str,
                         note: str, grant_seconds: int, grant_uses: int) -> dict:
        pending = self.approvals.get(approval_id)
        if not pending:
            return {"ok": False, "error": "no such approval"}
        if pending.status not in ("PENDING", SUSPENDED):
            return {"ok": False, "error": f"already {pending.status}"}

        pending.resolve(APPROVED if approve else DENIED, operator, note)
        grant = None
        if approve:
            grant = self.approvals.issue_grant(
                pending, operator=operator, seconds=grant_seconds,
                uses=grant_uses, reason=note or "operator approval")

        self.ledger.note("operator_decision", {
            "ts": _now(),
            "session_id": pending.session_id,
            "route": ALLOW if approve else HALT,
            "operator": {"id": operator, "method": "console"},
            "reasons": [f"{'approved' if approve else 'denied'} {pending.action} "
                        f"({pending.tool}) after {pending.age():.0f}s",
                        f"summary: {pending.summary}", f"note: {note}"],
            "perimeter_state": self.perimeter.state,
        })
        self.broadcast("approval_resolved", pending.to_dict())
        return {"ok": True, "status": pending.status,
                "grant": grant.to_dict() if grant else None}

    def disarm(self, *, operator: str, reason: str, scope: str, seconds: int) -> dict:
        d = self.perimeter.disarm(reason=reason, scope=scope, operator=operator,
                                  seconds=seconds)
        # Record the refusal immediately preceding a disarm. "What was the wall
        # stopping when it was switched off?" is the first question any review
        # asks, and it should not require correlating timestamps by hand.
        recent = self.ledger.read(limit=1, route=HALT)
        self.ledger.note("perimeter_disarmed", {
            "ts": _now(),
            "operator": {"id": operator, "method": "step_up_totp"},
            "route": REVIEW,
            "reasons": [f"disarmed for {seconds}s, scope={scope or '<all>'}",
                        f"reason: {reason}",
                        f"immediately preceding refusal: "
                        f"{recent[0].get('action') if recent else 'none'}"],
            "perimeter_state": "DISARMED",
        })
        self.broadcast("state_changed", self.perimeter.snapshot())
        return d.to_dict()

    def begin_maintenance(self, *, operator: str, reason: str, seconds: int) -> dict:
        m = self.perimeter.begin_maintenance(reason=reason, operator=operator,
                                             seconds=seconds)
        self.ledger.note("maintenance_opened", {
            "ts": _now(),
            "operator": {"id": operator, "method": "step_up_totp"},
            "route": REVIEW,
            "reasons": [f"maintenance window opened for {seconds}s",
                        f"reason: {reason}",
                        "lifts modify_governor and read_governor_files only; "
                        "ledger, chain anchor, key material and harness config "
                        "remain sealed"],
            "perimeter_state": self.perimeter.state,
        })
        self.broadcast("state_changed", self.perimeter.snapshot())
        return m.to_dict()

    def end_maintenance(self, operator: str) -> dict:
        info = self.perimeter.maintenance_info()
        self.perimeter.end_maintenance()
        self.ledger.note("maintenance_closed", {
            "ts": _now(),
            "operator": {"id": operator, "method": "console"},
            "reasons": [f"maintenance window closed after "
                        f"{(info or {}).get('actions', 0)} action(s)"],
            "perimeter_state": self.perimeter.state,
        })
        self.broadcast("state_changed", self.perimeter.snapshot())
        return {"ok": True, "closed": info}

    def rearm(self, operator: str) -> dict:
        self.perimeter.rearm()
        if self.policy.pinned or "no manifest" in self.policy.pin_message:
            pass
        self.ledger.note("perimeter_rearmed", {
            "ts": _now(), "operator": {"id": operator, "method": "console"},
            "reasons": ["perimeter re-armed"], "perimeter_state": ARMED})
        self.broadcast("state_changed", self.perimeter.snapshot())
        return self.perimeter.snapshot()

    def kill_switch(self, operator: str, reason: str) -> dict:
        """Everything read-only, now. The panic button."""
        self.perimeter.to_safe(f"kill switch engaged by {operator}: {reason}")
        self.ledger.note("kill_switch", {
            "ts": _now(), "operator": {"id": operator, "method": "console"},
            "route": HALT, "reasons": [f"kill switch: {reason}"],
            "perimeter_state": SAFE})
        self.broadcast("state_changed", self.perimeter.snapshot())
        return self.perimeter.snapshot()

    # -- status ------------------------------------------------------------

    def status(self) -> dict:
        ok, checked, problems = self.ledger.verify()
        return {
            "version": __version__,
            "perimeter": self.perimeter.snapshot(),
            "posture": "CONTAINMENT" if os.environ.get("RUNWALL_HARDENED") else
                       "DETERRENCE + EVIDENCE",
            "policy": {
                "path": self.policy.path,
                "sha256": self.policy.sha256,
                "pinned": self.policy.pinned,
                "pin_message": self.policy.pin_message,
                "actions": len(self.policy.gate_matrix),
                "protected_paths": len(self.policy.protected_paths),
                "halt_patterns": len(self.policy.halt_patterns),
            },
            "ledger": {"path": self.ledger.path, "chain_ok": ok,
                       "events": checked, "problems": problems[:5]},
            "approvals": self.approvals.stats(),
            "sessions": len(self.sessions.all()),
            "decisions": self.decisions,
            "operator_present": self.operators.operator_present(),
            "enrolled": self.operators.enrolled(),
            "uptime_s": int(time.time() - self.started),
        }

    # -- background --------------------------------------------------------

    def _housekeeping(self) -> None:
        while True:
            time.sleep(15)
            try:
                self.perimeter.heartbeat()
                n = self.approvals.expire_stale(self.policy.approval["hard_ceiling_seconds"])
                if n:
                    self.broadcast("approvals_expired", {"count": n})
                self.approvals.prune()
            except Exception:  # noqa: BLE001 - housekeeping must never kill the daemon
                pass


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _clamp(value, lo: int, hi: int, default: int) -> int:
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def _decision_response(d) -> dict:
    return {
        "route": d.route,
        "decision_id": d.decision_id,
        "action": d.action,
        "score": d.score,
        "reasons": d.reasons,
        "blast": d.blast,
        "findings": [{"ruleId": f["ruleId"], "message": f["message"],
                      "severity": f["severity"]} for f in d.findings],
        "operator": d.operator,
        "perimeter_state": d.perimeter_state,
        "latency_ms": d.latency_ms,
    }


def _feed_item(d) -> dict:
    return {
        "decision_id": d.decision_id, "ts": d.ts, "seq": d.seq,
        "session_id": d.session_id, "agent_id": d.agent_id,
        "tool": d.tool, "action": d.action, "route": d.route, "score": d.score,
        "blast": d.blast, "reasons": d.reasons[:6],
        "findings": [f["ruleId"] for f in d.findings],
        "operator": d.operator, "latency_ms": d.latency_ms,
        "summary": _summary_of(d),
    }


def _summary_of(d) -> str:
    """A short display string, defensively.

    Tool parameters are agent-controlled and arbitrary JSON. Slicing whatever
    `command` happens to hold raised TypeError on a dict and returned HTTP 500,
    which the hook maps to deny -- fail-closed for one call, but repeatable at
    will, producing a stream of refusals that looks like a broken governor and
    drives the operator to disarm. Never let display formatting decide a route.
    """
    params = (d.envelope or {}).get("raw_params") or {}
    for key in ("command", "file_path", "path", "url", "pattern", "query"):
        val = params.get(key) if isinstance(params, dict) else None
        if isinstance(val, str) and val.strip():
            return val[:200]
        if val is not None and not isinstance(val, str):
            return f"{d.tool}({key}=<{type(val).__name__}>)"[:200]
    return str(d.tool)[:200]


class Handler(BaseHTTPRequestHandler):
    server_version = f"Runwall/{__version__}"
    protocol_version = "HTTP/1.1"
    governor: Governor = None  # set by serve()

    def log_message(self, fmt, *args):  # noqa: A003 - silence stdlib access logging
        pass

    # -- helpers -----------------------------------------------------------

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return {}

    def _bearer(self) -> str:
        h = self.headers.get("Authorization") or ""
        return h[7:].strip() if h.lower().startswith("bearer ") else ""

    def _origin_ok(self) -> bool:
        """Reject cross-origin and rebound-DNS requests.

        The bearer token is the real control; this is the second layer. Without
        it, a page that rebinds an attacker domain to 127.0.0.1 becomes
        same-origin with the governor, and a single token leak (a screenshot, a
        pasted curl, a shared log) becomes full operator control with no further
        check. For a product whose thesis is layered enforcement, one layer is
        the wrong number.
        """
        host = (self.headers.get("Host") or "").strip().lower()
        expected = {f"127.0.0.1:{self.server.server_address[1]}",
                    f"localhost:{self.server.server_address[1]}"}
        if host and host not in expected:
            return False
        origin = (self.headers.get("Origin") or "").strip().lower()
        if origin and origin.split("//")[-1] not in expected:
            return False
        return True

    def _client_ok(self) -> bool:
        import hmac as _hmac
        return _hmac.compare_digest(self._bearer(), self.governor.client_token)

    def _operator(self, token: str | None = None) -> dict | None:
        return self.governor.operators.session(token if token is not None else self._bearer())

    def _require_operator(self):
        s = self._operator()
        if not s:
            self._json(401, {"error": "not authenticated"})
            return None
        return s

    # -- routing -----------------------------------------------------------

    def do_POST(self):  # noqa: N802
        try:
            if not self._origin_ok():
                self._json(403, {"error": "bad Host or Origin"})
                return
            self._route_post(urllib.parse.urlparse(self.path).path)
        except Exception as exc:  # noqa: BLE001
            self._json(500, {"error": f"{type(exc).__name__}: {exc}",
                             "trace": traceback.format_exc()[-800:]})

    def do_GET(self):  # noqa: N802
        try:
            parsed = urllib.parse.urlparse(self.path)
            self._route_get(parsed.path, urllib.parse.parse_qs(parsed.query))
        except Exception as exc:  # noqa: BLE001
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})

    def _route_post(self, path: str) -> None:
        g = self.governor
        body = self._body()

        if path == "/decide":
            if not self._client_ok():
                self._json(401, {"error": "invalid client token"})
                return
            self._json(200, g.handle_decide(body))
            return

        if path == "/auth/login":
            token, msg = g.operators.login(body.get("operator_id", ""),
                                           body.get("password", ""),
                                           body.get("totp", ""))
            if not token:
                self._json(401, {"error": msg})
                return
            self._json(200, {"token": token, "message": msg,
                             "sitekey": g.operators.sitekey()})
            return

        if path == "/auth/logout":
            g.operators.logout(self._bearer())
            self._json(200, {"ok": True})
            return

        if path == "/auth/stepup":
            if not self._require_operator():
                return
            ok, msg = g.operators.step_up(self._bearer(), body.get("totp", ""))
            self._json(200 if ok else 401, {"ok": ok, "message": msg})
            return

        s = self._require_operator()
        if not s:
            return
        operator = s["operator_id"]

        if path in ("/api/approve", "/api/deny"):
            approve = path.endswith("approve")
            pending = g.approvals.get(body.get("approval_id", ""))
            # High blast radius demands a fresh code. Approving something that
            # reaches outside this machine should cost more than a click.
            if (approve and pending and pending.blast.get("is_high")
                    and g.policy.approval.get("step_up_totp_for_high_blast")):
                if not g.operators.has_step_up(self._bearer()):
                    self._json(403, {"error": "step_up_required",
                                     "message": "high blast radius - re-enter your "
                                                "authenticator code to approve"})
                    return
                g.operators.consume_step_up(self._bearer())
            # Clamped server-side. A negative `grant_uses` produced a grant that
            # never depleted (live() tests `!= 0`, consume_grant only decrements
            # `> 0`), and `grant_seconds` was unbounded -- the console offers
            # "grant 15 min" but the server enforced nothing.
            self._json(200, g.resolve_approval(
                body.get("approval_id", ""), approve=approve, operator=operator,
                note=body.get("note", ""),
                grant_seconds=_clamp(body.get("grant_seconds"), 30, 3600, 900),
                grant_uses=_clamp(body.get("grant_uses"), 1, 50, 1)))
            return

        if path == "/api/disarm":
            if not g.operators.has_step_up(self._bearer()):
                self._json(403, {"error": "step_up_required",
                                 "message": "disarming requires a fresh authenticator code"})
                return
            if not (body.get("reason") or "").strip():
                self._json(400, {"error": "a typed reason is required to disarm"})
                return
            g.operators.consume_step_up(self._bearer())
            self._json(200, g.disarm(operator=operator, reason=body["reason"],
                                     scope=body.get("scope", ""),
                                     seconds=int(body.get("seconds") or 900)))
            return

        if path == "/api/maintenance":
            if not g.operators.has_step_up(self._bearer()):
                self._json(403, {"error": "step_up_required",
                                 "message": "opening a maintenance window requires "
                                            "a fresh authenticator code"})
                return
            if not (body.get("reason") or "").strip():
                self._json(400, {"error": "a typed reason is required"})
                return
            g.operators.consume_step_up(self._bearer())
            self._json(200, g.begin_maintenance(
                operator=operator, reason=body["reason"],
                seconds=_clamp(body.get("seconds"), 60, 3600, 900)))
            return

        if path == "/api/maintenance/end":
            self._json(200, g.end_maintenance(operator))
            return

        if path == "/api/rearm":
            self._json(200, g.rearm(operator))
            return

        if path == "/api/kill":
            self._json(200, g.kill_switch(operator, body.get("reason", "operator kill switch")))
            return

        if path == "/api/taint":
            sess = g.sessions.get(body.get("session_id", "default"))
            sess.note_external_content(body.get("source", "unknown"), body.get("body", ""))
            self._json(200, {"taint": sess.taint, "sources": sess.taint_sources})
            return

        self._json(404, {"error": "no such endpoint"})

    def _route_get(self, path: str, qs: dict) -> None:
        g = self.governor

        if path == "/status":
            if not (self._client_ok() or self._operator()):
                self._json(401, {"error": "unauthorized"})
                return
            self._json(200, g.status())
            return

        if path == "/health":
            # Liveness only -- no policy detail, no auth. Lets the hook tell
            # "governor down" from "governor says no".
            self._json(200, {"ok": True, "state": g.perimeter.state,
                             "heartbeat": g.perimeter.snapshot()["heartbeat_seq"]})
            return

        if path in ("/", "/index.html") or path.startswith("/console/"):
            self._serve_console(path)
            return

        # EventSource cannot set an Authorization header, so this one endpoint
        # also accepts the session token as a query parameter. It is the same
        # short-lived console session token, the server binds loopback only, and
        # no other route accepts it this way.
        qs_token = (qs.get("token") or [None])[0] if path == "/api/events" else None
        s = self._operator(qs_token) if qs_token else self._operator()
        if not s:
            self._json(401, {"error": "not authenticated"})
            return

        if path == "/api/queue":
            self._json(200, {"queue": g.approvals.queue(), "grants": g.approvals.grants()})
            return

        if path == "/api/ledger":
            self._json(200, {"events": g.ledger.read(
                limit=int(qs.get("limit", ["150"])[0]),
                route=(qs.get("route") or [None])[0],
                session_id=(qs.get("session_id") or [None])[0],
                action=(qs.get("action") or [None])[0],
            ), "stats": g.ledger.stats()})
            return

        if path == "/api/verify":
            ok, checked, problems = g.ledger.verify()
            self._json(200, {"ok": ok, "checked": checked, "problems": problems})
            return

        if path == "/api/policy":
            self._json(200, {"raw": g.policy.raw, "sha256": g.policy.sha256,
                             "pinned": g.policy.pinned,
                             "pin_message": g.policy.pin_message,
                             "path": g.policy.path})
            return

        if path == "/api/sessions":
            self._json(200, {"sessions": [{
                "session_id": s_.session_id, "taint": s_.taint,
                "taint_sources": s_.taint_sources, "decisions": s_.decisions,
                "halts": s_.halts, "egress_bytes": s_.egress_bytes,
                "domains": len(s_.domains),
                "denied_intents": len(s_.denied_intents),
            } for s_ in g.sessions.all()]})
            return

        if path == "/api/events":
            self._serve_sse()
            return

        self._json(404, {"error": "no such endpoint"})

    # -- SSE ---------------------------------------------------------------

    def _serve_sse(self) -> None:
        g = self.governor
        q = g.subscribe()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    msg = q.get(timeout=15)
                    self.wfile.write(f"data: {json.dumps(msg)}\n\n".encode("utf-8"))
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            g.unsubscribe(q)

    # -- static ------------------------------------------------------------

    def _serve_console(self, path: str) -> None:
        rel = "index.html" if path in ("/", "/index.html") else path[len("/console/"):]
        root = os.path.normpath(CONSOLE_DIR)
        target = os.path.normpath(os.path.join(root, rel))
        # Boundary comparison, not a bare prefix: `../console_backup/x`
        # normalizes to a sibling directory that startswith(root) accepts, and
        # this branch is served before any authentication check.
        if (target != root and not target.startswith(root.rstrip(os.sep) + os.sep)) \
                or not os.path.isfile(target):
            self._json(404, {"error": "not found"})
            return
        ctype = mimetypes.guess_type(target)[0] or "application/octet-stream"
        with open(target, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # The console handles approvals; it must not be framed or side-loaded.
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)


def serve(governor: Governor, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
    Handler.governor = governor
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    return httpd
