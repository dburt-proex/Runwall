#!/usr/bin/env python
"""Runwall PreToolUse hook client.

Invoked by Claude Code before every tool call. Reads the hook payload on stdin,
asks the governor for a route, and emits a permission decision.

Three constraints shape everything here.

**It must be fast.** This runs in front of every tool call. Standard library
only, no package imports from ``runwall`` itself, and it is invoked with
``-I -S`` so site initialisation is skipped. A slow hook is a hook a user
eventually removes.

**It must fail closed -- but usefully.** If the governor is unreachable the
correct answer is not "allow everything" (no wall) and not "deny everything"
(unusable machine, which becomes no wall the moment the user disables it). It is
the reduced rule set below: refuse the classes that are never acceptable, let
read-class work continue, and spool the record so the ledger shows a marked gap
rather than a silent hole.

**It must not hang.** Waiting past the harness's own hook timeout is how
fail-closed silently becomes fail-open: the harness stops waiting and proceeds.
The deadline here is set strictly below it and a timeout is a denial.

The fallback patterns are duplicated rather than imported on purpose. If the
runwall package is broken, missing, or has been tampered with, this file still
refuses the things that must always be refused.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import unicodedata
import urllib.error
import urllib.request

HOST = os.environ.get("RUNWALL_HOST", "127.0.0.1")
PORT = os.environ.get("RUNWALL_PORT", "8787")
DEADLINE_S = float(os.environ.get("RUNWALL_HOOK_DEADLINE", "8"))
STATE_DIR = os.environ.get("RUNWALL_STATE", "")

# --- reduced rule set: refused at every rung, governor or no governor -------
FALLBACK_DENY = [
    (r"\brm\b\s+-[a-z]*[rf]{2}", "recursive forced delete"),
    (r"remove-item\b(?=[^|;\n]*-recurse)(?=[^|;\n]*-force)", "recursive forced delete"),
    (r"\brd\b\s+/s|\brmdir\b\s+/s", "recursive directory delete"),
    (r"\bdrop\s+(table|database|schema)\b", "SQL DROP"),
    (r"\btruncate\s+table\b", "SQL TRUNCATE"),
    (r"\bmkfs(\.[a-z0-9]+)?\b|\bformat\s+[a-z]:|\bdiskpart\b", "storage destruction"),
    (r"--dangerously-skip-permissions|--permission-mode[= ]\s*bypass",
     "launching an agent harness with governance disabled"),
    (r"\btaskkill\b[^|;\n]*(runwall|governor)|stop-process\b[^|;\n]*runwall",
     "terminating the governor"),
    (r"settings(\.local)?\.json", "modifying the harness configuration"),
    (r"\bsitecustomize\.py\b|\busercustomize\.py\b|set\s+pythonpath\b|\$env:pythonpath",
     "interpreter substitution"),
    (r"client\.token|approval\.key|chain\.anchor|operator\.json",
     "accessing governor key material"),
    (r"runwall[/\\](policy|runwall|hook)\b", "reaching Runwall's own files"),
    (r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "fork bomb"),
    (r"\bchmod\s+(-[a-z]+\s+)*777\b", "world-writable permissions"),
]
_FALLBACK = [(re.compile(p, re.IGNORECASE), why) for p, why in FALLBACK_DENY]

READ_TOOLS = {"Read", "NotebookRead", "Grep", "Glob", "TodoRead", "TodoWrite"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}

# Mirrors envelope._CONTENT_PARAMS. Duplicated deliberately: this file must
# keep working when the runwall package is missing or broken.
#
# There is deliberately no ACTION_KEYS allowlist here -- an earlier version
# scanned "recognized action keys, and only if none of those were present,
# everything else," which meant a single populated action-shaped field (even
# an empty-ish one like `cwd: "."`) silently exempted every OTHER, unlisted
# parameter from the scan. A payload shaped like an unknown tool call with its
# real command text under an unlisted key (a custom MCP tool's `script` field,
# say) bypassed FALLBACK_DENY entirely. Scanning every string param except the
# known content-shaped ones closes that: an unrecognized key is treated as
# action text by default, which is the fail-closed direction to be wrong in.
#
# "new_source" is NotebookEdit's content field (its equivalent of Edit's
# "new_string") -- excluded here for the same reason "content"/"new_string"
# are, so DEGRADED mode doesn't start refusing ordinary notebook edits that
# happen to mention a dangerous-looking string in a comment or docstring.
CONTENT_KEYS = {"content", "new_string", "new_source", "prompt"}

_READ_VERB = re.compile(
    r"(?:^|[|;&]\s*)\s*(cat|tail|head|less|more|wc|nl|type|get-content|gc|grep|"
    r"rg|findstr|select-string|stat|diff|cmp)\b", re.IGNORECASE)
_WRITE_HINT = re.compile(
    r"(>>?\s*\S|\btee\b|\bmv\b|\bcp\b|\brm\b|\bdel\b|set-content|add-content|"
    r"out-file|remove-item|new-item)", re.IGNORECASE)


def _is_read(text: str, tool: str) -> bool:
    if tool in READ_TOOLS:
        return True
    if tool in WRITE_TOOLS:
        return False
    return bool(_READ_VERB.search(text)) and not _WRITE_HINT.search(text)

_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_PS_ENC = re.compile(r"-(?:enc|e|ec|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)


def _decode(text: str) -> str:
    """Minimal mirror of envelope.normalize_text -- enough that the fallback is
    not defeated by the first layer of base64 anyone would reach for."""
    out = unicodedata.normalize("NFC", text or "")
    for _ in range(3):
        prev = out

        def sub(m):
            blob = m.group(len(m.groups()))
            try:
                raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            except Exception:  # noqa: BLE001 - any decode failure means "not base64"
                return m.group(0)
            for enc in ("utf-16-le", "utf-8"):
                try:
                    dec = raw.decode(enc)
                except UnicodeDecodeError:
                    continue
                if sum(c.isprintable() for c in dec) > 0.9 * max(1, len(dec)):
                    return " " + dec + " "
            return m.group(0)

        out = _PS_ENC.sub(sub, out)
        out = _B64.sub(sub, out)
        out = re.sub(r"`(.)", r"\1", out)
        out = re.sub(r"['\"]\s*\+\s*['\"]", "", out)
        if out == prev:
            break
    return unicodedata.normalize("NFC", out).casefold()


def respond(decision: str, reason: str) -> None:
    """Emit the permission decision and exit.

    Both channels are used: the JSON contract, and a non-zero exit for deny.
    If a future harness version changes how it reads one of them, the other
    still refuses. A hook whose refusal depends on a single parsing path is one
    schema change away from being decorative.
    """
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }}))
    sys.stdout.flush()
    if decision == "deny":
        print(f"[Runwall] BLOCKED: {reason}", file=sys.stderr)
        sys.exit(2)
    sys.exit(0)


def fallback(payload: dict, why_unreachable: str) -> None:
    """DEGRADED: the governor is not answering."""
    tool = payload.get("tool_name", "")
    params = payload.get("tool_input") or {}

    # Action text only. Scanning file CONTENTS here meant writing a document that
    # merely mentions `.env` or a policy path was refused as though it were an
    # attack on those paths -- which made security documentation unwritable while
    # the wall was armed. Content is data; the command is the action.
    #
    # Recognized action keys plus any *unrecognized* key are scanned together,
    # unconditionally -- not "recognized action keys, and only if none of those
    # were present, everything else." The conditional form meant a single
    # populated ACTION_KEYS field (even an empty-ish one like `cwd: "."`)
    # silently exempted every other unrecognized parameter from the scan, so a
    # payload shaped like an unknown tool call with its real command text under
    # an unlisted key (e.g. a custom MCP tool's `script` field) bypassed
    # FALLBACK_DENY entirely -- downgrading an unconditional refusal to a mere
    # confirmation prompt during exactly the moment (governor unreachable) this
    # file exists to stay strict through.
    action = " ".join(str(v) for k, v in params.items()
                      if k not in CONTENT_KEYS and isinstance(v, str))
    text = _decode(action)

    for pat, why in _FALLBACK:
        if pat.search(text):
            # Say what was actually attempted. The governor distinguishes reads
            # from writes; this path used to call every match a modification, so
            # the two enforcement paths disagreed in the ledger.
            verb = "read of" if _is_read(text, tool) else "modification of"
            label = why if why.startswith("accessing") or "launch" in why else f"{verb} {why}"
            respond("deny", f"[DEGRADED] {label} - refused without a governor. "
                            f"({why_unreachable})")

    _spool(payload, why_unreachable)

    if tool in READ_TOOLS:
        respond("allow", f"[DEGRADED] read-class action permitted; {why_unreachable}")
    respond("ask", f"[DEGRADED] governor unreachable ({why_unreachable}) - "
                   f"'{tool}' needs your confirmation.")


def _spool(payload: dict, why: str) -> None:
    """Record what happened while the governor was blind, for later ingestion."""
    state = STATE_DIR or os.path.join(os.path.expanduser("~"), ".runwall")
    try:
        os.makedirs(state, exist_ok=True)
        with open(os.path.join(state, "spool.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "decision_id": "spooled",
                "ts": None,
                "session_id": payload.get("session_id", ""),
                "agent_id": "claude-code",
                "tool": payload.get("tool_name", ""),
                "action": "degraded_unmediated",
                "route": "ALLOW",
                "score": 0,
                "reasons": [f"recorded while the governor was unreachable: {why}"],
                "envelope": {"raw_params": payload.get("tool_input") or {}},
            }) + "\n")
    except OSError:
        pass


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except (json.JSONDecodeError, ValueError):
        respond("deny", "unparseable hook payload - refused")

    token = ""
    state = STATE_DIR or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".runwall")
    try:
        with open(os.path.join(state, "client.token"), encoding="utf-8") as f:
            token = f.read().strip()
    except OSError:
        pass

    payload["deadline_s"] = DEADLINE_S
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"http://{HOST}:{PORT}/decide", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"})

    try:
        with urllib.request.urlopen(req, timeout=DEADLINE_S) as resp:
            result = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        respond("deny", f"governor rejected the request (HTTP {exc.code}) - "
                        f"refusing rather than proceeding unmediated")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        fallback(payload, f"{type(exc).__name__}: {exc}")
        return

    route = result.get("route", "HALT")
    reason = _explain(result)
    if route == "ALLOW":
        respond("allow", reason)
    elif route == "REVIEW":
        # The governor already waited for a human and got no answer, so this is
        # a refusal with a live card in the console -- not a fresh question.
        respond("deny", reason)
    else:
        respond("deny", reason)


def _explain(result: dict) -> str:
    parts = [f"[Runwall {result.get('route')}] {result.get('action')}"]
    if result.get("score"):
        parts.append(f"score {result['score']}")
    rules = [f["ruleId"] for f in result.get("findings", [])][:3]
    if rules:
        parts.append("rules: " + ", ".join(rules))
    for r in (result.get("reasons") or [])[:3]:
        parts.append(r)
    if result.get("operator"):
        parts.append(f"operator: {result['operator'].get('id')}")
    parts.append(f"decision {result.get('decision_id')}")
    return " | ".join(str(p) for p in parts)


if __name__ == "__main__":
    main()
