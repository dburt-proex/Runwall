"""Escaping the boundary: persistence, privilege, and leaving the project.

An agent asked to work in one repository has no reason to install a scheduled
task, add a user, disable the firewall, or write into another account's profile.
These are not "risky commands"; they are actions whose entire purpose is to
outlive or widen the current session.

Persistence deserves specific emphasis because it is the one bypass that defeats
every other control by construction: code registered to run later runs outside
any governed session. Nothing downstream sees it. That makes registering
persistence a HALT rather than a score, independent of how innocuous the payload
looks at registration time.
"""
from __future__ import annotations

import os
import re

from . import Finding, register

_PERSISTENCE = [
    (r"\bschtasks\b[^|;\n]*/create", "Windows scheduled task"),
    (r"register-scheduledtask|new-scheduledtask", "Windows scheduled task"),
    (r"\bat\s+\d{1,2}:\d{2}\b", "AT job"),
    (r"currentversion\\\\?run(once)?\b", "Run registry key"),
    (r"hkcu:|hklm:.*\\run\b", "Run registry key"),
    (r"reg\s+add\b[^|;\n]*\\run", "Run registry key"),
    (r"start\s*menu\\\\?programs\\\\?startup|shell:startup", "Startup folder"),
    (r"register-wmievent|__eventfilter|commandlineeventconsumer", "WMI event subscription"),
    (r"\bcrontab\b|/etc/cron|systemctl\s+enable|launchctl\s+load", "unix persistence"),
    (r"new-service|sc\s+create\b", "service installation"),
    (r"\$profile\b|microsoft\.powershell_profile", "PowerShell profile"),
    (r"\.bashrc|\.zshrc|\.bash_profile|/etc/profile\.d", "shell profile"),
]
_PERSISTENCE = [(re.compile(p, re.IGNORECASE), why) for p, why in _PERSISTENCE]

_PRIVILEGE = [
    (r"start-process\b[^|;\n]*-verb\s+runas", "elevation prompt"),
    (r"\brunas\b\s*/user", "runas"),
    (r"\bsudo\b(?!\s+-n\s+true)", "sudo"),
    (r"net\s+user\b[^|;\n]*/add", "local account creation"),
    (r"net\s+localgroup\b[^|;\n]*administrators[^|;\n]*/add", "administrator group change"),
    (r"add-localgroupmember[^|;\n]*administrators", "administrator group change"),
    (r"new-localuser", "local account creation"),
]
_PRIVILEGE = [(re.compile(p, re.IGNORECASE), why) for p, why in _PRIVILEGE]

_SECURITY_DISABLE = [
    (r"set-mppreference[^|;\n]*-disable", "Defender disabled"),
    (r"add-mppreference[^|;\n]*-exclusionpath", "Defender exclusion added"),
    (r"netsh\s+advfirewall\s+set[^|;\n]*(off|disable)", "firewall disabled"),
    (r"set-executionpolicy[^|;\n]*(bypass|unrestricted)", "PowerShell policy bypassed"),
    (r"\bbcdedit\b[^|;\n]*testsigning", "driver signature enforcement"),
    (r"set-service[^|;\n]*(windefend|sense|wscsvc)[^|;\n]*disabled", "security service disabled"),
]
_SECURITY_DISABLE = [(re.compile(p, re.IGNORECASE), why) for p, why in _SECURITY_DISABLE]

_LINK_CREATE = re.compile(
    r"(mklink\b|new-item[^|;\n]*-itemtype\s+(symboliclink|junction)|\bln\s+-s)",
    re.IGNORECASE)

# Traversal that survives normalization is either a bug or an attempt.
_TRAVERSAL = re.compile(r"(\.\.[\\/]){2,}")


@register("scope")
def persistence(env, policy, session) -> list[Finding]:
    out = []
    for pat, why in _PERSISTENCE:
        m = pat.search(env.normalized)
        if m:
            out.append(Finding(
                ruleId="scope.persistence",
                severity="critical",
                score=100,
                message=(f"registers persistence ({why}) — code scheduled this way "
                         f"executes outside any governed session and is not mediated"),
                evidence=[m.group(0)[:120]],
                halt=True,
            ))
            break
    return out


@register("scope")
def privilege_escalation(env, policy, session) -> list[Finding]:
    out = []
    for pat, why in _PRIVILEGE:
        m = pat.search(env.normalized)
        if m:
            out.append(Finding(
                ruleId="scope.privilege",
                severity="critical",
                score=100,
                message=f"attempts privilege escalation or account change ({why})",
                evidence=[m.group(0)[:120]],
                halt=True,
            ))
            break
    return out


@register("scope")
def security_disable(env, policy, session) -> list[Finding]:
    out = []
    for pat, why in _SECURITY_DISABLE:
        m = pat.search(env.normalized)
        if m:
            out.append(Finding(
                ruleId="scope.security_disable",
                severity="critical",
                score=100,
                message=f"disables a host security control ({why})",
                evidence=[m.group(0)[:120]],
                halt=True,
            ))
    return out


@register("scope")
def link_creation(env, policy, session) -> list[Finding]:
    """Junctions and symlinks are the standard tool for defeating a path check.

    Create a link now, get a benign path approved later, and the write lands
    somewhere else. This is also the mechanism behind the TOCTOU window that a
    PreToolUse hook structurally cannot close, since it decides on a path string
    and never holds the handle.
    """
    m = _LINK_CREATE.search(env.normalized)
    if not m:
        return []
    return [Finding(
        ruleId="scope.link_creation",
        severity="high",
        score=60,
        message=("creates a symlink or junction — the standard way to make an "
                 "approved path resolve somewhere else after approval"),
        evidence=[m.group(0)[:120]],
    )]


@register("scope")
def traversal(env, policy, session) -> list[Finding]:
    if not _TRAVERSAL.search(env.normalized):
        return []
    return [Finding(
        ruleId="scope.traversal",
        severity="high",
        score=45,
        message="repeated parent-directory traversal survived path normalization",
    )]


@register("scope")
def outside_working_root(env, policy, session) -> list[Finding]:
    """Writes landing outside the session's working directory.

    Scored, not halted: legitimate work reaches outside a repo often enough
    (a temp file, a global config) that halting here would be noise. It raises
    the score so that reaching outside *combined with* anything else lands in
    REVIEW.
    """
    if not env.cwd or policy.tool_class(env.tool) not in ("write", "exec"):
        return []
    from ..envelope import canonical_path
    root = canonical_path(env.cwd)
    if not root:
        return []

    outside = []
    for p in env.paths:                    # declared targets only, to stay quiet
        if not (p == root or p.startswith(root.rstrip(os.sep) + os.sep)):
            if not any(p.startswith(t) for t in (os.path.normcase(os.environ.get("TEMP", "|||")),
                                                 os.path.normcase(os.environ.get("TMP", "|||")))):
                outside.append(p)
    if not outside:
        return []
    return [Finding(
        ruleId="scope.outside_root",
        severity="medium",
        score=30,
        message=f"writes outside the session working directory ({root})",
        files=outside[:5],
    )]
