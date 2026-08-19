"""Self-protection: the wall refusing to help dismantle itself.

The honest framing for this pack, stated up front so nobody oversells it: these
rules do not prevent an agent running as the operator from disabling Runwall.
Same-user process termination requires no privilege on Windows, and any file the
governor can write, the operator's agent can rewrite. What this pack does is
make the attempt *expensive and loud* -- every attempt is refused at the tool-call
layer and written to the ledger before it is refused, so "the wall went quiet"
is never indistinguishable from "nothing happened".

Containment comes from ``runwall harden`` putting these files under a different
Windows principal. This pack is the tripwire; ACLs are the lock. Ship both, and
do not describe the tripwire as a lock.
"""
from __future__ import annotations

import os
import re

from . import Finding, register
from ..envelope import canonical_path

_WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
_READ_TOOLS = ("Read", "NotebookRead", "Grep", "Glob")

# Commands whose effect is to READ a file. Only consulted when no write
# indicator is present -- see `_is_read_only`.
_READ_VERB = re.compile(
    r"(?:^|[|;&]\s*)\s*(cat|tail|head|less|more|wc|nl|od|xxd|strings|file|stat|"
    r"grep|egrep|fgrep|rg|findstr|select-string|sls|type|get-content|gc|"
    r"md5sum|sha\d+sum|get-filehash|diff|cmp)\b", re.IGNORECASE)

# Anything capable of changing a file. Presence of ANY of these means the
# command is treated as a write, whatever else it also does.
_WRITE_INDICATOR = re.compile(
    r"(>>?\s*\S|\btee\b|\bsed\b[^|;\n]*-i|\bmv\b|\bcp\b|\brm\b|\bdel\b|\berase\b|"
    r"\btruncate\b|\bchmod\b|\bchown\b|\bicacls\b|\battrib\b|\bfsutil\b|"
    r"set-content|add-content|out-file|new-item|remove-item|move-item|copy-item|"
    r"set-itemproperty|clear-content|rename-item|"
    r"open\s*\([^)]*['\"][wa]\+?['\"]|writefile|writealltext|writealllines)",
    re.IGNORECASE)


def _is_read_only(env) -> bool:
    """True when this action reads a protected file rather than changing it.

    Both outcomes are HALT -- Runwall's ledger holds prompts, paths and
    arguments, so reading it is gated exactly as writing it is. What differs is
    the label written to the ledger, and a record that says "modify" when the
    agent attempted a read misdescribes the very incident it exists to
    document. An audit trail whose classifications cannot be trusted is not an
    audit trail.

    Conservative by construction: only a positive read verb with no write
    indicator counts as a read. Anything ambiguous is labelled a modification,
    because over-describing an attempt is the safer error.
    """
    if env.tool in _READ_TOOLS:
        return True
    if env.tool in _WRITE_TOOLS:
        return False
    if env.tool != "Bash":
        return False
    if _WRITE_INDICATOR.search(env.normalized_action):
        return False
    return bool(_READ_VERB.search(env.normalized_action))

# Process control aimed at the governor.
_KILL = [
    re.compile(r"\btaskkill\b[^|;\n]*\b(runwall|governor)\b"),
    re.compile(r"\btaskkill\b[^|;\n]*/f\b[^|;\n]*python"),
    re.compile(r"stop-process\b[^|;\n]*(runwall|governor)"),
    re.compile(r"stop-process\b[^|;\n]*-name\b[^|;\n]*python"),
    re.compile(r"\bpkill\b[^|;\n]*runwall"),
    re.compile(r"\bkill\b\s+-9\b[^|;\n]*runwall"),
    re.compile(r"stop-service\b[^|;\n]*runwall"),
    re.compile(r"\bsc\b\s+(stop|delete)\b[^|;\n]*runwall"),
]

# The patterns above all assume the target name appears textually AFTER the
# kill verb, in the same pipe-free segment. PowerShell's idiomatic pipeline --
# `Get-Process runwall | Stop-Process`, or its short aliases `gps ... | spps`
# -- puts the target BEFORE the verb, separated by a `|` that `[^|;\n]*`
# deliberately excludes, and every pattern above missed it completely:
# `Get-Process runwall | Stop-Process` reached ALLOW with zero findings,
# which is exactly the "no single tool call should be able to disable
# enforcement, and no attempt should be unlogged" invariant THREAT_MODEL.md
# states as the one thing this pack must hold. This co-occurrence check is
# deliberately order-independent (a pipeline can name the target before the
# verb) rather than pattern-matching one more literal shape, because the
# underlying gap is positional, not lexical.
#
# Scoped to one `;`/newline-bounded statement -- an earlier version searched
# the whole command, so `python build.py; taskkill /F /IM notepad.exe` (an
# unrelated build plus an unrelated kill of Notepad) co-occurred into a false
# HALT: "python" matched the target list and "taskkill" matched the verb list,
# with no requirement that the two relate to each other. Statement-scoping
# still crosses pipes freely (`Get-Process runwall | Stop-Process` is one
# statement), which is the shape this check exists to catch; it costs the
# separate `$p = Get-Process runwall; $p.Kill()` variable-assignment form,
# which has a same-statement equivalent -- `(Get-Process runwall).Kill()` --
# that remains covered. See destructive.py's identical statement-scoping
# rationale, added for the same reason on a different rule.
_KILL_VERB_ANYWHERE = re.compile(
    r"\b(stop-process|spps|taskkill|pkill|stop-service)\b|\.kill\(\)|\bkill\s+-9\b",
    re.IGNORECASE)
_KILL_TARGET_ANYWHERE = re.compile(
    r"\b(runwall|governor)\b|\bpython[0-9.]*(\.exe)?\b", re.IGNORECASE)
_STATEMENT_SPLIT = re.compile(r";|\n|&&|\|\|")

# Launching an ungoverned harness, or one with permissions disabled. This is not
# "an agent being naughty" -- it is the single cheapest total bypass available,
# so it is a HALT rather than a score.
_UNGOVERNED_HARNESS = [
    re.compile(r"--dangerously-skip-permissions\b"),
    re.compile(r"--permission-mode[= ]\s*bypass"),
    re.compile(r"\bclaude\b[^|;\n]*--settings\b"),
    re.compile(r"set\s+claude_config_dir"),
    re.compile(r"\$env:claude_config_dir"),
]

# Interpreter substitution: replacing what the hook actually executes without
# touching any file the hook checks.
_INTERPRETER_HIJACK = [
    re.compile(r"\bsitecustomize\.py\b"),
    re.compile(r"\busercustomize\.py\b"),
    re.compile(r"set\s+pythonpath\b"),
    re.compile(r"\$env:pythonpath\b"),
    re.compile(r"\$env:path\s*=(?![^|;\n]*\$env:path)"),
    re.compile(r"setx?\s+path\s+(?![^|;\n]*%path%)", re.IGNORECASE),
]

_HOOK_DISABLE = [
    re.compile(r"\bhooks\b[^|;\n]*\bnull\b"),
    re.compile(r"runwall[^|;\n]*\b(down|disarm|stop|uninstall)\b"),
    re.compile(r"\bunregister\b[^|;\n]*hook"),
]


def _self_paths(policy) -> list[str]:
    """Every path whose modification would weaken the wall."""
    return policy.self_protected_paths()


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _targets_self(env, policy) -> list[str]:
    """Paths in this envelope that fall inside Runwall's own protected set.

    Compares canonicalized paths, never substrings. Substring matching on a
    basename is what makes a rule fire on ``webhook.site`` because it contains
    ``hook`` -- and a self-protection rule with a false positive rate is worse
    than none, because it is the rule an operator learns to click past.
    """
    protected = _self_paths(policy)
    return [p for p in env.target_paths()
            if any(_under(p, prot) for prot in protected)]


def _targets_sealed(env, policy) -> list[str]:
    """Paths that stay refused at every perimeter state, maintenance included."""
    sealed = policy.sealed_paths()
    return [p for p in env.target_paths()
            if any(_under(p, s) for s in sealed)]


# Filenames distinctive enough that naming one in a command is itself the
# signal, regardless of the path written around it. Anchored with boundaries so
# they cannot match as a fragment of a longer word.
_SELF_FILENAMES = re.compile(
    r"(?<![\w.-])(client\.token|approval\.key|chain\.anchor|operator\.json|"
    r"gate_decisions\.jsonl|perimeter\.json|runwall_hook\.py|manifest\.json)(?![\w-])")


@register("self_protect")
def touch_own_files(env, policy, session) -> list[Finding]:
    """Any action reaching Runwall's policy, ledger, keys, hook or code.

    Reads and writes are both refused, and are reported as what they were.
    Previously every match was labelled `modify_governor`, so a `tail` of the
    ledger was recorded as an attempted modification -- the right refusal
    carrying the wrong description.
    """
    if (env.tool not in _WRITE_TOOLS and env.tool not in _READ_TOOLS
            and env.tool != "Bash"):
        return []

    hits = _targets_self(env, policy)

    m = _SELF_FILENAMES.search(env.normalized_action)
    if m and m.group(1) not in hits:
        hits.append(m.group(1))

    if not hits:
        return []

    # Sealed targets -- the ledger, the anchor, key material -- are reported
    # separately so the gate can refuse them at every perimeter state. Source
    # targets are refused too, but a maintenance window can lift them; that
    # distinction has to exist in the finding, not only in the gate, or the
    # ledger cannot show which kind of refusal happened.
    sealed = _targets_sealed(env, policy)
    if sealed:
        return [Finding(
            ruleId="self_protect.sealed_surface",
            severity="critical",
            score=100,
            message=("action reaches Runwall's ledger, chain anchor or key "
                     "material - refused at every perimeter state, maintenance "
                     "included"),
            files=sealed,
            halt=True,
        )]

    if _is_read_only(env):
        return [Finding(
            ruleId="self_protect.read_governor_files",
            severity="critical",
            score=100,
            message=("action reads Runwall's own policy or code - reachable "
                     "only during an authenticated maintenance window"),
            files=hits,
            halt=True,
        )]
    return [Finding(
        ruleId="self_protect.modify_governor",
        severity="critical",
        score=100,
        message=("action modifies Runwall's own policy or code - reachable "
                 "only during an authenticated maintenance window"),
        files=hits,
        halt=True,
    )]


@register("self_protect")
def modify_harness_config(env, policy, session) -> list[Finding]:
    """Writes to the Claude Code settings that register the hook."""
    targets = [canonical_path(os.path.expanduser(p)) for p in policy.harness_config_paths]
    hits = [p for p in env.target_paths() if p in targets]
    if not hits and re.search(r"(?<![\w.-])\.claude[\\/]settings(\.local)?\.json",
                              env.normalized_action):
        hits = ["<.claude/settings.json referenced in command text>"]
    if not hits:
        return []
    return [Finding(
        ruleId="self_protect.harness_config",
        severity="critical",
        score=100,
        message="action modifies the harness configuration that installs the hook",
        files=hits,
        halt=True,
    )]


@register("self_protect")
def kill_governor(env, policy, session) -> list[Finding]:
    text = env.normalized_action
    for pat in _KILL:
        m = pat.search(text)
        if m:
            return [Finding(
                ruleId="self_protect.kill_governor",
                severity="critical",
                score=100,
                message="action attempts to terminate the governor process or service",
                evidence=[m.group(0)[:200]],
                halt=True,
            )]
    for stmt in _STATEMENT_SPLIT.split(text):
        verb = _KILL_VERB_ANYWHERE.search(stmt)
        target = _KILL_TARGET_ANYWHERE.search(stmt)
        if verb and target:
            return [Finding(
                ruleId="self_protect.kill_governor",
                severity="critical",
                score=100,
                message=("action attempts to terminate the governor process or service "
                         "- kill verb and target appear in an order the sequential "
                         "patterns above do not cover (e.g. a pipeline naming the "
                         "target before the verb)"),
                evidence=[verb.group(0)[:100], target.group(0)[:100]],
                halt=True,
            )]
    return []


@register("self_protect")
def ungoverned_harness(env, policy, session) -> list[Finding]:
    for pat in _UNGOVERNED_HARNESS:
        m = pat.search(env.normalized_action)
        if m:
            return [Finding(
                ruleId="self_protect.ungoverned_harness",
                severity="critical",
                score=100,
                message="action launches an agent harness with governance disabled or redirected",
                evidence=[m.group(0)[:200]],
                halt=True,
            )]
    return []


@register("self_protect")
def interpreter_hijack(env, policy, session) -> list[Finding]:
    for pat in _INTERPRETER_HIJACK:
        m = pat.search(env.normalized_action)
        if m:
            return [Finding(
                ruleId="self_protect.interpreter_hijack",
                severity="critical",
                score=100,
                message=("action alters interpreter resolution (PATH, PYTHONPATH, "
                         "sitecustomize) - this replaces what the hook executes "
                         "without modifying the hook"),
                evidence=[m.group(0)[:200]],
                halt=True,
            )]
    return []


@register("self_protect")
def disable_hook(env, policy, session) -> list[Finding]:
    for pat in _HOOK_DISABLE:
        m = pat.search(env.normalized_action)
        if m:
            return [Finding(
                ruleId="self_protect.disable_hook",
                severity="critical",
                score=100,
                message="action attempts to unregister or disarm the enforcement hook",
                evidence=[m.group(0)[:200]],
                halt=True,
            )]
    return []


@register("self_protect")
def read_governor_secrets(env, policy, session) -> list[Finding]:
    """Reading the client token is how an agent would talk to /decide directly."""
    secrets = [canonical_path(p) for p in policy.secret_paths()]
    hits = [p for p in env.target_paths() if p in secrets]
    if not hits:
        m = re.search(r"(?<![\w.-])(client\.token|approval\.key|operator\.json)(?![\w-])",
                      env.normalized_action)
        if m:
            hits = [m.group(1)]
    if not hits:
        return []
    return [Finding(
        ruleId="self_protect.read_secrets",
        severity="critical",
        score=100,
        message="action reads the governor's key material",
        files=hits,
        halt=True,
    )]


@register("self_protect")
def oversized_or_obfuscated(env, policy, session) -> list[Finding]:
    """Resource-exhaustion and unexplained layered encoding.

    An oversized payload is refused rather than evaluated: pushing the governor
    past the harness's hook timeout is the cheapest way to turn fail-closed into
    fail-open, so size is checked before anything expensive runs.
    """
    out = []
    if env.oversized:
        out.append(Finding(
            ruleId="self_protect.oversized_payload",
            severity="critical",
            score=100,
            message="payload exceeds the size cap - refused without evaluation",
            halt=True,
        ))
    if env.residual_encoding:
        out.append(Finding(
            ruleId="self_protect.residual_encoding",
            severity="high",
            score=55,
            message=(f"payload still contained decodable encoding after "
                     f"{env.decode_passes} passes - layered obfuscation has no "
                     f"legitimate use a plain command would not serve"),
        ))
    elif env.decode_passes >= 2:
        out.append(Finding(
            ruleId="self_protect.obfuscated_payload",
            severity="medium",
            score=25,
            message=f"payload required {env.decode_passes} decoding passes",
        ))
    return out
