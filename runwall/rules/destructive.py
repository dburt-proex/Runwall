"""Destructive-operation rules.

Scope: irreversible or hard-to-reverse effects on data, repositories, and
storage. These are the findings that carry ``halt=True`` rather than a score,
because their cost is not proportional to a threshold -- a dropped table is not
40% bad.

Every pattern here matches against ``env.normalized_action``, which has already been
base64-decoded, backtick-stripped, concat-collapsed and NFC-folded by
``envelope.normalize_text``. Writing these patterns against raw text would make
them trivially evadable.
"""
from __future__ import annotations

import re

from . import Finding, register

# --- filesystem -----------------------------------------------------------

_RECURSIVE_DELETE = [
    # rm -rf, rm -fr, rm -r -f, with flags in any order
    re.compile(r"\brm\b(?=[^|;&\n]*\s-[a-z]*r)(?=[^|;&\n]*\s-[a-z]*f)"),
    re.compile(r"\brm\b\s+-[a-z]*rf[a-z]*\b"),
    re.compile(r"\brm\b\s+-[a-z]*fr[a-z]*\b"),
    # PowerShell
    re.compile(r"remove-item\b(?=[^|;\n]*-recurse)(?=[^|;\n]*-force)"),
    re.compile(r"\bri\b\s+(?=[^|;\n]*-recurse)(?=[^|;\n]*-force)"),
    re.compile(r"\[io\.directory\]::delete\s*\([^)]*,\s*\$?true"),
    re.compile(r"get-childitem[^|;\n]*\|\s*%?\s*\{?\s*\$_\.delete\(\)"),
    # cmd
    re.compile(r"\brd\b\s+/s\b", re.IGNORECASE),
    re.compile(r"\brmdir\b\s+/s\b", re.IGNORECASE),
    re.compile(r"\bdel\b(?=[^|;&\n]*/s)(?=[^|;&\n]*/q)", re.IGNORECASE),
    # `find` performs its own recursion, so none of these need `rm -rf` --
    # `-delete` never invokes rm at all, and `-exec rm {} \;` / `| xargs rm`
    # hand find's matches to a completely bare `rm` with no -r/-f flags for
    # the three `rm` patterns above to catch. `find X -delete` in particular
    # reached full ALLOW with zero findings before this fix: no `rm` token to
    # match against at all.
    #
    # `(?<!\S)` requires whitespace (or statement start) immediately before
    # the flag -- a bare `\b-delete\b` also matched "-delete" as a substring
    # inside an unrelated quoted argument (`find . -name '*-delete*'`,
    # `find . -iname 'needs-delete'`), HALTing an ordinary filename search
    # that never used the flag at all.
    re.compile(r"\bfind\b[^|;\n]*(?<!\S)-delete\b"),
    re.compile(r"\bfind\b[^|;\n]*-exec(dir)?\s+rm\b"),
    re.compile(r"\bfind\b[^|;\n]*\|\s*xargs\b[^|;\n]*\brm\b"),
]

# The patterns above require -Recurse and -Force to sit in the SAME pipe-free
# segment as Remove-Item/ri itself. PowerShell's idiomatic discover-then-act
# pipeline -- `Get-ChildItem -Recurse C:\dir | Remove-Item`, optionally with a
# Where-Object filter stage in between -- puts the -Recurse flag on the
# discovery side of the pipe and leaves Remove-Item bare, which every pattern
# above missed (this is the same order/pipe-position gap fixed in
# self_protect.py's kill_governor for `Get-Process | Stop-Process`; -Force is
# not required for the discovery side to be fully destructive here, since the
# recursion already happened at Get-ChildItem, so it is deliberately not
# required in this check either). Scoped to one statement, not the whole
# command, so an unrelated `Copy-Item -Recurse ...; Remove-Item unrelated.tmp`
# on the same line does not co-occur into a false positive. The split
# originally covered only `;`/newline: `Get-ChildItem -Recurse src |
# Select-String TODO && Remove-Item temp.txt` -- a read-only search chained
# with an unrelated single-file delete -- was still one un-split segment
# under that split, so it co-occurred into a false HALT. `&&`/`||` are
# statement separators exactly like `;` for this purpose and are split on too.
_DISCOVER_VERB = re.compile(r"\b(get-childitem|gci|dir|ls)\b")
_RECURSE_FLAG = re.compile(r"-r(ecurse)?\b")
_PIPELINE_DELETE_VERB = re.compile(r"\b(remove-item|ri)\b")
_STATEMENT_SPLIT = re.compile(r";|\n|&&|\|\|")


def _pipeline_discover_then_delete(text: str) -> bool:
    for stmt in _STATEMENT_SPLIT.split(text):
        if (_DISCOVER_VERB.search(stmt) and _RECURSE_FLAG.search(stmt)
                and _PIPELINE_DELETE_VERB.search(stmt)):
            return True
    return False

_STORAGE = [
    (re.compile(r"\bmkfs(\.[a-z0-9]+)?\b"), "filesystem creation (mkfs)"),
    (re.compile(r"\bformat\s+[a-z]:"), "volume format"),
    (re.compile(r"\bdiskpart\b"), "diskpart"),
    (re.compile(r"\bcipher\s+/w\b"), "free-space wipe (cipher /w)"),
    (re.compile(r"\bdd\b[^|;\n]*\bof=/dev/(sd|nvme|disk)"), "raw block device write"),
    (re.compile(r">\s*/dev/(sd|nvme|disk)[a-z0-9]*\b"), "redirect to block device"),
]

_SQL = [
    (re.compile(r"\bdrop\s+(table|database|schema)\b"), "SQL DROP"),
    (re.compile(r"\btruncate\s+table\b"), "SQL TRUNCATE"),
    # DELETE with no WHERE is a full-table delete.
    (re.compile(r"\bdelete\s+from\s+\S+(?![^;]*\bwhere\b)"), "SQL DELETE without WHERE"),
    (re.compile(r"\bupdate\s+\S+\s+set\b(?![^;]*\bwhere\b)"), "SQL UPDATE without WHERE"),
]

_GIT = [
    (re.compile(r"\bgit\b[^|;\n]*\bpush\b[^|;\n]*(--force\b(?!-with-lease)|(?<!\w)-f(?!\w))"),
     "force push (overwrites remote history)", True),
    (re.compile(r"\bgit\b[^|;\n]*\breset\b[^|;\n]*--hard\b"),
     "git reset --hard (discards uncommitted work)", False),
    (re.compile(r"\bgit\b[^|;\n]*\bclean\b[^|;\n]*-[a-z]*[fd][a-z]*x?"),
     "git clean -fd (deletes untracked files)", False),
    (re.compile(r"\bgit\b[^|;\n]*\bfilter-branch\b"), "git filter-branch (rewrites history)", True),
    (re.compile(r"\bgit\b[^|;\n]*\bbranch\b[^|;\n]*(-D|--delete\s+--force)"),
     "force branch delete", False),
]

_PERMS = [
    (re.compile(r"\bchmod\s+(-[a-z]+\s+)*777\b"), "chmod 777 (world-writable)"),
    (re.compile(r"icacls\b[^|;\n]*/grant\b[^|;\n]*(everyone|users):\s*\(?f\)?"),
     "grant Everyone full control"),
    (re.compile(r"\bchown\s+-r\b[^|;\n]*\broot\b"), "recursive chown to root"),
]

_FORKBOMB = re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")

# Decode-then-execute. Worth catching on the *shape* rather than on whatever
# decodes out of it, because deobfuscation is bounded and adversarial: if the
# payload survives the pass ceiling, this still fires. Piping a decoder into an
# interpreter has no legitimate form that writing the command plainly would not
# also serve.
_DECODE_EXEC = re.compile(
    r"(base64\s+(-d|--decode)|frombase64string|certutil\s+-decode|xxd\s+-r|"
    r"openssl\s+enc\s+-d)[^|;\n]*\|\s*(sh|bash|zsh|python|node|perl|ruby|pwsh|powershell|iex)"
    r"|\|\s*(iex|invoke-expression)"
    r"|(iex|invoke-expression)\s*\(\s*(new-object\s+net\.webclient|irm|iwr|curl|wget)"
    r"|(curl|wget|irm|iwr)[^|;\n]*\|\s*(sh|bash|zsh)\b", re.IGNORECASE)


def _ev(env, pattern: re.Pattern) -> list[str]:
    m = pattern.search(env.normalized_action)
    return [m.group(0)[:200]] if m else []


@register("destructive")
def recursive_delete(env, policy, session) -> list[Finding]:
    for pat in _RECURSIVE_DELETE:
        if pat.search(env.normalized_action):
            return [Finding(
                ruleId="destructive.recursive_delete",
                severity="critical",
                score=100,
                message="recursive forced delete - irreversible without a backup",
                evidence=_ev(env, pat),
                files=env.paths,
                halt=True,
            )]
    if _pipeline_discover_then_delete(env.normalized_action):
        return [Finding(
            ruleId="destructive.recursive_delete",
            severity="critical",
            score=100,
            message=("recursive forced delete - discover-then-pipe-to-Remove-Item "
                     "idiom, an order the sequential patterns above do not cover"),
            files=env.paths,
            halt=True,
        )]
    return []


@register("destructive")
def storage_destruction(env, policy, session) -> list[Finding]:
    out = []
    for pat, label in _STORAGE:
        if pat.search(env.normalized_action):
            out.append(Finding(
                ruleId="destructive.storage",
                severity="critical",
                score=100,
                message=f"{label} - destroys data at the device level",
                evidence=_ev(env, pat),
                halt=True,
            ))
    return out


@register("destructive")
def sql_destruction(env, policy, session) -> list[Finding]:
    out = []
    for pat, label in _SQL:
        if pat.search(env.normalized_action):
            out.append(Finding(
                ruleId="destructive.sql",
                severity="critical",
                score=100,
                message=f"{label} - unbounded data loss",
                evidence=_ev(env, pat),
                halt=True,
            ))
    return out


@register("destructive")
def git_history(env, policy, session) -> list[Finding]:
    out = []
    for pat, label, halt in _GIT:
        if pat.search(env.normalized_action):
            out.append(Finding(
                ruleId="destructive.git",
                severity="critical" if halt else "high",
                score=100 if halt else 45,
                message=label,
                evidence=_ev(env, pat),
                halt=halt,
            ))
    return out


@register("destructive")
def permission_widening(env, policy, session) -> list[Finding]:
    out = []
    for pat, label in _PERMS:
        if pat.search(env.normalized_action):
            out.append(Finding(
                ruleId="destructive.permissions",
                severity="high",
                score=60,
                message=f"{label} - widens access rather than narrowing it",
                evidence=_ev(env, pat),
            ))
    return out


@register("destructive")
def fork_bomb(env, policy, session) -> list[Finding]:
    if _FORKBOMB.search(env.normalized_action):
        return [Finding(
            ruleId="destructive.fork_bomb",
            severity="critical",
            score=100,
            message="fork bomb - denial of service against this machine",
            halt=True,
        )]
    return []


@register("destructive")
def decode_and_execute(env, policy, session) -> list[Finding]:
    """Piping a decoder or a download straight into an interpreter."""
    m = _DECODE_EXEC.search(env.normalized_action)
    if not m:
        return []
    return [Finding(
        ruleId="destructive.decode_exec",
        severity="critical",
        score=100,
        message=("decoded or downloaded content is piped directly into an "
                 "interpreter - the executed payload is never inspected"),
        evidence=[m.group(0)[:160]],
        halt=True,
    )]


@register("destructive")
def protected_path_write(env, policy, session) -> list[Finding]:
    """Writes to paths the policy marks protected (lockfiles, migrations, auth)."""
    if env.tool not in ("Write", "Edit", "NotebookEdit", "MultiEdit"):
        return []
    hits = [p for p in env.target_paths() if policy.is_protected(p)]
    if not hits:
        return []
    return [Finding(
        ruleId="destructive.protected_path",
        severity="high",
        score=50,
        message="write targets a protected path",
        files=hits,
    )]


@register("destructive")
def halt_pattern(env, policy, session) -> list[Finding]:
    """Literal strings the policy declares unconditionally unsafe.

    Carried over from Diffwall's ``haltPatterns`` (rules/default.yml) so the two
    systems refuse the same literals. Matched against normalized text, so the
    encoded forms Diffwall would miss on a raw diff are caught here.
    """
    out = []
    for literal in policy.halt_patterns:
        if literal.casefold() in env.normalized_action:
            out.append(Finding(
                ruleId="destructive.halt_pattern",
                severity="critical",
                score=100,
                message=f"policy halt pattern matched: {literal}",
                evidence=[literal],
                halt=True,
            ))
    return out
