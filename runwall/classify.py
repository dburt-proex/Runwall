"""Deriving the action label -- server-side, always.

The single most important property of this module is what it does *not* accept.
An agent controls the shape of its own tool call, so any action label it
supplies is attacker-controlled input to the gate lookup: label a destructive
command ``local_note_creation`` and a matrix lookup happily returns ALLOW. The
label is therefore computed here, from the normalized envelope, and the hook
protocol has no field through which one could be supplied.

``ACTIONS`` is closed and is checked against the policy's ``gate_matrix`` at
load time in both directions. A label this module can emit that the matrix does
not cover refuses the load; a matrix entry nothing emits refuses it too. Dead
policy that reads as coverage is its own hazard.
"""
from __future__ import annotations

import re

ACTIONS = frozenset({
    # read
    "read_local_file", "search_local", "list_directory",
    # write
    "write_local_file", "edit_local_file", "write_protected_path", "delete_file",
    # execute
    "run_shell_command", "run_interpreter", "install_dependency",
    "run_git_local", "run_git_remote",
    # network / external
    "fetch_external_content", "send_external_message", "upload_or_publish",
    # destructive
    "destroy_data", "destroy_storage", "rewrite_history",
    # governance self-protection
    # `modify_governor` / `read_governor_files` target Runwall's own source and
    # are liftable by a maintenance window. `touch_sealed_surface` and the rest
    # are not liftable by anything.
    "modify_governor", "read_governor_files", "touch_sealed_surface",
    "modify_harness_config", "terminate_governor",
    "launch_ungoverned_harness", "read_governor_secrets",
    # fallback
    "unknown_action",
})


def known_actions() -> set[str]:
    return set(ACTIONS)


# Finding-driven labels take precedence over text heuristics: if a rule already
# concluded something specific, the label must agree with it rather than
# re-deriving a milder one from the same text.
_FROM_RULE = {
    "self_protect.sealed_surface": "touch_sealed_surface",
    "self_protect.modify_governor": "modify_governor",
    "self_protect.read_governor_files": "read_governor_files",
    "self_protect.harness_config": "modify_harness_config",
    "self_protect.kill_governor": "terminate_governor",
    "self_protect.ungoverned_harness": "launch_ungoverned_harness",
    "self_protect.interpreter_hijack": "modify_governor",
    "self_protect.disable_hook": "modify_governor",
    "self_protect.read_secrets": "read_governor_secrets",
    "destructive.recursive_delete": "destroy_data",
    "destructive.sql": "destroy_data",
    "destructive.storage": "destroy_storage",
    "destructive.fork_bomb": "destroy_storage",
    "destructive.git": "rewrite_history",
    "destructive.halt_pattern": "destroy_data",
    "secrets.exfiltration": "send_external_message",
    "egress.blocked_domain": "fetch_external_content",
}

_INTERPRETER = re.compile(
    r"\b(python[0-9.]*|py|node|deno|bun|ruby|perl|php|pwsh|powershell|uv|npx)\b[^|;\n]*"
    # -c / -e / --eval, a script file, or -m <module>. `python -m pytest` runs
    # arbitrary code exactly as much as `python -c` does; the opacity is the
    # same, so the classification should be too.
    r"(\s-[ce]\b|\s-e\b|\s--eval\b|\s-m\s+[\w.]+|\s\S+\.(py|js|mjs|ts|rb|pl|php|ps1))")
_INSTALL = re.compile(
    r"\b(pip[0-9.]*\s+install|npm\s+(i|install|ci)\b|pnpm\s+add|yarn\s+add|"
    r"uv\s+(pip\s+)?(install|add)|cargo\s+(add|install)|go\s+get|gem\s+install|"
    r"winget\s+install|choco\s+install|apt(-get)?\s+install)\b")
_GIT_REMOTE = re.compile(r"\bgit\b[^|;\n]*\b(push|pull|fetch|clone|remote\s+add)\b")
_GIT_LOCAL = re.compile(r"\bgit\b")
_PUBLISH = re.compile(
    r"\b(npm\s+publish|pip\s+upload|twine\s+upload|cargo\s+publish|"
    r"gh\s+(release|pr)\s+create|docker\s+push|aws\s+s3\s+(cp|sync)|"
    r"gcloud\s+\S+\s+deploy|vercel\s+deploy|netlify\s+deploy)\b")
_SEND = re.compile(
    r"\b(mailto:|sendmail|smtp|curl[^|;\n]*-[a-z]*x?\s*post|"
    r"invoke-restmethod[^|;\n]*-method\s*post|wget[^|;\n]*--post|"
    r"slack\S*webhook|discord\S*webhook|api\.telegram\.org)\b")
_FETCH = re.compile(r"\b(curl|wget|invoke-webrequest|invoke-restmethod|https?://)")
_DELETE = re.compile(r"\b(rm|del|erase|remove-item|unlink|rmdir|rd)\b")


def classify(env, findings, policy) -> str:
    """Return exactly one action label from ACTIONS."""
    # 1. Rules win. They looked at the same text with more specificity.
    for f in findings:
        label = _FROM_RULE.get(f.ruleId)
        if label:
            return label

    tool = env.tool
    text = env.normalized
    tool_class = policy.tool_class(tool)

    # 2. Tool identity, where it is unambiguous.
    if tool in ("Read", "NotebookRead"):
        return "read_local_file"
    if tool in ("Grep", "Glob"):
        return "search_local" if tool == "Grep" else "list_directory"
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        if any(policy.is_protected(p) for p in env.paths):
            return "write_protected_path"
        return "write_local_file" if tool == "Write" else "edit_local_file"
    if tool in ("WebFetch", "WebSearch"):
        return "fetch_external_content"

    # 3. Command text, most consequential first.
    if tool_class in ("exec", "unknown") or tool == "Bash":
        if _PUBLISH.search(text):
            return "upload_or_publish"
        if _SEND.search(text):
            return "send_external_message"
        if _INSTALL.search(text):
            return "install_dependency"
        if _INTERPRETER.search(text):
            # Effects happen inside a process we never see. Labelled distinctly
            # so policy can price that opacity rather than treating it as an
            # ordinary shell command.
            return "run_interpreter"
        if _GIT_REMOTE.search(text):
            return "run_git_remote"
        if _DELETE.search(text):
            return "delete_file"
        if _FETCH.search(text):
            return "fetch_external_content"
        if _GIT_LOCAL.search(text):
            return "run_git_local"
        return "run_shell_command"

    if tool_class == "network":
        return "fetch_external_content"
    if tool_class == "read":
        return "read_local_file"

    return "unknown_action"
