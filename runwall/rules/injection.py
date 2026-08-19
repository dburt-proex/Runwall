"""Prompt injection -- specifically, injection arriving through tool RESULTS.

The interesting attack is not a hostile prompt from the user. It is a README, an
issue body, a web page or a dependency description that says "run the setup
command", which the agent then dutifully proposes. The proposed command is
*plausible in isolation*, because it is plausible in isolation. Nothing about
its text distinguishes it from a command the user asked for.

Which means text inspection cannot solve this, and a rule pack that claims to
"detect prompt injection" is selling something. What actually engages the
problem is **provenance**: track that the session has consumed untrusted
external content, and raise the gate floor for everything after it until a real
user turn. That machinery lives in ``session.py``; this pack supplies its
inputs and prices the resulting risk.

So the honest split is:
  * ``session.taint`` — provenance, the control that works
  * this pack — recognises content that is *trying* to be an instruction, and
    refuses to let a tainted session take consequential action unsupervised
"""
from __future__ import annotations

import re

from . import Finding, register

# Phrasings whose only purpose is to redirect an agent. These do occur in
# legitimate security documentation, which is why they raise a score rather
# than halting on their own.
_INJECTION_MARKER = re.compile(
    r"(ignore (?:all )?(?:previous|prior|above) (?:instructions?|prompts?)|"
    r"disregard (?:your|all|the) (?:instructions?|rules?|system prompt)|"
    r"you are now|new instructions?:|system prompt:|"
    r"<\|im_start\|>|\[/?INST\]|###\s*instruction|"
    r"do not (?:tell|inform|mention to) the user|"
    r"without (?:asking|informing|notifying) the (?:user|human|operator)|"
    r"this is (?:an? )?(?:authorized|approved|pre-approved|sanctioned)|"
    r"the (?:user|operator|admin) has already (?:approved|authorized|consented))",
    re.IGNORECASE)

# Claims of authority an agent might relay from content it read.
_AUTHORITY_CLAIM = re.compile(
    r"(as (?:an? )?(?:admin|administrator|system|root|anthropic)|"
    r"override (?:the )?(?:governance|policy|security|guardrails?)|"
    r"bypass (?:the )?(?:wall|policy|check|governance|runwall)|"
    r"in (?:test|debug|maintenance|developer) mode|"
    r"security (?:scan|audit) exemption)", re.IGNORECASE)

_CONSEQUENTIAL = frozenset({
    "delete_file", "run_interpreter", "install_dependency", "run_git_remote",
    "send_external_message", "upload_or_publish", "write_protected_path",
})


@register("injection")
def injection_markers(env, policy, session) -> list[Finding]:
    """Instruction-shaped text inside a tool call's payload."""
    out = []
    m = _INJECTION_MARKER.search(env.normalized)
    if m:
        out.append(Finding(
            ruleId="injection.marker",
            severity="high",
            score=55,
            message=("payload contains instruction-override phrasing — text of this "
                     "shape is data, never a directive, and its presence in an "
                     "action payload is itself notable"),
            evidence=[m.group(0)[:160]],
        ))
    a = _AUTHORITY_CLAIM.search(env.normalized)
    if a:
        out.append(Finding(
            ruleId="injection.authority_claim",
            severity="high",
            score=60,
            message=("payload asserts pre-authorization or an exemption — "
                     "authorization is never established by content, only by an "
                     "operator decision recorded in the ledger"),
            evidence=[a.group(0)[:160]],
        ))
    return out


@register("injection")
def tainted_consequential_action(env, policy, session) -> list[Finding]:
    """A consequential action proposed after the session read untrusted content.

    This is the rule that actually engages injection laundering. The command
    itself may be perfectly ordinary; what is not ordinary is taking it
    immediately after ingesting external content, with no intervening user turn
    to establish that a human asked for it.
    """
    from ..classify import classify as _classify
    action = _classify(env, [], policy)
    if action not in _CONSEQUENTIAL:
        return []
    if session.taint <= 0:
        return []

    if session.taint >= 2:
        return [Finding(
            ruleId="injection.laundered_instruction",
            severity="critical",
            score=100,
            message=(f"consequential action '{action}' proposed after this session "
                     f"consumed external content containing imperative language, "
                     f"with no intervening user turn. Sources: "
                     f"{', '.join(session.taint_sources[:2])}"),
            halt=True,
        )]
    return [Finding(
        ruleId="injection.tainted_session",
        severity="high",
        score=50,
        message=(f"consequential action '{action}' proposed while the session is "
                 f"carrying untrusted external content "
                 f"({len(session.taint_sources)} source(s))"),
    )]


@register("injection")
def instruction_in_written_content(env, policy, session) -> list[Finding]:
    """Writing injection-shaped text into a file others will read.

    An agent writing "ignore previous instructions" into a README is planting
    for the next reader — possibly another agent, possibly this one after a
    context reset.
    """
    if env.tool not in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        return []
    # "new_source" is NotebookEdit's content field (its equivalent of Edit's
    # "new_string") -- omitted here independently made this rule blind to
    # planted instructions written through NotebookEdit specifically.
    content = " ".join(str(v) for k, v in env.raw_params.items()
                       if k in ("content", "new_string", "new_source") and isinstance(v, str))
    m = _INJECTION_MARKER.search(content)
    if not m:
        return []
    return [Finding(
        ruleId="injection.planted_instruction",
        severity="critical",
        score=85,
        message=("writes instruction-override text into a file — this plants an "
                 "injection for whoever reads it next"),
        evidence=[m.group(0)[:160]],
        files=env.paths,
    )]
