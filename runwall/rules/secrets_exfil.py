"""Credential exposure and exfiltration.

The shape that matters is not "a secret appears" or "a network call happens" --
it is the two in the same action. Reading `.env` is ordinary. POSTing it
somewhere is not. So the high-severity findings here are conjunctions, which
also keeps the false-positive rate low enough that the operator keeps reading
the cards.

What this cannot do, stated plainly: once a host is allowlisted, content-level
exfiltration through it is invisible to a host-level control. A secret pushed to
an allowlisted gist, or encoded into a URL path on an approved API, passes.
Session budgets in ``session.py`` bound the volume; nothing here bounds the
content. Domain allowlisting is a coarse control and is described as one.
"""
from __future__ import annotations

import re

from . import Finding, register

_SECRET_LITERAL = re.compile(
    r"(sk-[a-z0-9]{16,}|ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|"
    r"xox[baprs]-[a-z0-9-]{10,}|akia[0-9a-z]{16}|"
    r"-----begin [a-z ]*private key-----|"
    r"eyj[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}\.[a-z0-9_-]{10,})", re.IGNORECASE)

_SECRET_REF = re.compile(
    r"(\$\{?[a-z_]*(api[_-]?key|secret|token|password|passwd|credential)[a-z_]*\}?"
    r"|%[a-z_]*(api[_-]?key|secret|token|password)[a-z_]*%"
    r"|\$env:[a-z_]*(key|secret|token|password)[a-z_]*)", re.IGNORECASE)

_SECRET_FILE = re.compile(
    r"(?<![\w.-])(\.env(\.[a-z]+)?|id_rsa|id_ed25519|\.npmrc|\.pypirc|"
    r"credentials|\.netrc|\.git-credentials|secrets?\.(ya?ml|json)|"
    r"\.aws[\\/]|\.ssh[\\/]|\.docker[\\/]config\.json)(?![\w-])", re.IGNORECASE)

_OUTBOUND = re.compile(
    r"(curl|wget|invoke-restmethod|invoke-webrequest|nc\b|netcat|"
    r"http\.client|requests\.(post|put)|urllib|fetch\(|axios|"
    r"\bscp\b|\bsftp\b|\brsync\b|\bmail\b|sendmail|smtp)", re.IGNORECASE)

_ENCODE_THEN_SEND = re.compile(
    r"(base64|b64encode|tobase64string|gzip|compress-archive|zip\b|xxd|openssl enc)",
    re.IGNORECASE)

_HISTORY_WIPE = re.compile(
    r"(history\s+-c|clear-history|remove-item[^|;\n]*consolehost_history|"
    r"wevtutil\s+cl|clear-eventlog|>\s*~?/?\.bash_history)", re.IGNORECASE)


@register("secrets")
def literal_secret_present(env, policy, session) -> list[Finding]:
    """A credential appearing verbatim in a tool call."""
    m = _SECRET_LITERAL.search(env.normalized)
    if not m:
        return []
    return [Finding(
        ruleId="secrets.literal_credential",
        severity="critical",
        score=80,
        message="a live-looking credential appears verbatim in this action",
        # Never echo the secret into a finding -- the ledger would then hold it
        # permanently, and the chain makes removal impossible.
        evidence=[f"{m.group(0)[:6]}…[redacted, {len(m.group(0))} chars]"],
    )]


@register("secrets")
def exfiltration(env, policy, session) -> list[Finding]:
    """Secret material AND an outbound channel in the same action."""
    outbound = _OUTBOUND.search(env.normalized)
    if not outbound:
        return []

    carriers = []
    if _SECRET_REF.search(env.normalized):
        carriers.append("environment credential reference")
    if _SECRET_FILE.search(env.normalized):
        carriers.append("credential file")
    if _SECRET_LITERAL.search(env.normalized):
        carriers.append("literal credential")
    if not carriers:
        return []

    findings = [Finding(
        ruleId="secrets.exfiltration",
        severity="critical",
        score=100,
        message=(f"outbound request carrying {', '.join(carriers)} — "
                 f"credential exfiltration"),
        evidence=[outbound.group(0)],
        halt=True,
    )]
    if _ENCODE_THEN_SEND.search(env.normalized):
        findings.append(Finding(
            ruleId="secrets.encoded_exfiltration",
            severity="critical",
            score=100,
            message="payload is encoded or compressed before transmission — "
                    "consistent with evading content inspection",
            halt=True,
        ))
    return findings


@register("secrets")
def credential_file_read(env, policy, session) -> list[Finding]:
    """Reading credential stores. Ordinary alone; taint-relevant in aggregate."""
    m = _SECRET_FILE.search(env.normalized)
    if not m:
        return []
    if _OUTBOUND.search(env.normalized):
        return []          # already covered, and at HALT, by exfiltration()
    return [Finding(
        ruleId="secrets.credential_access",
        severity="medium",
        score=30,
        message=f"reads a credential store ({m.group(0)})",
        evidence=[m.group(0)],
    )]


@register("secrets")
def anti_forensics(env, policy, session) -> list[Finding]:
    """Clearing shell history or event logs. There is no benign version of this
    inside an automated agent run."""
    m = _HISTORY_WIPE.search(env.normalized)
    if not m:
        return []
    return [Finding(
        ruleId="secrets.anti_forensics",
        severity="critical",
        score=100,
        message="clears shell history or event logs — destroys evidence",
        evidence=[m.group(0)],
        halt=True,
    )]
