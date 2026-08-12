"""Blast radius -- how far the damage reaches if this action is wrong.

CASA lists "operational blast radius" as a risk dimension but does not define
how to compute one. This module does, and it makes two commitments that keep the
number honest:

**It carries its own confidence.** A blast radius computed before execution is a
prediction, not a measurement. A low-confidence prediction of high blast is
routed to a human rather than acted on, because the correct response to "this
might be enormous and I am not sure" is to ask.

**It is re-measured afterwards.** ``basis`` records whether a figure was
declared, inferred, or observed. Once the ledger holds both the prediction and
the post-execution observation, a systematic gap between them is the best
available evasion detector -- an action that consistently turns out larger than
it looked is either misclassified or being shaped to look small. That signal is
nearly free once the ledger exists, and nothing else in the system produces it.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

SCOPES = ("local", "repo", "machine", "network", "external")
REVERSIBILITY = ("trivial", "recoverable", "irreversible")
PROPAGATION = ("bounded", "fan_out")

_SCOPE_RANK = {s: i for i, s in enumerate(SCOPES)}
_REV_RANK = {r: i for i, r in enumerate(REVERSIBILITY)}

_SECRET_HINT = re.compile(
    r"\b(api[_-]?key|secret|token|password|passwd|credential|private[_-]?key|"
    r"\.env\b|aws_access|bearer\s+[a-z0-9._-]{10,})", re.IGNORECASE)
_PERSONAL_HINT = re.compile(
    r"\b(ssn|social security|date of birth|passport|customer[_-]?(list|data)|"
    r"email[_-]?list|phone[_-]?number)\b", re.IGNORECASE)
_FINANCIAL_HINT = re.compile(
    r"\b(invoice|payment|payout|refund|charge|stripe|paypal|bank[_-]?account|"
    r"routing[_-]?number|card[_-]?number)\b", re.IGNORECASE)
_URL = re.compile(r"https?://([a-z0-9.-]+)", re.IGNORECASE)
_FANOUT = re.compile(r"\b(for|foreach|while|xargs|parallel|-r\b|--recursive|\*\*|\*\.)")


@dataclass
class BlastRadius:
    scope: str = "local"
    reversibility: str = "recoverable"
    subjects_affected: int = 0
    data_classes: list[str] = field(default_factory=list)
    propagation: str = "bounded"
    confidence: float = 0.5
    basis: str = "inferred"
    notes: list[str] = field(default_factory=list)

    @property
    def is_high(self) -> bool:
        return (_SCOPE_RANK[self.scope] >= _SCOPE_RANK["machine"]
                or self.reversibility == "irreversible"
                or self.propagation == "fan_out"
                or bool(set(self.data_classes) & {"secrets", "personal", "financial"}))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["is_high"] = self.is_high
        return d


def _widen(current: str, candidate: str, ranks: dict) -> str:
    return candidate if ranks[candidate] > ranks[current] else current


def compute(env, policy, findings) -> BlastRadius:
    """Derive blast radius from the normalized envelope and the findings."""
    b = BlastRadius()
    text = env.normalized
    tool_class = policy.tool_class(env.tool)

    # -- scope -------------------------------------------------------------
    if tool_class in ("write", "exec"):
        b.scope = _widen(b.scope, "repo", _SCOPE_RANK)
    if tool_class == "network" or _URL.search(text):
        b.scope = _widen(b.scope, "network", _SCOPE_RANK)
    for p in env.all_paths():
        low = p.casefold()
        if any(seg in low for seg in ("\\windows\\", "\\program files", "\\system32",
                                      "/etc/", "/usr/", "/bin/")):
            b.scope = _widen(b.scope, "machine", _SCOPE_RANK)
            b.notes.append("touches a system location")
            break
    if re.search(r"\b(git\s+push|npm\s+publish|pip\s+upload|twine|gh\s+(pr|release)|"
                 r"curl\s+-[a-z]*x?\s*post|smtp|sendmail|mailto:)", text):
        b.scope = _widen(b.scope, "external", _SCOPE_RANK)
        b.notes.append("action leaves this machine")

    # -- reversibility -----------------------------------------------------
    if any(f.halt for f in findings):
        b.reversibility = "irreversible"
    elif re.search(r"\b(delete|remove|drop|truncate|overwrite|force|--hard|>\s*\S)", text):
        b.reversibility = _widen(b.reversibility, "irreversible", _REV_RANK)
    elif tool_class == "read":
        b.reversibility = "trivial"

    # An action that leaves the machine cannot be un-sent, whatever it is.
    if b.scope == "external":
        b.reversibility = _widen(b.reversibility, "irreversible", _REV_RANK)
        b.notes.append("external effects cannot be recalled")

    # -- data classes ------------------------------------------------------
    haystack = text + " " + " ".join(env.all_paths())
    for pat, label in ((_SECRET_HINT, "secrets"), (_PERSONAL_HINT, "personal"),
                       (_FINANCIAL_HINT, "financial")):
        if pat.search(haystack):
            b.data_classes.append(label)
    if tool_class in ("write", "exec") and not b.data_classes:
        b.data_classes.append("code" if env.paths else "unknown")

    # -- propagation -------------------------------------------------------
    if _FANOUT.search(text) and tool_class in ("write", "exec", "network"):
        b.propagation = "fan_out"
        b.notes.append("iteration or glob suggests the effect repeats")

    # -- subjects ----------------------------------------------------------
    b.subjects_affected = max(len(env.all_paths()), 1 if tool_class != "read" else 0)
    if b.propagation == "fan_out":
        # Genuinely unknown, and pretending otherwise is the failure mode this
        # field exists to prevent. -1 reads as "unbounded" downstream.
        b.subjects_affected = -1

    # -- confidence --------------------------------------------------------
    confidence = 0.85
    if env.tool == "Bash":
        # A shell string is an intent, not a plan. We are reading a command, not
        # observing an effect.
        confidence -= 0.20
    if re.search(r"\b(python|node|deno|ruby|perl|pwsh|powershell|bash|sh|uv|npx)\b\s+"
                 r"(-[ce]\b|\S+\.(py|js|ts|rb|ps1|sh))", text):
        confidence -= 0.30
        b.notes.append("interpreter invocation - effects occur inside a process "
                       "Runwall does not observe")
        b.scope = _widen(b.scope, "machine", _SCOPE_RANK)
    if env.decode_passes:
        confidence -= 0.10 * env.decode_passes
    if env.oversized:
        confidence = 0.0
    b.confidence = max(0.0, min(1.0, confidence))
    b.basis = "inferred"
    return b


def floor_route(b: BlastRadius) -> str:
    """Minimum route this blast radius justifies, independent of score.

    Scores are additive and tuned; blast radius is categorical. A cheap-looking
    action with an irreversible external effect should not reach ALLOW because
    it happened to accumulate few points.
    """
    if b.confidence < 0.4 and b.is_high:
        return "REVIEW"
    if b.scope == "external" and b.reversibility == "irreversible":
        return "REVIEW"
    if "secrets" in b.data_classes and b.scope in ("network", "external"):
        return "HALT"
    if b.propagation == "fan_out" and b.reversibility == "irreversible":
        return "REVIEW"
    return "ALLOW"


def observe(env, result_summary: dict) -> BlastRadius:
    """Post-execution measurement, for the predicted-vs-observed delta."""
    b = BlastRadius(basis="observed", confidence=1.0)
    b.subjects_affected = int(result_summary.get("files_touched") or 0)
    b.scope = result_summary.get("scope") or "local"
    b.data_classes = list(result_summary.get("data_classes") or [])
    b.reversibility = result_summary.get("reversibility") or "recoverable"
    return b
