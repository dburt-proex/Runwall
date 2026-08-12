"""Rule registry and the Finding contract.

``Finding`` is deliberately field-identical to Diffwall's TypeScript interface
(``src/types.ts``): ruleId, severity, score, message, files, evidence, halt.
Same shape, same additive scoring, same thresholds. A Runwall finding and a
Diffwall finding render in the same report and mean the same thing -- Diffwall
guards what gets written, Runwall guards what gets done, and a reviewer should
not have to learn two vocabularies.

Every rule is deterministic: regex, path comparison, set membership, arithmetic.
No rule consults a language model. This is the property that makes the wall
worth having -- a regex cannot be talked out of matching. An agent can obfuscate
its payload (which ``envelope.normalize_text`` is there to undo) but it cannot
persuade a rule to change its mind, because there is no mind to change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass
class Finding:
    """One reason an action is not obviously safe. Mirrors Diffwall's Finding."""

    ruleId: str
    severity: str
    score: int
    message: str
    files: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    halt: bool = False

    def __post_init__(self) -> None:
        # An unrecognised severity must not silently sort as "low". Anything we
        # cannot interpret is treated as the worst case, because the alternative
        # is a typo in a rule quietly downgrading a critical finding.
        if self.severity not in SEVERITIES:
            self.severity = "critical"
            self.halt = True
            self.message += " [invalid severity - forced critical]"

    def to_dict(self) -> dict:
        return {
            "ruleId": self.ruleId,
            "severity": self.severity,
            "score": self.score,
            "message": self.message,
            "files": self.files,
            "evidence": self.evidence,
            "halt": self.halt,
        }


class Rule(Protocol):
    def __call__(self, env, policy, session) -> list[Finding]: ...


_REGISTRY: list[tuple[str, Rule]] = []


def register(pack: str) -> Callable[[Rule], Rule]:
    def deco(fn: Rule) -> Rule:
        _REGISTRY.append((pack, fn))
        return fn
    return deco


def evaluate_all(env, policy, session) -> list[Finding]:
    """Run every registered rule. A rule that raises is itself a critical finding.

    A rule pack that crashes must never mean "no findings" -- that would turn a
    bug into a bypass, and an attacker who can reliably crash one rule would get
    a free pass. Convert the exception into a HALT and keep going.
    """
    findings: list[Finding] = []
    for pack, rule in _REGISTRY:
        try:
            findings.extend(rule(env, policy, session) or [])
        except Exception as exc:  # noqa: BLE001 - a crashing rule must fail closed
            findings.append(Finding(
                ruleId=f"{pack}.rule_error",
                severity="critical",
                score=100,
                message=f"rule {getattr(rule, '__name__', '?')} raised {type(exc).__name__}: {exc}",
                halt=True,
            ))
    return findings


def loaded_packs() -> list[str]:
    return sorted({pack for pack, _ in _REGISTRY})


def rule_count() -> int:
    return len(_REGISTRY)


# Importing the packs is what registers them.
from . import (destructive, egress, injection, scope_escape,  # noqa: E402,F401
               secrets_exfil, self_protect)
