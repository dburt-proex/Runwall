"""`runwall claims-audit` -- a build gate against overclaiming.

Runwall is sold into governance and compliance contexts, where an overclaim is
a misrepresentation exposure rather than mere enthusiasm. The precision is also
what makes the genuine claim ("cannot be reasoned past") worth believing, so
protecting it is protecting the product.

Documentation drifts. Somebody writes "unbreakable" in a launch post at 11pm and
nobody notices for six months. This makes that a build failure instead.

Run it before shipping anything public. Exits non-zero on a hit.
"""
from __future__ import annotations

import os
import re

from . import ROOT

# (pattern, why it is banned, what to say instead)
BANNED = [
    (r"\bcannot be broken\b", "false - see docs/UNINSTRUMENTED_PATHS.md",
     "cannot be reasoned past"),
    (r"\bunbypassab\w+", "false at the execution layer",
     "mediates instrumented chokepoints"),
    (r"\bun(hack|break)able\b", "meaningless", "state the actual control"),
    (r"\btamper[\s-]?proof\b", "the chain is detective, not preventive",
     "tamper-evident"),
    (r"\bprevents? prompt injection\b", "nothing prevents injection",
     "raises the gate floor on content-derived actions"),
    (r"\bevery agent action\b", "only instrumented ones",
     "every mediated tool call"),
    (r"\bensures? compliance\b", "no tool ensures compliance",
     "produces an auditable record of policy decisions"),
    (r"\bguarantees? (safety|security|compliance)\b", "no such guarantee exists",
     "describe the control and its bounds"),
    (r"\bmilitary[\s-]grade\b", "meaningless", "-"),
    (r"\bzero[\s-]trust\b", "marketing noise with a specific meaning this is not",
     "describe the actual control"),
    (r"\bai[\s-]powered security\b", "the opposite of the design",
     "deterministic policy engine"),
    (r"\b100% (secure|safe|coverage)\b", "false", "state measured coverage"),
    (r"\bimpossible to (bypass|evade|defeat)\b", "false",
     "raises the cost of bypass to a deliberate, logged campaign"),
]
_COMPILED = [(re.compile(p, re.IGNORECASE), why, alt) for p, why, alt in BANNED]

SCAN_EXT = {".md", ".html", ".js", ".py", ".yml", ".yaml", ".txt", ".json"}
SKIP_DIRS = {".git", "__pycache__", ".runwall", "node_modules", ".pytest_cache"}
# This file and CLAIMS.md necessarily quote the banned strings in order to ban them.
SKIP_FILES = {"claims.py", "CLAIMS.md"}

# "Tamper-evident, not tamper-proof" is the sentence we most want people to
# write, and a naive grep flags it. A linter that fires on correct usage is a
# linter somebody disables -- the same rubber-stamp dynamic the rest of this
# system is built to avoid. So: a banned term is permitted when it is negated,
# or when scare quotes mark it as a term being discussed rather than asserted.
_NEGATION = re.compile(
    r"(?:\bnot\b|\bnever\b|n't\b|\brather than\b|\bnot merely\b|\bfar from\b|"
    r"\bcannot claim\b|\bdo not (?:say|write|use|claim)\b|\bavoid\b|\bbanned\b|"
    r"\bno such\b|\bdoes not\b)[^.]{0,40}$", re.IGNORECASE)


def _exempt(line: str, match: re.Match) -> bool:
    before = line[:match.start()]
    if _NEGATION.search(before):
        return True
    # Scare quotes: "unbreakable" / 'unbreakable' / `unbreakable`
    lead, trail = line[max(0, match.start() - 1):match.start()], line[match.end():match.end() + 1]
    if lead in "\"'`" and trail in "\"'`":
        return True
    return False


def audit(root: str = ROOT) -> list[tuple[str, int, str, str, str]]:
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() not in SCAN_EXT or name in SKIP_FILES:
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for lineno, line in enumerate(f, 1):
                        for pat, why, alt in _COMPILED:
                            for m in pat.finditer(line):
                                if _exempt(line, m):
                                    continue
                                hits.append((os.path.relpath(path, root), lineno,
                                             m.group(0), why, alt))
            except OSError:
                continue
    return hits


def run_audit(args) -> int:
    from .term import init, rule
    C, G = init()

    hits = audit()
    print(f"\n{C['bold']}Runwall claims audit{C['reset']}")
    print(f"{C['dim']}{rule(G, 74)}{C['reset']}")
    if not hits:
        print(f"{C['green']}{G['ok']} clean{C['reset']} - no banned claim language found")
        print(f"{C['dim']}{len(BANNED)} patterns checked across .md/.html/.js/.py/.yml"
              f"{C['reset']}\n")
        return 0

    for path, lineno, text, why, alt in hits:
        print(f"{C['red']}{G['bad']} {path}:{lineno}{C['reset']}  \"{text}\"")
        print(f"    {C['dim']}{why}{G['arrow'] if False else ''}{C['reset']}")
        print(f"    {C['dim']}use instead: {alt}{C['reset']}")
    print(f"\n{C['red']}{C['bold']}{len(hits)} overclaim(s){C['reset']} - "
          f"see docs/CLAIMS.md\n")
    return 1
