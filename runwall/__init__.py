"""Runwall -- runtime governance for agentic execution.

Diffwall guards what gets written. Runwall guards what gets done.

Runwall is a policy enforcement point for AI agent tool calls. A deterministic,
out-of-process decision is made before every instrumented action, recorded in a
hash-chained ledger, with a human able to intervene.

What that does and does not mean is stated plainly in docs/CLAIMS.md and is not
softened anywhere in this codebase:

  * An agent cannot argue, persuade, or prompt-inject its way past a Runwall
    decision. The decider runs out-of-process, is deterministic, and never
    interprets agent-authored text as instructions.

  * It can act through a path Runwall does not instrument -- code inside an
    approved interpreter, GUI automation, browser-resident network calls,
    scheduled tasks, or a harness with no hook installed. Those paths are
    enumerated in docs/UNINSTRUMENTED_PATHS.md and shipped with the product.

  * Tamper-evident, not tamper-proof. Fail-closed with respect to mediated
    paths. Enforcement strength is bounded by OS privilege separation --
    see `runwall harden`.
"""
from __future__ import annotations

import os

__version__ = "1.0.0"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_DIR = os.path.join(ROOT, "policy")
DEFAULT_POLICY = os.path.join(POLICY_DIR, "default.yml")
MANIFEST = os.path.join(POLICY_DIR, "manifest.json")
STATE_DIR = os.path.join(ROOT, ".runwall")
CONSOLE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "console")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787

# Must stay strictly below the harness's own hook timeout. A hook that hangs
# into the harness timeout is a hook that fails open -- the harness stops
# waiting and proceeds. Deny fast instead of waiting slowly.
HOOK_DEADLINE_S = 8.0
