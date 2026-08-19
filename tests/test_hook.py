"""Unit tests for hook/runwall_hook.py's DEGRADED-mode fallback.

This file has no coverage anywhere else in the suite -- deliberately, per its
own docstring, it does not import the `runwall` package at all, so it cannot
be exercised by importing through `runwall.*`. It is loaded here by file path
instead. That gap in coverage is itself notable: this is the code that is
supposed to keep refusing the unacceptable when everything else -- the
governor, the package, the policy -- is down or broken, and until this file
existed it had never been executed by the test suite even once.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

_HOOK_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hook", "runwall_hook.py")


@pytest.fixture
def hook():
    spec = importlib.util.spec_from_file_location("runwall_hook", _HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _decide(hook, payload):
    """Run fallback() and capture the (decision, reason) it would emit,
    without actually exiting the process the way respond() does."""
    seen = []

    def fake_respond(decision, reason):
        seen.append((decision, reason))
        raise SystemExit(0)

    hook.respond = fake_respond
    try:
        hook.fallback(payload, "test: governor unreachable")
    except SystemExit:
        pass
    assert seen, "fallback() must always call respond() exactly once"
    return seen[-1]


def test_unrecognized_key_alone_is_still_refused(hook):
    """Baseline: a dangerous string under a key FALLBACK_DENY has never heard
    of must still be scanned and refused -- this is what the fallback's own
    docstring promises ("refuse the classes that are never acceptable")."""
    decision, reason = _decide(hook, {
        "tool_name": "SomeMcpTool", "tool_input": {"script": "rm -rf /data"}})
    assert decision == "deny"
    assert "recursive forced delete" in reason


def test_unrecognized_key_is_not_exempted_by_a_recognized_one(hook):
    """Regression: an earlier version scanned "recognized action keys, and
    only if none of those were present, everything else." A single populated
    action-shaped field (even an empty-ish `cwd: "."`) silently exempted every
    OTHER, unlisted parameter from the scan -- so the identical dangerous
    payload above, sitting next to an ordinary `cwd`, sailed through as a mere
    confirmation prompt instead of an unconditional refusal."""
    decision, reason = _decide(hook, {
        "tool_name": "SomeMcpTool",
        "tool_input": {"cwd": ".", "script": "rm -rf /data"}})
    assert decision == "deny"
    assert "recursive forced delete" in reason


@pytest.mark.parametrize("tool,params", [
    ("Write", {"file_path": "src/util.py", "content": "def f():\n    return 1\n"}),
    ("Write", {"file_path": "docs/THREAT_MODEL.md",
               "content": "Evict client.token and approval.key or it is cosmetic."}),
    ("NotebookEdit", {"notebook_path": "analysis.ipynb", "cell_id": "c1",
                       "cell_type": "code", "edit_mode": "replace",
                       "new_source": "import subprocess\nsubprocess.run(['rm', '-rf', '/tmp/x'])"}),
])
def test_content_is_still_data_not_action_in_degraded_mode(hook, tool, params):
    """The content/action split that makes security documentation writable
    while ARMED must hold in DEGRADED mode too: file/cell CONTENTS never drive
    a `deny`, only the command or the target path does. Removing the
    ACTION_KEYS short-circuit must not turn this into a content scanner."""
    decision, _ = _decide(hook, {"tool_name": tool, "tool_input": params})
    assert decision != "deny"


def test_read_tools_still_pass_through_in_degraded_mode(hook):
    decision, _ = _decide(hook, {"tool_name": "Read", "tool_input": {"file_path": "src/util.py"}})
    assert decision == "allow"


def test_ordinary_bash_asks_rather_than_denies_in_degraded_mode(hook):
    decision, _ = _decide(hook, {"tool_name": "Bash", "tool_input": {"command": "ls -la"}})
    assert decision == "ask"
