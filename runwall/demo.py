"""A two-case, non-executing introduction to the Runwall decision path."""
from __future__ import annotations

import json
import os
import tempfile

from . import DEFAULT_POLICY, MANIFEST, ROOT, classify, policy as policy_mod
from .envelope import ActionEnvelope
from .gate import decide
from .ledger import Ledger
from .redteam import ATTACKS, CONTROLS
from .session import SessionStore
from .state import Perimeter


def run_demo() -> int:
    """Evaluate one attack and one control; execute neither tool payload."""
    attack = next(case for case in ATTACKS if case[0] == "destroy-rmrf")
    control = next(case for case in CONTROLS if case[0] == "ok-git-status")
    policy = policy_mod.load(DEFAULT_POLICY, ROOT, classify.known_actions(), MANIFEST)

    print("Runwall offline demo — policy evaluation; tool commands are never executed")
    with tempfile.TemporaryDirectory(prefix="runwall_demo_") as state_dir:
        perimeter = Perimeter(state_dir)
        sessions = SessionStore()
        ledger = Ledger(os.path.join(state_dir, "decisions.jsonl"), state_dir)
        workdir = os.path.join(state_dir, "neutral_workdir")
        os.mkdir(workdir)
        passed = True

        cases = (
            ("attack", attack[0], attack[2], attack[3], attack[4]),
            ("ordinary", control[0], control[1], control[2], control[3]),
        )
        for seq, (label, cid, tool, params, expected) in enumerate(cases, start=1):
            env = ActionEnvelope.from_hook_payload(
                {"tool_name": tool, "tool_input": params,
                 "session_id": f"demo_{cid}", "cwd": workdir},
                envelope_id=f"demo_{seq}", seq=seq, ts="demo", agent_id="demo")
            decision = decide(env, policy, sessions.get(f"demo_{cid}"),
                              perimeter, operator_present=False)
            event = ledger.append(decision.to_dict())
            passed &= decision.route == expected
            print(f"{label}: {params['command']}")
            print(f"  expected {expected}; got {decision.route}")
            print("  decision record: " + json.dumps({
                "decision_id": event["decision_id"],
                "route": event["route"],
                "action": event["action"],
            }, sort_keys=True))
            print(f"  chain SHA-256: {event['hash']}")

        ok, checked, problems = ledger.verify()
        passed &= ok and checked == 2
        print(f"Temporary ledger: {'verified' if ok else 'FAILED'} "
              f"({checked} chained decisions; deleted when demo ends)")
        if not ok:
            print("  " + "; ".join(problems))

    print("Demo PASS" if passed else "Demo FAIL")
    return 0 if passed else 1
