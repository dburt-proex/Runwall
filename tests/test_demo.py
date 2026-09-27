"""The shareable demo must show routes and verifiable decision records."""
import json
import subprocess
import sys


def test_offline_demo_exposes_both_routes_and_verified_records():
    run = subprocess.run(
        [sys.executable, "-m", "runwall.cli", "demo"],
        capture_output=True, text=True, check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert "expected HALT; got HALT" in run.stdout
    assert "expected ALLOW; got ALLOW" in run.stdout
    assert "Temporary ledger: verified (2 chained decisions" in run.stdout
    records = [json.loads(line.split("decision record: ", 1)[1])
               for line in run.stdout.splitlines() if "decision record: " in line]
    assert [record["route"] for record in records] == ["HALT", "ALLOW"]
    assert all(record["decision_id"] for record in records)
    hashes = [line.split("chain SHA-256: ", 1)[1]
              for line in run.stdout.splitlines() if "chain SHA-256: " in line]
    assert len(hashes) == 2 and all(len(value) == 64 for value in hashes)
