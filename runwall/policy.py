"""Policy loading, strict validation, and hash pinning.

Two decisions here differ deliberately from DaxxerOS Local's
``governance.gate_for_action``, and both are corrections rather than
preferences:

1. **Unknown tokens refuse the load.** Daxxer coerces an unrecognised action to
   REVIEW at decision time. That is fail-closed in the narrow sense but it
   routes every typo into the human approval queue, and approval fatigue is a
   security failure -- an operator who clicks approve reflexively has stopped
   being a control. Validate the whole policy once, at load, and refuse to start
   on anything unrecognised. A misconfigured wall should not start; it should
   not quietly become a worse wall.

2. **Unknown severity is HALT, not REVIEW.** A value we cannot interpret is
   treated as the most dangerous thing it could be.

Hash pinning: the loaded policy is hashed and compared with ``policy/manifest.json``.
A mismatch drops the governor to SAFE rather than proceeding on unverified
rules. Note the honest limit -- in the default deployment the manifest is
writable by the same principal as the policy, so pinning detects accident and
casual edit, not a determined attacker who updates both. ``runwall harden``
moves the manifest under the governor's own account, which is what makes the
pin adversarially meaningful.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any

import yaml

from .envelope import canonical_path

GATES = ("ALLOW", "REVIEW", "HALT")

_REQUIRED = ("thresholds", "gate_matrix", "protected_paths", "halt_patterns",
             "tool_classes", "egress", "budgets", "approval", "taint")

_ALLOWED_TOP = set(_REQUIRED) | {"version", "self_protect", "harness_config_paths"}


class PolicyError(Exception):
    """Policy is malformed. The governor must not start."""


@dataclass
class Policy:
    raw: dict[str, Any]
    path: str
    sha256: str
    pinned: bool = False
    pin_message: str = ""

    thresholds: dict[str, int] = field(default_factory=dict)
    gate_matrix: dict[str, str] = field(default_factory=dict)
    protected_paths: list[str] = field(default_factory=list)
    halt_patterns: list[str] = field(default_factory=list)
    tool_classes: dict[str, list[str]] = field(default_factory=dict)
    egress: dict[str, list[str]] = field(default_factory=dict)
    budgets: dict[str, int] = field(default_factory=dict)
    approval: dict[str, int] = field(default_factory=dict)
    taint: dict[str, Any] = field(default_factory=dict)
    harness_config_paths: list[str] = field(default_factory=list)
    runwall_root: str = ""

    # -- lookups -----------------------------------------------------------

    def gate_for_action(self, action: str) -> str:
        """Gate for a derived action label. Unknown labels are a bug, not input.

        Labels come from ``classify.py``, never from the agent, and the loader
        has already checked every label the classifier can emit against this
        matrix. Reaching the fallback means the two drifted -- fail to HALT and
        make the drift visible rather than guessing.
        """
        return self.gate_matrix.get(action, "HALT")

    def is_protected(self, path: str) -> bool:
        p = os.path.normcase(path)
        return any(fnmatch.fnmatch(p, os.path.normcase(pat)) for pat in self.protected_paths)

    def tool_class(self, tool: str) -> str:
        for cls, tools in self.tool_classes.items():
            if tool in tools:
                return cls
        return "unknown"

    def self_protected_paths(self) -> list[str]:
        """Every path whose modification would weaken the wall.

        Deliberately the enforcement surface only -- not the whole repository.
        Protecting the bare root would make editing Runwall's own README or
        tests a HALT, which is both wrong and corrosive: a rule that fires on
        obviously-safe work is the rule an operator learns to click past, and
        then keeps clicking past when it fires for real.
        """
        return self.source_paths() + self.sealed_paths()

    def source_paths(self) -> list[str]:
        """Runwall's own code and policy.

        Refused normally, but reachable during an authenticated maintenance
        window. A security tool that can only be patched by removing it will
        eventually be left removed -- which is a worse outcome than the bug the
        refusal was preventing.
        """
        root = self.runwall_root
        return [canonical_path(p) for p in (
            os.path.join(root, "policy"),
            os.path.join(root, "runwall"),
            os.path.join(root, "hook"),
        ) if p]

    def sealed_paths(self) -> list[str]:
        """Key material, the ledger, and the chain anchor.

        Never reachable, by any state of the perimeter. Maintenance exists to
        let the operator change how the wall DECIDES; it does not let anyone
        rewrite what the wall RECORDED, or read the keys that authenticate the
        operator. A maintenance mode that reached these would be an off switch
        wearing a lab coat.
        """
        return [canonical_path(p) for p in (
            self.state_dir(),
            self.ledger_path(),
            self.anchor_path(),
        ) if p]

    def secret_paths(self) -> list[str]:
        sd = self.state_dir()
        return [os.path.join(sd, "client.token"),
                os.path.join(sd, "approval.key"),
                os.path.join(sd, "operator.json")]

    # -- locations ---------------------------------------------------------

    def state_dir(self) -> str:
        return os.path.join(self.runwall_root, ".runwall")

    def ledger_path(self) -> str:
        """Prefer DaxxerOS Local's audit directory; fall back to local state.

        ``94_AUDIT_LOGS/gate_decisions.jsonl`` already exists in DaxxerOS and has
        never been written to -- the schema anticipated exactly this record. Use
        it when present so the governance evidence lives in one place.
        """
        daxxer = os.environ.get("DAXXER_HOME") or r"C:\Users\15075\Daxxer\DaxxerOS_Local"
        audit = os.path.join(daxxer, "94_AUDIT_LOGS")
        if os.path.isdir(audit):
            return os.path.join(audit, "gate_decisions.jsonl")
        return os.path.join(self.state_dir(), "gate_decisions.jsonl")

    def anchor_path(self) -> str:
        return os.path.join(self.state_dir(), "chain.anchor")


def _fail(msg: str) -> None:
    raise PolicyError(msg)


def _validate(doc: dict, known_actions: set[str]) -> None:
    if not isinstance(doc, dict):
        _fail("policy root must be a mapping")

    unknown = set(doc) - _ALLOWED_TOP
    if unknown:
        _fail(f"unknown top-level policy keys: {sorted(unknown)}")
    missing = [k for k in _REQUIRED if k not in doc]
    if missing:
        _fail(f"policy missing required sections: {missing}")

    th = doc["thresholds"]
    if not isinstance(th, dict) or set(th) != {"review", "halt"}:
        _fail("thresholds must define exactly: review, halt")
    if not all(isinstance(v, int) for v in th.values()):
        _fail("thresholds must be integers")
    if not 0 < th["review"] < th["halt"] <= 100:
        _fail(f"thresholds must satisfy 0 < review < halt <= 100 (got {th})")

    gm = doc["gate_matrix"]
    if not isinstance(gm, dict) or not gm:
        _fail("gate_matrix must be a non-empty mapping")
    for action, gate in gm.items():
        if gate not in GATES:
            _fail(f"gate_matrix['{action}'] = '{gate}' is not one of {GATES}")

    # The classifier and the matrix must agree completely, in both directions.
    # A label the classifier can emit but the matrix does not cover would hit the
    # HALT fallback in production; a matrix entry no classifier emits is dead
    # policy that reads as coverage.
    undefined = known_actions - set(gm)
    if undefined:
        _fail(f"classifier emits actions with no gate_matrix entry: {sorted(undefined)}")
    orphaned = set(gm) - known_actions
    if orphaned:
        _fail(f"gate_matrix defines actions no classifier emits: {sorted(orphaned)}")

    for key in ("protected_paths", "halt_patterns"):
        if not isinstance(doc[key], list):
            _fail(f"{key} must be a list")

    tc = doc["tool_classes"]
    if not isinstance(tc, dict) or not {"read", "write", "exec", "network"} <= set(tc):
        _fail("tool_classes must define at least: read, write, exec, network")

    eg = doc["egress"]
    if not isinstance(eg, dict) or "allow_domains" not in eg:
        _fail("egress must define allow_domains")

    # Keys ending in _route carry a gate value; _floor likewise. Everything else
    # in these sections is a non-negative count, duration or flag. Validating by
    # suffix keeps the schema extensible without loosening the type check.
    for key in ("budgets", "approval"):
        if not isinstance(doc[key], dict):
            _fail(f"{key} must be a mapping")
        for k, v in doc[key].items():
            if k.endswith(("_route", "_floor")):
                if v not in GATES:
                    _fail(f"{key}['{k}'] = '{v}' is not one of {GATES}")
            elif isinstance(v, bool):
                continue
            elif not isinstance(v, int) or v < 0:
                _fail(f"{key}['{k}'] must be a non-negative integer (got {v!r})")

    if not isinstance(doc["taint"], dict):
        _fail("taint must be a mapping")
    for k, v in doc["taint"].items():
        if k.endswith("_floor") and v not in GATES:
            _fail(f"taint['{k}'] = '{v}' is not one of {GATES}")


def compute_sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def load(policy_path: str, runwall_root: str, known_actions: set[str],
         manifest_path: str | None = None) -> Policy:
    """Load, validate, and pin. Raises PolicyError rather than degrading."""
    if not os.path.exists(policy_path):
        _fail(f"policy file not found: {policy_path}")

    with open(policy_path, encoding="utf-8") as f:
        try:
            doc = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            _fail(f"policy is not valid YAML: {exc}")

    _validate(doc, known_actions)
    digest = compute_sha256(policy_path)

    pinned, pin_msg = False, "no manifest present - policy is unpinned"
    manifest_path = manifest_path or os.path.join(os.path.dirname(policy_path), "manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)
            expected = manifest.get("policy_sha256")
            if expected == digest:
                pinned, pin_msg = True, "policy matches pinned hash"
            else:
                pinned = False
                pin_msg = (f"POLICY HASH MISMATCH - expected {expected}, got {digest}. "
                           f"The policy has changed since it was pinned.")
        except (json.JSONDecodeError, OSError) as exc:
            pin_msg = f"manifest unreadable: {exc}"

    p = Policy(
        raw=doc,
        path=policy_path,
        sha256=digest,
        pinned=pinned,
        pin_message=pin_msg,
        thresholds=doc["thresholds"],
        gate_matrix=doc["gate_matrix"],
        protected_paths=doc["protected_paths"],
        halt_patterns=doc["halt_patterns"],
        tool_classes=doc["tool_classes"],
        egress=doc["egress"],
        budgets=doc["budgets"],
        approval=doc["approval"],
        taint=doc["taint"],
        harness_config_paths=doc.get("harness_config_paths", []),
        runwall_root=runwall_root,
    )
    return p


def write_manifest(policy_path: str, manifest_path: str) -> str:
    """Pin the current policy. Returns the recorded digest."""
    digest = compute_sha256(policy_path)
    os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump({"policy_sha256": digest, "policy_file": os.path.basename(policy_path)},
                  f, indent=2)
    return digest
