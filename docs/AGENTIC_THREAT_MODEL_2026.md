# Runwall Agentic Runtime Threat-Model Delta — 2026

Status: TEST/REVIEW INPUT

Issue: #3

## Purpose

Extend Runwall's threat model to modern agentic execution patterns without expanding its authority claims. Runwall remains a deterministic governor for execution paths it can actually observe. A scenario that does not cross an instrumented Runwall boundary is recorded as an explicit gap, not described as prevented.

## Decision boundary

This slice is allowed to add threat documentation, deterministic fixtures, false-positive controls, and evidence requirements. It does **not** add new policy thresholds, new authority states, semantic MCP trust decisions, parent/child delegation authority, or universal-security claims.

## Threat inventory

| ID | Threat | Current observability | Current deterministic treatment | Gap / next gate |
|---|---|---|---|---|
| AT-01 | MCP server/tool identity mismatch | Partial | Existing tool call may be seen, but Runwall has no canonical MCP server/tool identity contract to compare | Add signed/normalized server + tool identity to the action envelope before enforcing identity mismatch |
| AT-02 | New remote MCP endpoint outside approved trust set | Partial | Network text may be classified as external fetch, but MCP endpoint registration/trust is not a first-class input | Requires endpoint trust-set semantics and explicit registration event coverage |
| AT-03 | Delegated subagent requests broader tool scope than parent | Not represented | No parent/child authority relation is present in the current envelope | Requires parent receipt/agent ID, delegated scope, requested scope, and monotonic-scope rule |
| AT-04 | Handoff attempts to shed taint or denial history | Partial | Planted instruction content is detectable when it crosses a governed write/tool boundary | Requires portable taint/denial lineage across handoff receipts |
| AT-05 | Poisoned memory/context contains executable or authority-bypass instructions | Partial | Injection-like content is detectable when written through governed tool paths; downstream memory consumption is not independently mediated | Preserve provenance + trust tier and carry taint into subsequent governed actions |
| AT-06 | Cross-agent message smuggles a denied action | Partial | Malicious planted content is detectable when the message is persisted through governed writes | Inter-agent transports not crossing Runwall remain uninstrumented |
| AT-07 | Cascading retry/fan-out after HALT/REVIEW | Partial | Session budgets and denial memory reduce simple verdict shopping | Cross-agent fan-out needs shared parent/task correlation to prevent distributed retries |
| AT-08 | Sandbox/interpreter child process uses an uninstrumented execution path | Observable at launch, opaque after launch | `run_interpreter` routes to REVIEW because effects inside the child are not observed | Stronger containment requires sandbox/process telemetry outside current Runwall mediation |
| AT-09 | Long-running task changes target/scope after initial approval | Not represented as a task lifecycle | Individual later tool calls are still governed, but approval-to-task scope continuity is not first-class | Requires task ID, approved scope hash, current scope hash, and transition receipts |
| AT-10 | Runtime policy/ledger integrity loss during multi-step execution | Instrumented | Existing perimeter/integrity controls fail closed rather than treating corrupted authority as valid | Add task/delegation correlation so integrity failures terminate the entire related execution tree |

## Executable fixture slice

The first executable fixtures intentionally cover only current observable behavior:

1. **Memory authority poisoning** — a governed write that asserts prior approval/bypass language must route to at least REVIEW.
2. **Cross-agent planted injection** — a governed handoff/message write containing a planted instruction marker must HALT.
3. **Opaque interpreter child execution** — launching an interpreter that can spawn unobserved child effects must route to REVIEW.
4. **False-positive controls** — ordinary memory notes and ordinary handoff notes must remain ALLOW.

The fixtures do not encode AT-01/02/03/07/09 as passing protections because the current envelope does not carry enough identity/scope/task information to make those claims honestly.

## Required GE-007 correlation fields

A future shared receipt adapter should be able to reference, without becoming authority:

- `receipt_id`
- `parent_receipt_id`
- `source_system`
- `agent_id`
- `parent_agent_id`
- `delegation_id`
- `task_id`
- `tool_call_id`
- `mcp_server_id`
- `mcp_tool_name`
- `approved_scope_hash`
- `observed_scope_hash`
- `taint_refs`
- `denial_refs`
- `policy_hash`
- `ledger_integrity_ref`
- `route`
- `verification_refs`

These are correlation/evidence fields. GE-007 must not upgrade or replace Runwall/CASA authority.

## Claims boundary

Passing these fixtures means only that the named, instrumented scenarios route as specified under the tested policy. It does not prove protection against arbitrary MCP compromise, arbitrary memory poisoning, arbitrary subagent behavior, sandbox escape, or uninstrumented execution paths.

## Next gate

After CI establishes this fixture baseline, propose the smallest semantic increment for the highest-value explicit gap. Recommended order:

1. parent/child delegation and task identity in the action envelope;
2. MCP server/tool identity + endpoint trust metadata;
3. cross-agent denial/taint lineage;
4. long-running task scope continuity.

Each enforcement-semantic increment requires a separate REVIEW decision and paired negative/false-positive fixtures.
