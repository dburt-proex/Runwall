# Runwall Runtime Integrity Closure v0.1 — Pilot Evidence Receipt

**Gate:** REVIEW — local, offline verification only; not a production or pilot authorization.

## Identity

- Repository: `dburt-proex/Runwall`
- Baseline inspected: `main@079675ab9dc8d5ea522af38a4cda38cd757bc4b0`
- Scope: command-shape hardening only; no MCP, delegation, policy-threshold, approval, hook, or ledger-semantic change.
- Evaluation environment: Python 3.12.13; Python 3.11 and 3.13 were unavailable in this workspace.

## Pre-patch exploit evidence

The eight fixtures in `tests/test_command_shape_gaps.py` were asserted against
the baseline before enforcement changed. All failed the required route:

| Domain | Shape | Baseline route | Required route |
| --- | --- | --- | --- |
| Storage | PowerShell discovery → `Format-Volume -Force` | REVIEW | HALT |
| SQL | `Get-Content cleanup.sql | psql` | ALLOW | HALT |
| Git | ref discovery → `xargs git update-ref -d` | ALLOW | HALT |
| Permissions | `icacls` Everyone SID full-control grant | ALLOW | REVIEW |
| Secrets | `dir/findstr env` discovery → `curl @%i` | ALLOW | HALT |
| Egress | file-fed PowerShell web destination | ALLOW | HALT |
| Interpreter | `find ... | xargs sh` | ALLOW | REVIEW |
| Interpreter | `Get-Content deploy.ps1 | powershell -` | ALLOW | REVIEW |

## Implemented control changes

- One shared interpreter vocabulary now drives both classification and blast-radius opacity pricing.
- Added bounded detection for PowerShell `Format-Volume`, opaque SQL-client pipelines, Git ref deletion, and the Windows Everyone SID.
- Added credential-discovery-to-send and dynamic-destination egress refusals.
- Added eight permanent unit fixtures and the same eight red-team corpus fixtures.

## Post-patch verification

| Check | Result |
| --- | --- |
| Exact command-shape regression fixtures | 8/8 passed |
| Full unit suite | 110 passed, 1 skipped (optional DaxxerOS parity check) |
| Offline red-team corpus | 83/83 passed: 62 attacks refused, 21 controls unobstructed |
| Ledger integrity coverage | Passed within full unit suite |
| Claims audit | Clean |
| Diff whitespace check | Clean |

## Residual risk

- Runwall governs mediated tool calls, not arbitrary host execution or effects inside child interpreters.
- The pipeline rules are bounded lexical controls. Novel wrappers, encoded payloads beyond normalizer limits, GUI/browser execution, and uninstrumented egress remain outside this increment's guarantee.
- Python 3.11 and 3.13 CI was not executable in this workspace; the required three-version CI run remains a merge-gate dependency.
- No live governor, customer environment, production deployment, or pilot evidence was exercised.

## Next gate

Run CI on Python 3.11, 3.12, and 3.13 from the review branch; independently review the frozen diff; retain `REVIEW` until an explicit operator pilot decision and field evidence exist.
