# Runwall Compliance Readiness Baseline

Status: REVIEW  
Assessment date: 2026-08-16  
Canonical control registry: `dburt-proex/casa/governance/CONTROL-REGISTRY.yaml` v0.1

## Claim boundary

This repository does **not** claim ISO/IEC 27001 certification, ISO/IEC 42001 certification, SOC 2 attestation, or full regulatory compliance. Framework references are readiness/control-family mappings only until exact current requirements are licensed/mapped and independent assurance is completed.

## Scope

Runwall is assessed as the runtime enforcement surface for agent tool calls: deterministic classification, authorization, approvals, fail-closed behavior, integrity checks, self-protection, decision logging, hardening, and adversarial testing.

## Evidence-backed strengths

- Deterministic runtime decision path with explicit gate outcomes.
- Human approval and operator authentication mechanisms.
- Hash-chained ledger plus integrity verification.
- Threat models, adversarial corpus, self-protection and hardening mechanisms.
- Explicit claim-limitation discipline and documented uninstrumented paths.
- DEGRADED and SAFE behavior for control-plane failures.

## Gap register

| Priority | Control | Gap | Closure evidence |
|---|---|---|---|
| P0 | RSK-001 | No formal risk register/treatment/residual-risk acceptance | risk register + treatment decisions + acceptance receipt |
| P0 | INC-001 | No complete incident-response lifecycle | IR SOP + tabletop + RCA + corrective-action/retest record |
| P0 | DAT-001 | No canonical data inventory/classification/retention/deletion policy | approved inventory/policy + deletion/exception evidence |
| P0 | SUP-001 | No supplier/model-provider risk process | supplier inventory + assessment + approved-use review |
| P0 | BCM-001 | No documented backup/restore/RTO/RPO test | backup policy + successful restore test + recovery receipt |
| P1 | CHG-001 | Change evidence not bound to canonical compliance receipts | control/test/evidence receipt from CI/PR |
| P1 | AI-001 | Runtime governance is not a complete AI lifecycle record | AI inventory + intended use + TEVV + monitoring + retirement record |
| P1 | REV-001 | No recurring management review/internal-audit cadence | internal audit + management review + corrective-action status |

## Validation workflow

1. Confirm every `COMPLIANCE.yaml` evidence path exists at the assessed commit.
2. Execute repository CI, unit tests, `runwall redteam --offline`, `runwall verify`, and `runwall claims-audit` in an authorized execution environment.
3. Record actual outputs as evidence receipts using the CASA `EVIDENCE-SCHEMA.json` contract.
4. Resolve failed controls as findings; do not relabel them `VERIFIED` without successful evidence.
5. Review P0 remediation and formally accept any residual risk.
6. Run internal readiness review before selecting an independent assessor.

## Phase 10 entry criteria

External assurance remains blocked until P0 findings are closed or formally risk-treated, exact applicable framework requirements are mapped, evidence is retained for the required period, and operator/management review is recorded.
