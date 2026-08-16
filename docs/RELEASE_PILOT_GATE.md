# Runwall Release and Pilot Gate

Status: DRAFT / REVIEW

## Purpose

Create a repeatable path from repository state to a bounded pilot candidate without changing Runwall's runtime enforcement semantics.

## Required gates

1. Exact-head CI passes on all supported Python versions.
2. Unit/adversarial suite passes.
3. `runwall claims-audit` passes.
4. Threat model and uninstrumented-path inventory are reviewed against the candidate.
5. Version, changelog/release notes, and rollback commit are recorded.
6. Pilot scope names the instrumented harness and explicitly lists uninstrumented paths.
7. No production-enforcement, universal-coverage, certification, or guaranteed-prevention claim is made.

## Pilot boundary

A pilot candidate may be used only in an operator-authorized test or non-production environment until field evidence exists.

The pilot record must include:

- candidate commit SHA;
- Runwall version;
- host/harness and hook type;
- policy hash;
- enabled rule packs;
- perimeter state;
- adversarial corpus result;
- known uninstrumented paths;
- rollback procedure;
- operator decision (`ALLOW`, `REVIEW`, or `HALT`).

## Release decision

`ALLOW` requires all required gates and an explicit operator decision. Missing test evidence, unknown runtime scope, policy drift, ledger integrity failure, or unresolved security findings route to `REVIEW` or `HALT` according to existing Runwall controls.

## Non-scope

This document does not change rule behavior, policy thresholds, authentication, maintenance mode, ledger semantics, hook behavior, or CASA routing.
