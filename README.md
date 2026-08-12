# Runwall

Runtime governance for agentic execution.

Runwall is designed as an out-of-process policy enforcement point for AI-agent tool calls. A mediated action is normalized, classified, evaluated against deterministic policy, routed through ALLOW / REVIEW / HALT, and recorded in a hash-chained decision ledger.

## Included in this source import

This initial import contains the governance core:

- deterministic gate and blast-radius routing
- ARMED / DEGRADED / SAFE / DISARMED perimeter states
- human approval broker with time-bounded grants
- TOTP operator authentication and split client/approval keys
- action-envelope normalization and bounded deobfuscation
- policy validation and SHA-256 policy pinning
- redaction-before-write and hash-chained ledger integrity
- session taint, denial memory, and budget controls
- adversarial red-team corpus and overclaiming audit
- privilege-separation hardening script generator
- stdlib HTTP daemon and CLI surface

## Current release boundary

This is a source import, not yet a declared production release. The uploaded set contains the core Python modules only. The following integration assets still need to be added and verified before Runwall should be described as a runnable or pilot-ready public release:

- runwall/rules.py
- policy/default.yml
- policy/manifest.json
- hook/
- console/
- automated tests and CI
- packaging metadata and installation instructions

The implementation is intentionally bounded. It does not claim universal coverage, tamper-proofing, enterprise readiness, or protection against a determined local administrator. Its claims are limited to mediated, instrumented paths and the evidence those paths produce.

## Verification performed before import

- Python syntax compilation passed for all supplied modules.
- No automated test suite was included in the supplied files, so runtime behavior and integration coverage remain an explicit next gate.

## Source layout

The implementation lives in runwall/. Module names are normalized from the uploaded source filenames by removing upload-order prefixes.
