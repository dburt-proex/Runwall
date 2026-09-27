# Runwall Public Readiness Evidence Receipt v0.2

**Gate:** REVIEW — technically validated review candidate; no production or customer-pilot authorization is implied.

## Identity

- Repository: `dburt-proex/Runwall`
- Reviewed PR head: `e95901d3e0d9542fc3c64e97a9e6e00140c5115e`
- Merged `main` technical baseline: `d93f62f946ffed828e9889ad2075454b7d889e21`
- Pull request: [#9](https://github.com/dburt-proex/Runwall/pull/9) — Public-readiness hardening and evidence refresh (merged 2026-09-22)
- PR-head GitHub Actions run: [#22](https://github.com/dburt-proex/Runwall/actions/runs/35605566883)
- Merged-main GitHub Actions run: [#23](https://github.com/dburt-proex/Runwall/actions/runs/35775379286)
- Scope: close post-merge command-shape findings, strengthen regression evidence, add red-team CI, and make the public README evidence-first.

## Trigger

PR #8 merged a runtime-integrity hardening increment and then received five unresolved automated review findings:

1. path-qualified interpreter pipeline sinks could bypass interpreter opacity pricing;
2. `xargs` parsing could mistake an argument named `python` for the executed command;
3. `Format-Volume` matching could incorrectly borrow `-Force` from a later pipeline stage;
4. secret-discovery language could co-occur with an unrelated outbound request and appear to be exfiltration;
5. dynamic-destination detection could mistake an output-path variable for a network destination.

These findings were treated as public-readiness blockers rather than hidden behind documentation polish.

## Implemented controls

- Interpreter command-position matching now recognizes path-qualified executables and Windows `.exe` forms.
- `xargs` parsing is bounded to the actual command position.
- `Format-Volume` force matching stops at pipeline boundaries.
- Secret-discovery/exfiltration detection requires stronger same-statement dataflow.
- Coarse blast-radius evidence distinguishes ambiguous sensitive-network combinations (REVIEW) from explicit credential exfiltration (HALT).
- Dynamic-destination detection binds variables to destination/URI positions in the same statement.
- Five permanent regression cases were added.
- The offline adversarial corpus now runs in CI on every supported Python version.
- Red-team output now describes control cases as exact-route validations instead of implying every ordinary action must ALLOW.

## Verification

| Check | Result |
|---|---|
| Python 3.11 CI | Passed |
| Python 3.12 CI | Passed |
| Python 3.13 CI | Passed |
| Unit/regression suite | **115 passed, 1 optional integration skip** |
| Offline adversarial corpus | **88/88 passed** |
| Attack cases | **63 refused at or above the required route** |
| Control cases | **25 routed exactly as expected** |
| Claims audit | Passed |
| README public-claim boundary | Passed through the same CI claims audit |

The optional skip is the existing DaxxerOS parity integration check when its external sibling source is unavailable; it is not a skipped Runwall security regression.

## Public presentation changes

The README now:

- states the current `REVIEW` / bounded-pilot posture above the fold;
- gives an evidence-at-a-glance table before deep architecture;
- uses current validated counts instead of stale test/red-team numbers;
- links to the public CASA and Diffwall repositories instead of a local workstation path;
- uses ALLOW / REVIEW / HALT terminology consistently;
- links directly to claims, threat-model, uninstrumented-path, and release-gate evidence.

## Residual risk and non-claims

This receipt does **not** establish:

- production containment;
- universal mediation of arbitrary host execution;
- customer or field validation;
- certification or attestation;
- content-level exfiltration prevention through allowlisted channels;
- visibility into GUI/browser-resident execution or arbitrary child-interpreter effects.

Those boundaries remain documented in `docs/THREAT_MODEL.md`,
`docs/UNINSTRUMENTED_PATHS.md`, `docs/CLAIMS.md`, and
`docs/RELEASE_PILOT_GATE.md`.

## Repository presentation

At the PR #9 merged baseline, these were presentation choices rather than failed technical acceptance criteria:

- The repository description and topics were unset. Leave the homepage blank until a distinct project page is verified.
- The owner has chosen public inspection without a reuse license for now. No `LICENSE` file is present; the README states the source and reuse boundary. This is not an open-source grant.
- `pyproject.toml` and `runwall/__init__.py` both report package version `1.0.0`. The README distinguishes that code identifier from the operational `REVIEW` gate. Changing version semantics or either value requires a separate coordinated decision.

## Next gate

PR #9 was merged on 2026-09-22. This receipt records the technical baseline at `d93f62f946ffed828e9889ad2075454b7d889e21`; public metadata updates and documentation corrections require their own passing CI before they are cited as the current repository state.
