# Runwall Public Readiness Evidence Receipt v0.2

**Gate:** REVIEW — technically validated review candidate; no production or customer-pilot authorization is implied.

## Identity

- Repository: `dburt-proex/Runwall`
- Review branch: `runwall/public-readiness-hardening-v0.2`
- Validated candidate head: `d7d6ba12451b57a181b180663296078e0b133c08`
- Pull request: #9 — Public-readiness hardening and evidence refresh
- GitHub Actions run: #20 (`35605439521`)
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

## Remaining owner decisions

These are public-repository presentation decisions, not failed technical acceptance criteria:

- GitHub repository description/topics/homepage are still unset.
- No `LICENSE` file is present; decide deliberately whether Runwall is source-available, open source, or all-rights-reserved before inviting reuse.
- `pyproject.toml` currently reports version `1.0.0` while the operational release posture remains `REVIEW`; decide whether semantic versioning should represent package evolution or operational maturity.

## Next gate

Human review of PR #9. Merge only if the owner accepts the runtime semantics, public positioning, and evidence boundary above.
