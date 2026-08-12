# What Runwall does and does not guarantee

This file is normative. Marketing copy, README text, console strings, and any
client-facing material must be consistent with it. `runwall claims-audit` greps
the repository for the banned phrasings below and exits non-zero on a hit.

The reason for the discipline is commercial as much as technical: Runwall is
sold into governance and compliance contexts. In that market, an overclaim is
not enthusiasm — it is a misrepresentation exposure, and the first competent
reviewer who finds one discounts everything else in the system. Precision here
is what makes the rest of the claims worth believing.

---

## The claim worth making

> An agent cannot argue, persuade, or prompt-inject its way past a Runwall
> decision. The decider runs out-of-process, is deterministic, and never
> interprets agent-authored text as instructions.

This is true, it is unusual, and it is the product.

The mechanism: enforcement runs in a separate process the model does not
control, invoked by the harness rather than by the agent. Decisions come from
regular expressions, canonicalized path comparison, set membership, and
arithmetic. No rule consults a language model. A regex cannot be talked out of
matching, cannot be flattered, and does not have a context window to poison.

Note carefully what the claim is scoped to: **unbypassable by reasoning is not
unbypassable by execution.** That distinction is the whole product, and it
should be stated in one sentence rather than hedged into mush.

---

## Banned phrasings

Do not write, say, or ship any of these:

| Banned | Why | Use instead |
|---|---|---|
| "cannot be broken" | False. See `UNINSTRUMENTED_PATHS.md`. | "cannot be reasoned past" |
| "unbypassable" | False at the execution layer. | "mediates instrumented chokepoints" |
| "tamper-proof" | The chain is detective, not preventive. | "tamper-evident" |
| "prevents prompt injection" | Nothing prevents injection. Taint tracking *contains* it. | "raises the gate floor on content-derived actions" |
| "every agent action" | Only instrumented ones. | "every mediated tool call" |
| "ensures compliance with X" | No tool ensures compliance. | "produces an auditable record of policy decisions" |
| "zero trust" | Marketing noise with a specific architectural meaning this is not. | describe the actual control |
| "military-grade" / "unhackable" | Meaningless. | — |
| "AI-powered security" | The opposite of the design. Determinism is the feature. | "deterministic policy engine" |

---

## Defensible phrasings

**Coverage**
> Runwall mediates agent actions at instrumented chokepoints. Actions taken
> through uninstrumented paths — code executed by an approved interpreter, GUI
> automation, browser-resident network calls, scheduled tasks, and harnesses
> without an installed hook — are not mediated. That list is published in
> `docs/UNINSTRUMENTED_PATHS.md`.

**Ledger**
> Tamper-evident, not tamper-proof. Modification is detectable by chain
> verification against an anchored head; it is not prevented. Detection is only
> adversarially meaningful once `runwall harden` has moved the anchor under a
> principal the agent cannot write.

**Enforcement strength**
> Enforcement strength is bounded by OS privilege separation. Where the agent
> runs with administrative privileges on the same machine as the governor,
> Runwall provides deterrence, friction, and evidence — not containment.
> Containment requires the agent to run under a separate, lower-privileged
> principal or in an isolated VM.

**Failure behaviour**
> Fail-closed with respect to mediated paths. When the governor is unreachable,
> the hook evaluates a reduced rule set from a cached policy: destructive,
> credential, egress, and self-protection classes are refused; read-class
> actions proceed and are spooled with an explicit gap marker.

**Two-factor authentication**
> Step-up authentication binds a named operator to each privileged decision. It
> is an attribution control, not an access-prevention control — it does not stop
> a process already running as that operator.

**Compliance**
> Produces a tamper-evident, queryable record of policy decisions suitable as
> evidence in an audit. Never: "makes you compliant with the EU AI Act."

**Blast radius**
> A pre-execution *estimate* carrying its own confidence and basis. Low-confidence
> high-blast estimates route to a human rather than being acted on.

---

## The VPN metaphor

Permitted as a **control-surface metaphor**: arm/disarm, kill switch, tunnel
view. It communicates the operator experience accurately and it is good UX.

Not permitted in technical or commercial claims. A VPN operates at the network
layer and carries an implication of transport-level totality that Runwall does
not have. Runwall is a policy enforcement point for tool calls. Anywhere the
distinction could mislead a buyer, say the latter.

---

## Review checklist before shipping anything public

1. Run `runwall claims-audit`.
2. Does any sentence imply totality of coverage? Rewrite.
3. Does any sentence imply prevention where the control is detection? Rewrite.
4. Is a compliance framework named as an outcome rather than as a mapping? Rewrite.
5. Would the uninstrumented-paths list embarrass the claim if a reviewer read it
   immediately afterward? If so, the claim is wrong, not the list.
