# Runwall

**Runtime governance for agentic execution.**

> Diffwall guards what gets written. Runwall guards what gets done.

Runwall is a policy enforcement point for AI agent tool calls. Before an agent
does anything through an instrumented path, a deterministic decision is made
out-of-process, recorded in a hash-chained ledger, and — when it matters — put
in front of a human.

It is the runtime that makes [CASA](../../OneDrive/Documents/GitHub/Claude-Cowork/00_DREW_AI_OPERATING_HQ/02_ACTIVE_SYSTEMS/CASA.md)
enforceable rather than documented.

---

## The claim

**An agent cannot argue, persuade, or prompt-inject its way past a Runwall
decision.** The decider runs in a separate process the model does not control.
Every rule is a regular expression, a canonicalized path comparison, a set
membership test, or arithmetic. No rule consults a language model. A regex
cannot be talked out of matching, cannot be flattered, and has no context window
to poison.

**It can still act through a path Runwall does not instrument.** Code inside an
approved interpreter, GUI automation, browser-resident `fetch`, scheduled tasks,
a harness with no hook. Those are enumerated in
[docs/UNINSTRUMENTED_PATHS.md](docs/UNINSTRUMENTED_PATHS.md) and shipped with
the product, because a wall with named doors is defensible and a wall claimed to
be seamless is a liability.

There is a real difference between a control an agent cannot *reason* past and
one it cannot *route around*. Runwall is firmly the first, and honest about not
being the second. That distinction is the product.
[docs/CLAIMS.md](docs/CLAIMS.md) is normative and enforced by
`runwall claims-audit`.

---

## Quick start

Requires Python 3.11+ and PyYAML. That is the entire dependency list — a policy
enforcement point that drags in a transitive dependency tree has enlarged the
attack surface it exists to reduce.

```bash
pip install -e .
runwall pin                    # record the policy hash
runwall enroll                 # operator: password + TOTP + sitekey phrase
runwall up                     # governor + console on http://127.0.0.1:8787
runwall hook-install           # register the PreToolUse hook (backs up settings.json)
```

Prove it works:

```bash
runwall redteam                # 75-case adversarial corpus against the live governor
runwall verify                 # walk the hash chain
runwall claims-audit           # fail the build on overclaiming language
```

---

## How a decision happens

```
agent decides to act
      │
      ▼
Claude Code fires PreToolUse hook ◄── a harness feature, not a model feature.
      │                                the model is never asked to cooperate
      ▼
hook/runwall_hook.py   stdlib only, python -I -S, deadline 8s
      │                fail-closed: no governor → cached policy → reduced rule set
      ▼
GOVERNOR
      ├─ envelope     normalize · decode · NFC · canonicalize paths · size caps
      ├─ classify     derive the action label SERVER-SIDE, never from the agent
      ├─ rules        6 deterministic packs → Finding[]  (Diffwall-compatible)
      ├─ blast        {scope, reversibility, subjects, data_classes,
      │                propagation, confidence, basis}
      ├─ session      budgets · taint · denied-intent fingerprints
      └─ gate         CASA route ──► ALLOW / REVIEW / HALT
      │
      ▼
ALLOW → runs   REVIEW → blocks on a human   HALT → refused
      │
      ▼
hash-chained ledger — every route, including ALLOW
```

**ALLOW** is invisible. **REVIEW** blocks the call and raises a card in the
console showing blast radius rather than a raw command string. **HALT** is
terminal for that action class — retrying with a mutated payload matches its own
denial fingerprint and escalates instead of getting a fresh roll.

---

## The switch

```
ARMED      full mediation
DEGRADED   governor unreachable → cached signed policy, reduced rule set.
           Destructive / credential / egress / self-protection still DENY;
           read-class proceeds and spools behind an explicit gap marker
SAFE       policy hash mismatch, ledger unwritable, disk pressure → read-only
DISARMED   TOTP + typed reason · scoped to one project · time-boxed ·
           auto-rearms. There is no permanent off switch, and a disarm can
           never authorise dismantling the wall
```

### Maintaining Runwall itself

Runwall refuses edits and reads of its own source. Without a way in, the only
route to patching or auditing it is uninstalling the hook — and a security tool
that must be *removed* to be maintained will eventually be left removed. That is
a worse outcome than the bug the refusal was preventing.

```bash
runwall maintenance --reason "apply audit fixes" --minutes 15
runwall maintenance --end
```

Requires the governor running and a fresh authenticator code. Time-boxed, auto-
closing, every action counted and logged.

It lifts exactly two action classes — `modify_governor` and
`read_governor_files`, meaning Runwall's own code and policy. **The ledger, the
chain anchor, key material and the harness config stay sealed at every perimeter
state**, maintenance included. Changing how the wall decides is maintenance;
rewriting what it recorded is not. There is deliberately no on-disk grant an
agent could forge, which is also why a stopped governor means no maintenance.

Two invariants at every rung: never auto-allow on timeout, and "governor down"
never looks like "governor said yes."

---

## What it defends against

| Attack | Control |
|---|---|
| Destructive commands | 7 rule families, HALT on shape not score |
| Encoding evasion | base64 (UTF-8 + UTF-16LE), `-EncodedCommand`, backticks, string-concat splitting, `[char]` codes, 4 decode passes; residual encoding is itself a finding |
| Path obfuscation | 8.3 names, `\\?\`, UNC-to-self, junctions, trailing dots, NFC/NFD — canonicalized, never substring-matched |
| Credential exfiltration | secret + outbound channel in one action → HALT; encode-then-send flagged separately |
| Egress | allow/deny domains, proxy-evasion intent, DNS tunnelling, reverse tunnels. **No TLS interception** — a local CA the agent can read is a net-negative trade |
| Persistence | scheduled tasks, Run keys, WMI, services, shell profiles → HALT at *registration*, because execution is unmediated |
| Privilege escalation | account creation, admin group changes, disabling Defender or the firewall |
| Prompt injection via tool results | taint tracking: consuming external content raises the gate floor until the next real user turn |
| Decomposition | session budgets — 10 MB split into 1000 allowlisted calls trips the same limit |
| Verdict shopping | denied-intent fingerprints on normalized intent, not literal payload |
| Self-protection | policy, ledger, keys, hook config, governor process — HALT, always, even while disarmed |
| Wall silently down | liveness canary; a missing denial is itself a ledger event |

Verified by `runwall redteam`: **54 attacks refused, 21 ordinary development
actions unobstructed.** The controls matter as much as the attacks — a wall that
refuses everything is trivially "unbreakable" and useless, and would be
uninstalled within a day.

---

## Posture: the part that decides whether this is real

By default the governor runs as **the same Windows principal as the agent**.
Same-user process termination needs no privilege. Anything the governor can
write, the agent can rewrite. The console labels this honestly:

**DETERRENCE + EVIDENCE** — every attempt is refused at the tool-call layer and
written to the ledger *before* it is refused.

```bash
runwall harden      # generates a reviewed PowerShell script; you run it elevated
```

`harden` provisions a dedicated low-privilege local account that owns the
policy, ledger and keys, denies your interactive account write access to them,
and registers the governor as an auto-restarting service. The console then reads
**CONTAINMENT**.

Even hardened, your account remains a local administrator, so admin-to-SYSTEM
paths remain. The honest framing: this raises a bypass from one incidental tool
call to a deliberate, multi-step, loudly-logged campaign. Full containment means
running agents under a separate lower-privileged account or in a VM.

---

## The ledger

Hash-chained SHA-256 over canonical JSON — **byte-identical to DaxxerOS Local's
`daxxer/integrity.py`**, with a test asserting parity, so one verifier reads both
chains. Writes to `94_AUDIT_LOGS/gate_decisions.jsonl` when DaxxerOS is present.

- Every route recorded, including ALLOW. A ledger of refusals cannot answer what
  an agent actually *did*.
- **Redacted at write.** Tool parameters carry secrets, and an append-only
  chained file cannot have them removed afterwards without breaking the chain.
- Monotonic sequence independent of the wall clock — a local admin can move the
  clock; they cannot move the counter backwards undetected.
- Tamper-**evident**, not tamper-proof. Detection becomes adversarially
  meaningful once `harden` puts the anchor under a different principal.

---

## Where it sits

```
CASA            the governance policy — ALLOW / REVIEW / HALT
VIL             scoring and routing
PromptBP        instruction discipline
Diffwall        validation of what gets written  (git diffs)
Runwall         enforcement of what gets done    (live tool calls)   ← this
DaxxerOS Local  the record store and audit substrate
Agent-Ops       orchestration, HITL-gated
```

Runwall reuses Diffwall's `Route` / `Finding` / `Rule` contracts and its exact
additive scoring (`min(100, Σ)`, thresholds `{review:40, halt:75}`), so a score
means the same thing in both tools and a reviewer learns one vocabulary.

---

## Deliberately not built

- **MCP stdio proxy** — largely redundant while Claude Code is the only harness,
  since MCP calls are tool calls. Worth building when a second harness enters the
  threat model.
- **Egress proxy** — theatre as a bare `HTTPS_PROXY` env var: child processes
  with a cleared environment, Node's undici, raw sockets and HTTP/3 over UDP/443
  all ignore it. Real only alongside per-account firewall default-deny-outbound.
- **Credential broker** — worth building as a *request-signing proxy* that
  terminates the authenticated call itself, never as secret injection into an
  agent-controlled child. Requires first evicting `~/.aws/credentials`, `.env`,
  `gh auth token` and browser cookie jars, or it is cosmetic.

---

## Commands

| | |
|---|---|
| `runwall up` | start the governor and console |
| `runwall status` | rung, policy pin, chain health, approval fatigue |
| `runwall verify` | walk the chain and check the anchor |
| `runwall pin` | record the policy hash into `policy/manifest.json` |
| `runwall enroll` | operator: password + TOTP + sitekey |
| `runwall hook-install` | register the PreToolUse hook (backs up `settings.json`) |
| `runwall redteam` | the adversarial corpus |
| `runwall harden` | generate the privilege-separation script |
| `runwall claims-audit` | fail the build on overclaiming language |

---

## Tests

```bash
python -m pytest tests/ -q      # 98 tests
runwall redteam --offline       # 53 cases, no daemon required
```

The suite emphasises properties that must hold under attack: fail-closed
behaviour, tamper detection, refusal of agent-supplied action labels, and
normalization that cannot be walked around.
