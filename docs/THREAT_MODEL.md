# Threat model

## Adversary

Not a remote attacker. The adversary is **a capable agent running with the
operator's own privileges on Windows 11 Home, where the operator is a local
administrator.** It may be misaligned, or — far more commonly — perfectly aligned
and acting on injected instructions it cannot distinguish from legitimate ones.

Three assumptions shape every control:

1. **The agent can read anything the operator can read.** Including the client
   token, the policy, and the ledger.
2. **The agent is not trying to be caught, but it is not a nation-state either.**
   It will take an available path; it will not develop a kernel exploit.
3. **The overwhelmingly common case is not malice.** It is an agent behaving
   exactly as designed while acting on bad input. Controls that only defeat
   deliberate attack miss most real incidents.

## What "secure" means here

Runwall does **not** attempt to make bypass impossible. It attempts to make
bypass **expensive, multi-step, and loud** — so that the difference between "the
wall is working" and "the wall is gone" is always visible in the ledger.

Stated as an invariant: *no single tool call should be able to disable
enforcement, and no attempt should be unlogged.*

---

## Bypass paths, classified

**P** = prevented (with `harden`) · **D** = detectable only · **N** = neither

### Against the decider

| Mechanism | Class | Control |
|---|---|---|
| `taskkill` the governor (same-user, no privilege needed) | D → P | heartbeat gap is an alarm; `harden` runs it as a service under another SID with auto-restart |
| Edit `.claude/settings.json` to remove the hook | P | `self_protect.harness_config` HALT; `harden` ACLs it |
| Launch a fresh harness with `--dangerously-skip-permissions` | D | `self_protect.ungoverned_harness` HALT when mediated; a desktop shortcut is not |
| PATH-hijack the interpreter, `sitecustomize.py`, `PYTHONPATH` | P | hook invoked by absolute path with `-I -S`; `self_protect.interpreter_hijack` HALT |
| Read `client.token` and call `/decide` directly | P | split keys — the client token can request decisions and nothing else |
| Read `approval.key` and self-approve | P | `harden` ACLs it away from the agent's account entirely |
| Rewrite policy **and** manifest together | D → P | pin detects single-file edits; `harden` moves both under the governor's SID |
| Fill the disk so the ledger becomes unwritable | D | `LedgerUnwritable` drops the perimeter to SAFE rather than deciding unrecorded |
| Flood REVIEW to exhaust the operator | P | `reviews_per_hour` budget; fatigue metric marks the window low-assurance |
| **Ask the operator to turn it off** | **N** | accepted residual risk. Disarm is scoped, time-boxed, requires a typed reason, and records the refusal that immediately preceded it |

### Against classification

| Mechanism | Class | Control |
|---|---|---|
| Base64 / `-EncodedCommand` / backticks / concat / `[char]` | P | 4 decode passes; best-scoring encoding chosen by ASCII ratio, not first-that-parses |
| Five layers of encoding | D | pass ceiling reached with decodable content left is itself a finding |
| Decode-then-pipe-to-shell | P | matched on *shape*, so it fires regardless of what decodes out |
| Path obfuscation (junction, 8.3, `\\?\`, UNC-to-self, trailing dot, NFD) | P | canonicalized before comparison; never substring-matched |
| **Effects inside `python -c` / `node -e`** | **N** | classified `run_interpreter`, gated REVIEW, blast-radius confidence reduced 0.30. The opacity is priced, not removed |
| Agent supplies its own action label | P | label derived server-side; the protocol has no field to supply one |
| Oversized payload to blow the hook timeout | P | size cap refuses before evaluation; hook deadline strictly below the harness timeout |
| Decomposition — one HALT as N ALLOWs | P | session budgets accumulate |
| Verdict shopping — mutate and retry | P | denied-intent fingerprints on normalized intent |

### Against egress

| Mechanism | Class | Control |
|---|---|---|
| Denylisted / unlisted destination | P | host gating |
| Explicit proxy evasion (`--noproxy`, `trust_env=False`, `env -i`) | P | intent is refused even where the mechanism would have worked |
| DNS tunnelling, DoH, raw sockets, reverse tunnels | P | matched against the *pre-decode* view, since the encoding is the evidence |
| **Exfil through an allowlisted host** | **N** | host-level gating cannot see content. Budgets bound volume only |
| Child process with cleared environment | N | needs per-account firewall default-deny-outbound |

### Against the human loop

| Mechanism | Class | Control |
|---|---|---|
| Local process POSTs `/api/approve` with a stolen token | P | split keys; approve requires a console session, not the client token |
| Spoofed approval prompt | P | operator-chosen sitekey phrase shown on every card |
| High-blast approval by a single click | P | step-up TOTP, single-use, consumed on use |
| Approval fatigue → rubber-stamping | P | median latency < 2s or > 10/hour flags the window as low-assurance |
| Notification path blocked by the wall itself | P | approval channel is out-of-band and exempt |
| Clock manipulation breaking TOTP / expiry | D | ledger ordering uses a monotonic counter; the time-based controls remain affected |

---

## Known-unsolved

Listed so nobody has to rediscover them.

1. **Interpreter opacity** — the largest gap. Closing it needs in-process
   instrumentation or a sandboxed syscall surface.
2. **GUI automation and browser-resident network calls** — entirely outside the
   tool-call layer.
3. **Content-level exfiltration through allowlisted hosts** — requires content
   inspection Runwall deliberately does not do.
4. **TOCTOU** — the hook decides on a path string and never holds the handle.
   Narrowed by canonicalization and by scoring link creation; not closed.
5. **Social engineering of the operator** — no technical control. Disarm is made
   costly and auditable instead.
6. **Pre-existing persistence** — anything registered before installation.

## Design principles that follow

- **Fail closed, but stay usable.** An unusable control gets removed, and a
  removed control protects nothing. Hence the four-rung ladder rather than an
  on/off switch.
- **Deterministic, never a model judge.** An LLM judge can be prompt-injected;
  that would put the adversary inside the decider.
- **Price opacity, do not pretend to see through it.** Where Runwall cannot
  observe effects, it lowers confidence and raises the gate.
- **Record before refusing.** So "the wall went quiet" is never
  indistinguishable from "nothing happened."
- **False positives are security failures.** Every over-block trains the
  operator toward the click-through reflex that makes the whole loop decorative.
