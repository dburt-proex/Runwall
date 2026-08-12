# Uninstrumented paths

Runwall mediates tool calls. This is the list of ways an action can happen on
this machine **without passing through a Runwall decision**.

Publishing it is deliberate. A security control whose coverage gaps are
undocumented invites the assumption of total coverage, and that assumption is
more dangerous than the gaps. Every item below is a known limitation with a
stated reason, not an oversight awaiting a patch.

---

## 1. Code inside an approved interpreter

**The largest gap, by a wide margin.**

Runwall sees `Bash(python deploy.py)` as one action. It does not see the twelve
file writes, the database connection, and the HTTP POST that happen inside that
process. The same applies to `node -e`, `powershell -EncodedCommand`, `uv run`,
`ruby`, `perl`, and `wsl bash -c`.

**Mitigation, partial:** interpreter invocations are classified as
`run_interpreter` rather than `run_shell_command`, gated at REVIEW by default,
and their blast-radius confidence is reduced by 0.30 with the note "effects
occur inside a process Runwall does not observe." The opacity is *priced*, not
removed.

**What would actually close it:** in-process instrumentation (an audit hook or
`sitecustomize` shim per runtime), or running interpreters in a sandbox with a
mediated syscall surface. Neither is implemented.

## 2. GUI automation

Any tool that drives the mouse and keyboard — typing into an already-open
terminal, clicking through a browser — produces effects Runwall never sees. On
this machine that includes the `computer-use` MCP server.

**Mitigation:** none within Runwall. This is a genuine hole.

## 3. Browser-resident network calls

JavaScript executed in a page (`fetch`, `XMLHttpRequest`) runs in the browser's
network stack with the user's existing cookies and session. It does not traverse
any proxy Runwall could configure, and the request never appears as a tool call.

**Mitigation:** none. Browser automation MCP servers are an uninstrumented
egress channel by construction.

## 4. Scheduled and persistent execution

Code registered with Task Scheduler, a Run key, a WMI event subscription, a
service, a shell profile, or cron executes **later, outside any governed
session**. Nothing downstream mediates it.

**Mitigation, real:** *registering* persistence is a HALT (`scope.persistence`),
independent of how innocuous the payload looks. Runwall cannot mediate the
execution, so it refuses the registration. Persistence established before
Runwall was installed is invisible.

## 5. Harnesses without the hook

Cursor, Claude Desktop, VS Code Copilot, a raw SDK script, or a second Claude
Code installation with a different config directory. None of them read the
`settings.json` that registers the Runwall hook.

**Mitigation, partial:** launching a harness with governance disabled or
redirected (`--dangerously-skip-permissions`, `CLAUDE_CONFIG_DIR`, `--settings`)
is a HALT (`self_protect.ungoverned_harness`) *when it happens through a
mediated call*. Starting one from a desktop shortcut is not mediated.

**What would close it:** the MCP stdio proxy, deliberately deferred — see the
README's roadmap.

## 6. Direct process action by the operator's own account

Runwall runs, by default, as the same Windows principal as the agent. That
principal can terminate the governor, rewrite the policy, and rewrite the
ledger. Same-user process termination requires no privilege; process
self-protection is not achievable in userland without a signed driver.

**Mitigation, real but incomplete:** `runwall harden` moves policy, keys and
ledger under a separate low-privilege account and denies the operator's account
write access. That is the difference between the labels **DETERRENCE +
EVIDENCE** and **CONTAINMENT** in the console. Even hardened, the operator
remains a local administrator, so admin-to-SYSTEM paths remain.

## 7. Content-level exfiltration through an allowlisted host

Runwall gates destinations, not payloads. A secret pushed to an allowlisted
gist, encoded into a URL path on an approved API, or tunnelled through DNS TXT
records to a permitted resolver passes host-level gating.

**Mitigation, partial:** session budgets bound *volume* (bytes egressed,
distinct domains) so a thousand small requests trip the same limit as one large
one. Several covert-channel shapes are detected specifically. Content inspection
is not performed, and TLS is deliberately not intercepted — a local CA whose
private key the agent can read trades a real secret for the appearance of
visibility.

## 8. Time-of-check to time-of-use

Runwall decides on a path *string*; the tool acts on a path *handle*. Between
the decision and the write, the path can be replaced with a junction pointing
elsewhere.

**Mitigation, partial:** paths are canonicalized (8.3 names, `\\?\`,
UNC-to-self, trailing dots, junctions resolved), and creating a symlink or
junction is itself a scored finding. The window is narrowed, not closed. Closing
it requires the enforcement point to hold the handle, which a PreToolUse hook
structurally cannot do because it does not perform the operation.

## 9. Bounded deobfuscation

`deep_decode` runs four passes. A payload wrapped in five layers survives.

**Mitigation, real:** hitting the ceiling with decodable content remaining is
itself a finding (`self_protect.residual_encoding`), and piping a decoder into an
interpreter is a HALT on shape alone (`destructive.decode_exec`) regardless of
what decodes out.

## 10. Clock manipulation

A local administrator can set the system clock. TOTP windows, time-boxed disarm,
and grant expiry all move with it.

**Mitigation, partial:** ledger ordering uses a persisted monotonic sequence
independent of the wall clock, so reordering is detectable. The time-based
*controls* remain affected.

---

## How to read this list

Two failure modes to avoid.

**"So it doesn't work."** Wrong. Items 1–5 describe an agent that has decided to
route around the wall, which is a loud, unusual, multi-step act — and several of
those steps are themselves refused and logged. The overwhelmingly common case is
an agent behaving as designed while acting on bad input, and that case is
mediated.

**"So we should claim it's complete."** Also wrong, and worse. See
`docs/CLAIMS.md`.

The correct summary: **a wall with named doors is defensible; a wall claimed to
be seamless is a liability.**
