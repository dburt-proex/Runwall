"""Runwall CLI.

    runwall up            start the governor (and the console)
    runwall status        current rung, policy pin, chain health
    runwall verify        walk the hash chain and check the anchor
    runwall pin           record the policy hash into policy/manifest.json
    runwall enroll        create the operator: password + TOTP + sitekey
    runwall hook-install  register the PreToolUse hook (backs up settings.json)
    runwall redteam       run the adversarial corpus against the live governor
    runwall harden        provision the separate service account and ACLs
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request

from . import (DEFAULT_HOST, DEFAULT_POLICY, DEFAULT_PORT, MANIFEST, ROOT,
               STATE_DIR, __version__)

HOOK_SCRIPT = os.path.join(ROOT, "hook", "runwall_hook.py")
SETTINGS = os.path.join(os.path.expanduser("~"), ".claude", "settings.json")

# Populated by main() via term.init(), which also switches stdout to UTF-8.
# Windows consoles default to cp1252 and will raise UnicodeEncodeError on the
# first arrow or ellipsis otherwise -- a CLI that crashes while printing its own
# success message is not a CLI anyone keeps using.
C: dict = {k: "" for k in ("reset", "dim", "bold", "red", "green", "yellow",
                           "cyan", "mag", "blue")}
G: dict = {"ok": "+", "bad": "x", "rule": "-", "dot": "*",
           "arrow": "->", "ellipsis": "...", "warn": "!"}


def _url(args, path: str) -> str:
    return f"http://{args.host}:{args.port}{path}"


def _token() -> str:
    try:
        with open(os.path.join(STATE_DIR, "client.token"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _get(args, path: str, timeout: float = 5.0) -> dict:
    req = urllib.request.Request(_url(args, path),
                                 headers={"Authorization": f"Bearer {_token()}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _post(args, path: str, body: dict, timeout: float = 30.0,
          token: str | None = None) -> dict:
    req = urllib.request.Request(
        _url(args, path), data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json",
                 "Host": f"{args.host}:{args.port}",
                 "Authorization": f"Bearer {_token() if token is None else token}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


# --------------------------------------------------------------------------


def cmd_up(args) -> int:
    from .daemon import Governor, serve

    if args.background:
        import subprocess
        flags = 0x00000008 | 0x00000200 if os.name == "nt" else 0  # DETACHED | NEW_GROUP
        cmd = [sys.executable, "-m", "runwall.cli", "up",
               "--host", args.host, "--port", str(args.port)]
        subprocess.Popen(cmd, creationflags=flags, close_fds=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(40):
            time.sleep(0.25)
            try:
                urllib.request.urlopen(_url(args, "/health"), timeout=1)
                print(f"{C['green']}governor up{C['reset']} — "
                      f"console http://{args.host}:{args.port}/")
                return 0
            except (urllib.error.URLError, OSError):
                continue
        print(f"{C['red']}governor did not become healthy{C['reset']}", file=sys.stderr)
        return 1

    try:
        g = Governor(root=ROOT, policy_path=args.policy, manifest_path=MANIFEST,
                     state_dir=STATE_DIR)
    except Exception as exc:  # noqa: BLE001 - a bad policy must not start a bad wall
        print(f"{C['red']}refusing to start: {exc}{C['reset']}", file=sys.stderr)
        return 2

    httpd = serve(g, args.host, args.port)
    st = g.status()
    state = st["perimeter"]["state"]
    print(f"{C['bold']}Runwall {__version__}{C['reset']}  "
          f"{C['green'] if state == 'ARMED' else C['yellow']}"
          f"{state}{C['reset']}   posture: {st['posture']}")
    print(f"  policy   {os.path.basename(g.policy.path)}  "
          f"sha256 {g.policy.sha256[:16]}…  {g.policy.pin_message}")
    print(f"  actions  {len(g.policy.gate_matrix)} gated · "
          f"{len(g.policy.protected_paths)} protected paths · "
          f"{len(g.policy.halt_patterns)} halt patterns")
    print(f"  ledger   {g.ledger.path}")
    print(f"  console  http://{args.host}:{args.port}/")
    if not g.operators.enrolled():
        print(f"  {C['yellow']}no operator enrolled — run `runwall enroll` "
              f"before approvals will work{C['reset']}")
    print(f"{C['dim']}Ctrl-C to stop.{C['reset']}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping…")
        g.ledger.note("governor_stop", {"reasons": ["operator stopped the governor"],
                                        "perimeter_state": g.perimeter.state})
        httpd.shutdown()
    return 0


def cmd_down(args) -> int:
    try:
        _post(args, "/api/kill", {"reason": "runwall down"}, timeout=3)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        pass
    print("sent shutdown intent; stop the foreground process with Ctrl-C")
    return 0


def cmd_status(args) -> int:
    try:
        st = _get(args, "/status")
    except (urllib.error.URLError, OSError) as exc:
        print(f"{C['red']}governor unreachable{C['reset']} ({exc}) — "
              f"hooks are in DEGRADED fallback")
        return 1

    p = st["perimeter"]
    color = {"ARMED": C["green"], "DEGRADED": C["yellow"],
             "SAFE": C["mag"], "DISARMED": C["red"]}.get(p["state"], "")
    print(f"{C['bold']}Runwall {st['version']}{C['reset']}   "
          f"{color}{C['bold']}{p['state']}{C['reset']}   posture: {st['posture']}")
    for r in p["reasons"]:
        print(f"    {C['dim']}· {r}{C['reset']}")
    if p["disarm"]:
        d = p["disarm"]
        print(f"    {C['red']}disarmed by {d['operator']} — {d['remaining_s']}s left "
              f"— scope: {d['scope'] or '<all>'} — {d['reason']}{C['reset']}")

    pol, led, ap = st["policy"], st["ledger"], st["approvals"]
    pin = f"{C['green']}pinned{C['reset']}" if pol["pinned"] else f"{C['yellow']}unpinned{C['reset']}"
    print(f"  policy   {pol['actions']} actions · {pin} · {pol['sha256'][:16]}…")
    chain = f"{C['green']}intact{C['reset']}" if led["chain_ok"] else f"{C['red']}BROKEN{C['reset']}"
    print(f"  ledger   {led['events']} events · chain {chain}")
    # Anchor status is always reported by verify(); only render it as a warning
    # when it actually indicates a problem. A success marked with "!" teaches
    # the operator to ignore the "!".
    for prob in led["problems"]:
        if led["chain_ok"]:
            print(f"    {C['dim']}{prob}{C['reset']}")
        else:
            print(f"    {C['red']}{G['warn']} {prob}{C['reset']}")
    print(f"  approvals pending {ap['pending']} · suspended {ap['suspended']} · "
          f"approved {ap['approved']} · denied {ap['denied']} · "
          f"grants {ap['live_grants']}")
    if ap["rubber_stamp_risk"]:
        print(f"    {C['yellow']}! median approval latency {ap['median_latency_s']}s — "
              f"approvals in this window are low-assurance{C['reset']}")
    print(f"  sessions {st['sessions']} · decisions {st['decisions']} · "
          f"operator {'present' if st['operator_present'] else 'absent'} · "
          f"uptime {st['uptime_s']}s")
    return 0 if p["state"] == "ARMED" and led["chain_ok"] else 1


def cmd_verify(args) -> int:
    from .ledger import Ledger
    from . import policy as policy_mod, classify
    pol = policy_mod.load(args.policy, ROOT, classify.known_actions(), MANIFEST)
    led = Ledger(pol.ledger_path(), STATE_DIR)
    ok, checked, problems = led.verify()
    if ok:
        print(f"{C['green']}chain intact{C['reset']} — {checked} events verified")
        print(f"  {led.path}")
        for p in problems:
            print(f"  {C['dim']}{p}{C['reset']}")
        return 0
    print(f"{C['red']}CHAIN VERIFICATION FAILED{C['reset']} — {checked} events checked")
    for p in problems:
        print(f"  {C['red']}! {p}{C['reset']}")
    return 1


def cmd_pin(args) -> int:
    from . import policy as policy_mod
    digest = policy_mod.write_manifest(args.policy, MANIFEST)
    print(f"{C['green']}pinned{C['reset']} {os.path.basename(args.policy)} → {digest}")
    print(f"  {MANIFEST}")
    return 0


def cmd_enroll(args) -> int:
    from .auth import OperatorStore
    store = OperatorStore(STATE_DIR)
    if store.enrolled() and not args.force:
        print(f"{C['yellow']}an operator is already enrolled{C['reset']} "
              f"(use --force to replace)")
        return 1

    operator_id = args.operator or input("operator id: ").strip()
    pw = getpass.getpass("password: ")
    if len(pw) < 10:
        print(f"{C['red']}password must be at least 10 characters{C['reset']}")
        return 1
    if pw != getpass.getpass("confirm: "):
        print(f"{C['red']}passwords do not match{C['reset']}")
        return 1
    print("\nChoose a sitekey phrase. The console shows it on every approval card;")
    print("a prompt that does not display it did not come from Runwall.")
    sitekey = input("sitekey phrase: ").strip() or "runwall"

    out = store.enroll(operator_id, pw, sitekey)
    print(f"\n{C['green']}enrolled{C['reset']} {operator_id}")
    print(f"  TOTP secret : {C['bold']}{out['totp_secret']}{C['reset']}")
    print(f"  otpauth URI : {out['uri']}")
    print(f"  sitekey     : {out['sitekey']}")
    print(f"\n{C['yellow']}Add the secret to your authenticator now — "
          f"it is not shown again.{C['reset']}")
    return 0


def cmd_hook_install(args) -> int:
    """Register the PreToolUse hook, backing up settings.json first."""
    interp = args.python or sys.executable
    # -I isolates (ignores PYTHONPATH and user site), -S skips site
    # initialisation. Both are startup-cost wins AND they close the
    # sitecustomize/PYTHONPATH substitution path that would otherwise let an
    # agent replace the enforcer without touching any file we check.
    command = f'"{interp}" -I -S "{HOOK_SCRIPT}"'

    settings = {}
    if os.path.exists(SETTINGS):
        with open(SETTINGS, encoding="utf-8") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                print(f"{C['red']}{SETTINGS} is not valid JSON — refusing to "
                      f"rewrite it{C['reset']}")
                return 1

    entry = {"matcher": "*", "hooks": [
        {"type": "command", "command": command, "timeout": int(args.timeout)}]}
    hooks = settings.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    pre = [e for e in pre if "runwall_hook" not in json.dumps(e)]
    pre.append(entry)
    hooks["PreToolUse"] = pre

    print(f"{C['bold']}About to modify{C['reset']} {SETTINGS}")
    print(f"  hook command: {command}")
    print(f"  timeout     : {args.timeout}s "
          f"(the hook's own deadline is {C['bold']}8s{C['reset']}, deliberately lower)")
    if not args.yes:
        if input("\nproceed? [y/N] ").strip().lower() not in ("y", "yes"):
            print("aborted — nothing written")
            return 1

    if os.path.exists(SETTINGS):
        backup = f"{SETTINGS}.runwall-backup.{int(time.time())}"
        shutil.copy2(SETTINGS, backup)
        print(f"  backup      : {backup}")

    os.makedirs(os.path.dirname(SETTINGS), exist_ok=True)
    with open(SETTINGS, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
    print(f"{C['green']}hook installed{C['reset']} — new Claude Code sessions are governed.")
    print(f"{C['dim']}Restart any running session for it to take effect.{C['reset']}")
    return 0


def cmd_hook_uninstall(args) -> int:
    if not os.path.exists(SETTINGS):
        print("no settings.json")
        return 0
    with open(SETTINGS, encoding="utf-8") as f:
        settings = json.load(f)
    pre = settings.get("hooks", {}).get("PreToolUse", [])
    kept = [e for e in pre if "runwall_hook" not in json.dumps(e)]
    if len(kept) == len(pre):
        print("no Runwall hook registered")
        return 0
    backup = f"{SETTINGS}.runwall-backup.{int(time.time())}"
    shutil.copy2(SETTINGS, backup)
    settings["hooks"]["PreToolUse"] = kept
    if not kept:
        settings["hooks"].pop("PreToolUse")
    if not settings.get("hooks"):
        settings.pop("hooks", None)
    with open(SETTINGS, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
    print(f"{C['yellow']}hook removed{C['reset']} (backup {backup})")
    return 0


def cmd_redteam(args) -> int:
    from .redteam import run_corpus
    return run_corpus(args)


def cmd_harden(args) -> int:
    from .harden import run_harden
    return run_harden(args)


def cmd_claims(args) -> int:
    from .claims import run_audit
    return run_audit(args)


def cmd_maintenance(args) -> int:
    """Open a window in which Runwall's own source may be edited.

    Requires the governor running and a fresh authenticator code. There is
    deliberately no on-disk grant an agent could forge, which is also why a
    stopped governor means no maintenance.
    """
    import getpass as _gp

    if args.end:
        try:
            tok = _operator_token(args)
            r = _post(args, "/api/maintenance/end", {}, token=tok)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            print(f"{C['red']}{exc}{C['reset']}", file=sys.stderr)
            return 1
        closed = r.get("closed") or {}
        print(f"{C['green']}maintenance closed{C['reset']} — "
              f"{closed.get('actions', 0)} action(s) in that window")
        return 0

    reason = args.reason or input("reason (recorded in the ledger): ").strip()
    if not reason:
        print(f"{C['red']}a typed reason is required{C['reset']}", file=sys.stderr)
        return 1

    try:
        tok = _operator_token(args)
        code = _gp.getpass("authenticator code: ").strip()
        _post(args, "/auth/stepup", {"totp": code}, token=tok)
        r = _post(args, "/api/maintenance",
                  {"reason": reason, "seconds": args.minutes * 60}, token=tok)
    except urllib.error.HTTPError as exc:
        import json as _j
        msg = _j.loads(exc.read() or b"{}").get("message") or exc.reason
        print(f"{C['red']}{msg}{C['reset']}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, OSError) as exc:
        print(f"{C['red']}governor unreachable ({exc}) — maintenance requires a "
              f"running governor by design{C['reset']}", file=sys.stderr)
        return 1

    print(f"{C['green']}maintenance open{C['reset']} for {r['remaining_s']}s")
    print(f"  lifts   {C['bold']}modify_governor{C['reset']} and "
          f"{C['bold']}read_governor_files{C['reset']} — Runwall's own code and policy")
    print(f"  sealed  ledger · chain anchor · key material · harness config")
    print(f"  {C['dim']}every action in this window is logged and counted; "
          f"it auto-closes.{C['reset']}")
    print(f"\n  close early:  runwall maintenance --end")
    return 0


def _operator_token(args) -> str:
    """Authenticate as the operator for a privileged CLI action."""
    import getpass as _gp
    operator = args.operator or input("operator id: ").strip()
    pw = _gp.getpass("password: ")
    code = _gp.getpass("authenticator code: ").strip()
    r = _post(args, "/auth/login",
              {"operator_id": operator, "password": pw, "totp": code}, token="")
    return r["token"]


# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="runwall",
                                description="Runtime governance for agentic execution.")
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--policy", default=DEFAULT_POLICY)
    p.add_argument("--version", action="version", version=f"runwall {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    up = sub.add_parser("up", help="start the governor")
    up.add_argument("--background", action="store_true")
    up.set_defaults(func=cmd_up)

    # --host/--port are global flags, but `runwall up --port 8787` is what
    # anyone actually types. SUPPRESS keeps the global value when the
    # subcommand form is omitted, so both orderings work.
    for p_ in (up,):
        p_.add_argument("--host", default=argparse.SUPPRESS)
        p_.add_argument("--port", type=int, default=argparse.SUPPRESS)

    sub.add_parser("down", help="engage the kill switch").set_defaults(func=cmd_down)
    sub.add_parser("status", help="current state").set_defaults(func=cmd_status)
    sub.add_parser("verify", help="verify the ledger chain").set_defaults(func=cmd_verify)
    sub.add_parser("pin", help="pin the policy hash").set_defaults(func=cmd_pin)

    en = sub.add_parser("enroll", help="enroll the operator")
    en.add_argument("--operator")
    en.add_argument("--force", action="store_true")
    en.set_defaults(func=cmd_enroll)

    hi = sub.add_parser("hook-install", help="register the PreToolUse hook")
    hi.add_argument("--python", help="interpreter to invoke (default: this one)")
    hi.add_argument("--timeout", default=15, type=int)
    hi.add_argument("--yes", action="store_true")
    hi.set_defaults(func=cmd_hook_install)

    sub.add_parser("hook-uninstall").set_defaults(func=cmd_hook_uninstall)

    rt = sub.add_parser("redteam", help="run the adversarial corpus")
    rt.add_argument("--verbose", action="store_true")
    rt.add_argument("--offline", action="store_true",
                    help="evaluate in-process instead of against a running governor")
    rt.set_defaults(func=cmd_redteam)

    hd = sub.add_parser("harden", help="provision privilege separation")
    hd.add_argument("--account", default="runwall-gov")
    hd.add_argument("--dry-run", action="store_true")
    hd.set_defaults(func=cmd_harden)

    sub.add_parser("claims-audit",
                   help="fail the build on overclaiming language").set_defaults(func=cmd_claims)

    mt = sub.add_parser("maintenance",
                        help="open a window to edit Runwall's own source")
    mt.add_argument("--reason", help="recorded in the ledger; required")
    mt.add_argument("--minutes", type=int, default=15)
    mt.add_argument("--operator")
    mt.add_argument("--end", action="store_true", help="close the window now")
    mt.set_defaults(func=cmd_maintenance)
    return p


def main(argv=None) -> int:
    global C, G
    from .term import init
    C, G = init()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
