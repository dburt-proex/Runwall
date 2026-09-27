# Reproduce the Runwall offline demo

From a fresh Python 3.11+ terminal with Git installed:

```bash
git clone https://github.com/dburt-proex/Runwall.git
cd Runwall
python -m pip install -e .
python -m runwall.cli demo
```

Expected: the `rm -rf /srv/production` fixture routes to **HALT**, the
`git status --short` fixture routes to **ALLOW**, two decision records include
IDs and chain hashes, and the temporary ledger reports **verified (2 chained
decisions)**. The printed IDs and hashes change each run. Neither fixture's
command is executed. The demo cleans up its temporary ledger after verification.

The video renders the terminal output captured from an actual demo run:
[Watch the short terminal demo](../media/runwall-offline-demo.mp4).

For the full fixture suite, run:

```bash
python -m runwall.cli redteam --offline
python -m runwall.cli claims-audit
```

This demonstrates offline policy evaluation and hash-chained decision records.
It does not demonstrate a live harness interception or protect execution paths
without an installed hook. See [uninstrumented paths](UNINSTRUMENTED_PATHS.md),
[threat model](THREAT_MODEL.md), and [pilot gate](RELEASE_PILOT_GATE.md).

## Share text

Runwall's two-case demo takes one command after install: a destructive fixture
routes to HALT, ordinary `git status --short` routes to ALLOW, and both decisions
appear in a verified temporary chain. The demo evaluates policy offline and
never executes either fixture. Coverage is limited to instrumented tool calls;
known bypass paths are documented in the repository. [Demo](../media/runwall-offline-demo.mp4)
