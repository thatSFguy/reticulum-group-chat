# interop harness

Live end-to-end tests of fwdsvc against the upstream Python `rns` + `lxmf`
implementation. The harness spins up a localhost-only test environment
(an `rnsd` transport, a fwdsvc binary built from source, and one Python
LXMF peer per test case), so test runs are isolated from any real
deployment and from each other.

## When to run

- Before merging any wire-format / crypto / link / Resource change.
- Before cutting a release.
- Whenever you suspect a regression that an in-process Go test won't
  catch (e.g. "we got a proof timeout against a live receiver").

In-process tests under `internal/...` test our code against itself —
they cannot detect divergence from upstream. The interop harness is
the only place we assert byte-for-byte and behavior-for-behavior
compatibility against the real Reticulum stack.

## Prereqs

- Go (whatever `go.mod` requires).
- Python 3.10+.
- `pip install rns lxmf` — installs `rnsd` on PATH.

Verify locally:

```sh
rnsd --version
python -c "import RNS, LXMF; print(RNS.__version__, LXMF.__version__)"
```

## Run it

```sh
# all cases
bash tests/interop/run.sh

# Windows
pwsh tests/interop/run.ps1

# single case
bash tests/interop/run.sh -run TestHarness/opportunistic_short
```

The harness skips with a clear message if the prereqs aren't installed —
it doesn't fail your test run.

## What runs

The Go test `TestHarness` (build tag `interop`) does the orchestration:

1. Picks a free localhost TCP port.
2. Writes an isolated Reticulum config and starts `rnsd` against it,
   bound to `127.0.0.1:<port>` as a `TCPServerInterface`.
3. Builds fwdsvc from `./cmd/fwdsvc` into a tempdir, writes a fwdsvc
   config that connects to the harness rnsd, and starts it. Parses the
   delivery destination hash out of fwdsvc's startup log.
4. For each `*.py` file under `tests/interop/cases/` (excluding ones
   starting with `_`), spawns it as a subprocess with `--rnsd
   127.0.0.1:<port>` and `--fwdsvc <hash>` args. The case runs to
   completion and returns 0 on success, non-zero on failure.

Files matching `*_xfail.py` are expected to fail today; the harness
reports them as `SKIP — xfail` instead of failing the run. Rename the
file (drop the `_xfail` suffix) once the underlying bug is fixed.

## Adding a case

1. Create `tests/interop/cases/<name>.py`.
2. Use the `_common.py` helpers — `setup()` returns a parsed-args object
   and a `Peer` with delivery destination, send_cmd, and wait_for_reply.
3. Print informative `[case] ...` lines so failures show what we did.
4. Exit 0 on success, non-zero on failure.

Minimal skeleton:

```python
#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common
import LXMF

def main() -> int:
    args, peer = _common.setup(display_name="my-case")
    peer.wait_for_fwdsvc()
    peer.send_cmd("/help", method=LXMF.LXMessage.OPPORTUNISTIC)
    text = peer.wait_for_reply(match=lambda t: "/?" in t)
    return 0 if "/help" in text or "/?" in text else 1

if __name__ == "__main__":
    sys.exit(main())
```

## Cases (current)

| File | What it asserts |
|------|------------------|
| `opportunistic_short.py` | `/version` over single-packet opportunistic LXMF. Smallest possible exercise — if this fails, announce / Token encrypt / Token decrypt is broken. |
| `link_data_one_user.py` | `/users` reply with 1 member fits a single link DATA packet. |
| `link_data_oversize_xfail.py` | `/users` reply with a large roster either truncates cleanly or arrives via Resource transfer. **Currently xfail** — flip to a regular test once `/users` reply path is fixed. |
| `chat_fanout.py` | Two Python peers /join, alice sends a chat, bob receives via fanout. |

## Files

- `harness_test.go` — Go orchestrator (build tag `interop`).
- `cases/_common.py` — shared scaffolding for case scripts.
- `cases/*.py` — one case per scenario.
- `run.sh` / `run.ps1` — wrappers for `go test -tags=interop`.
- `.github/workflows/interop.yml` — runs this on every push to main.

## Legacy scripts

`python_lxmf_receiver.py` and `python_peer.py` predate this harness
and are kept around as ad-hoc debugging tools. Prefer adding new tests
under `cases/` rather than extending those.
