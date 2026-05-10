# Interop harness — design notes

This document describes the harness as a reusable pattern, separate from
the fwdsvc-specific glue. The intent: someone running an LXMF service
written in any language could lift this directory into their own repo
with a few hours of adaptation.

## What problem does this solve

In-process tests prove a system is self-consistent. They cannot prove
it interoperates with anything outside itself. For wire-format /
crypto / link-layer code, self-consistency is a much weaker guarantee
than interop:

- **Both sides of a Go round-trip test agree on a wire mistake.** If we
  encode a field as little-endian when SPEC says big-endian, our sender
  and our receiver both have the bug; the test passes.
- **Interop with the upstream reference implementation is the only test
  that catches divergence.** If our Go sender produces bytes that an
  upstream Python client refuses, the test fails — and now we know.

This harness makes that interop test cheap and runnable on every
commit. It boots a real Python `rnsd` + a real Python LXMF client and
asserts the system-under-test behaves correctly when speaking to them.

## Design at a glance

```
            ┌─────────────────────────────────────────┐
            │           harness_test.go               │
            │  (orchestrator, build tag `interop`)    │
            └───────────────────┬─────────────────────┘
                                │ spawns
            ┌───────────────────┼───────────────────────┐
            ▼                   ▼                       ▼
       ┌─────────┐         ┌─────────┐              ┌────────┐
       │  rnsd   │ ◀──TCP─▶│ fwdsvc  │              │ case-N │ ─┐
       └─────────┘         │ (built  │              │ (py    │  │ assertions
            ▲              │  fresh) │              │  LXMF) │  ▼
            │              └─────────┘              └────────┘  exit 0/1
            └──────── all on 127.0.0.1:<free-port> ─────────────┘
```

Three subprocesses, all on loopback:

1. **rnsd** — upstream Reticulum transport. Runs unmodified (the
   `python -m pip install rns` binary). Configured to expose a single
   `TCPServerInterface` on a free local port.
2. **System under test** — fwdsvc here, but conceptually: any LXMF
   service. The harness builds it from source per run, configures it
   to connect to the rnsd above, and parses its delivery destination
   hash out of its startup log.
3. **Per-case Python LXMF client** — one subprocess per scenario. Each
   uses upstream `RNS` + `LXMF` libraries to play the part of a real
   user, send commands, and assert replies.

The Go test orchestrator (`harness_test.go`) is the glue: it picks the
port, writes configs to tempdirs, sequences subprocess lifetimes, and
collects each case's exit code as the test result.

## Why subprocesses, not in-process?

We want each case to use the *real* upstream Python implementation, not
a Go reimplementation of it. That forces process boundaries. The
trade-off — slower test runs, log capture complexity — is worth it
because process isolation is the only credible way to guarantee
"nothing on our side influenced this case's behavior."

## Per-case isolation

Each case gets:

- A fresh fwdsvc binary instance (its own state.json, identity,
  history, log file under `t.TempDir()`).
- A fresh Python `Reticulum` instance (its own config, its own
  identity).

Cases share:

- The single rnsd transport (cheap to share, no state-leakage path).
- The TCP port (rnsd is the only thing listening on it).

Why this split: a case's `/join` shouldn't bleed into the next case's
`/users` count. Sharing rnsd is fine because rnsd has no application
state — it's a router.

## Handling the announce race

Reticulum's announce model is push-based: a peer announces, listeners
cache the announce, and now they can talk. A naive case that "send /v
right after RNS startup" tends to fail because:

- fwdsvc announced before our case's RNS connected to rnsd.
- Our announce hasn't reached fwdsvc yet, so fwdsvc drops our inbound
  message ("sender unknown — must announce first").

The harness handles this with two patterns in `_common.py`:

1. **Wait until we can recall fwdsvc.** Block until
   `RNS.Identity.recall(fwdsvc_hash)` returns non-None. Periodically
   issue `RNS.Transport.request_path` (every ~3s, regardless of what
   `has_path` says — `has_path` can be true while `recall` is still
   None) to nudge fwdsvc into responding with a fresh announce.
2. **Sleep ~3s after recall.** Even though we now have fwdsvc, fwdsvc
   may not have us yet. The 3s gives our own announce time to land
   on fwdsvc's side. Without this, the first command after a fresh
   start gets dropped silently for OPPORTUNISTIC sends (which don't
   retry on no-PROOF).

This matches what real clients experience. A real client sees the
same race; if the test were less flaky than real life, it'd be lying.

## xfail mechanism

A test case file named `*_xfail.py` is expected to fail today. The
harness reports it as `SKIP — xfail` rather than failing the run. The
suffix is the only thing carrying that meaning — no separate config.

Workflow:

1. Author a case for a path that's currently broken.
2. Save it as `mything_xfail.py`. The harness skips it.
3. Fix the underlying bug.
4. Rename to drop the `_xfail` suffix. The harness now treats failure
   as a real test failure.

This pattern keeps the harness in lock-step with what's actually
shipping: a regression that re-breaks `mything` is now a CI failure
rather than a forever-skip.

## Components

### `harness_test.go` (Go, build tag `interop`)

Generic responsibilities:

- Verify prereqs (`rnsd`, `python`, `RNS`, `LXMF`); skip with clear
  message if missing.
- Pick a free TCP port on 127.0.0.1.
- Write rnsd config; spawn rnsd; wait for it to listen.
- Per-case: write SUT config; spawn SUT; parse delivery hash; spawn
  Python case with `--rnsd` + `--fwdsvc` args; assert exit 0 within
  case timeout.
- On any failure (within parent or any subtest), dump captured rnsd /
  SUT output to test log so the failure is debuggable.

fwdsvc-specific responsibilities (callouts for porting):

- `requireFwdsvc()` runs `go build ./cmd/fwdsvc` — replace with the
  build command for your service.
- `writeFwdsvcConfig()` writes a fwdsvc-style TOML config — replace
  with your service's config shape.
- `fwdsvcDeliveryRe` parses the line `delivery destination : <hex>`
  out of fwdsvc's stdout — replace with a regex against whatever line
  your service uses to publish its LXMF destination hash.

### `cases/_common.py` (Python)

Generic LXMF client scaffolding. The `Peer` class handles:

- RNS init against the harness rnsd (writes its own RNS config).
- Identity creation + LXMF.LXMRouter setup.
- Delivery-destination registration + announce.
- `wait_for_fwdsvc()` — recall + path? loop + post-recall settle.
- `send_cmd()` — wrap a string as an LXMessage.
- `wait_for_reply()` — block until the inbox has a message satisfying
  a caller-supplied match function.

This file is reusable as-is for any LXMF service. The only thing it
"knows" about the SUT is the destination hash, passed in via
`--fwdsvc`.

### `cases/*.py`

Each case is a single self-contained Python script. Convention:

- Takes `--rnsd <host:port>` + `--fwdsvc <hex>` + optional
  `--timeout`.
- Uses `_common.parse_args()` and `_common.Peer()` to remove
  boilerplate.
- Prints `[case] ...` lines so the orchestrator-captured stdout tells
  the story of what the case did when it fails.
- Returns 0 on success, non-zero on failure (the harness asserts the
  exit code).

### `run.sh` / `run.ps1`

Thin wrappers around `go test -tags=interop -v ./tests/interop/...`.
Their main job is to set CWD to repo root and pass through filter
args.

### `.github/workflows/interop.yml`

CI runs the harness on Ubuntu against pinned Python + RNS + LXMF.
Triggers: push to main, PRs to main, manual dispatch.

## Extending the harness

### Adding a case

1. Drop a Python script into `cases/`.
2. Use the `_common.Peer` helper for boilerplate.
3. Run `bash tests/interop/run.sh -run TestHarness/<name>` to iterate
   on it before pushing.

### Preloading SUT state per case

Today each case starts with an empty SUT (fresh state.json). Some
tests need a populated state — e.g., to test "what happens when the
roster has 50 users and someone runs `/users`."

Recommended pattern (not yet implemented):

- A sidecar file `cases/<name>.preload.json` is copied into the SUT's
  state dir before `spawnFwdsvc` boots it.
- The case asserts behavior given that preloaded state.

### Multiple SUT instances

For tests that need two services talking to each other (e.g., two
fwdsvcs federating), spawn additional SUT subprocesses. The rnsd
already routes between any clients that connect to it.

## What you'd change to extract this for another service

If you wanted to lift `tests/interop/` out into a standalone repo:

1. **Replace `requireFwdsvc()` and `writeFwdsvcConfig()`** with the
   build + config commands for your service.
2. **Update `fwdsvcDeliveryRe`** to match whatever startup-log line
   your service uses to publish its delivery hash.
3. **Rewrite the cases** to exercise your service's commands and
   protocols.
4. **Keep `_common.py` mostly as-is** — it's already generic.
5. **Pin RNS / LXMF versions** in your CI workflow that match what
   your service was written against.

The harness pattern itself — orchestrator + shared transport +
per-case fresh SUT + Python clients — works for any LXMF service. The
fwdsvc bits are isolated to the three call-outs above.

## Limitations

- **Loopback only.** Doesn't catch real-network artifacts (jitter,
  packet loss, NAT, partial transport availability). We compensate with
  conservative announce-settle timing and recommend supplemental
  manual testing against a real public transport before releases.
- **One Python version.** CI pins Python 3.12 and the latest RNS +
  LXMF. Compatibility with older RNS / LXMF requires explicit matrix
  expansion.
- **Subprocess startup cost.** Each case takes ~10s end-to-end (RNS
  warmup + announce settle + actual work). Acceptable for a once-per-
  push test but not for inner-loop development; for that, prefer the
  in-process Go tests.

## See also

- `tests/interop/README.md` — user-facing how-to-run docs.
- `internal/rns/testdata/resource_interop/` — byte-level wire-format
  fixtures generated by upstream RNS, separate from this harness.
- `tests/interop/interop_test.go` — older byte-level interop tests
  (pre-harness). These still run under the same `interop` build tag
  and exercise the announce + LXMF wire format byte-for-byte.
