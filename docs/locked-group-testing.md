# Locked-group test runbook

Test plan for the invite-only ("locked") group feature on the
`feature/locked-group` branch, to validate it before release.

> **Note:** the daemon has no local console for commands. Every command
> (`/adduser`, `/removeuser`, …) arrives as an LXMF message, so the
> operator issues them from their **own** chat client whose delivery hash
> is listed in `admins`.

## What you need

- The `feature/locked-group` build:
  ```
  git checkout feature/locked-group
  go build -o fwdsvc ./cmd/fwdsvc
  ```
- **Two** LXMF clients (Sideband / NomadNet / MeshChat):
  - **Operator client** — the config admin issuing invites.
  - **Tester client** — the outsider trying to get in.

## One-time setup

1. Start the daemon once with your normal config and message it from the
   **operator client**. In the daemon log, find:
   `new sender contact: full dest_hash = <32 hex chars>` — that's your
   operator/admin address.
2. Edit the config. **`admins` must be at the very top, before any
   `[section]` header:**
   ```toml
   admins = [ "<operator dest_hash from step 1>" ]

   [service]
   display_name = "Test Group"
   locked = true
   # ...rest unchanged
   ```
3. Restart the daemon. The log should show it running with your
   identity / destination hash.

## Admins/mods are auto-enrolled

Config `admins`/`mods` are added to the roster automatically at startup, so
they **receive** group messages — being an admin grants command powers, and
enrollment makes them a participant too. The startup log shows
`auto-enrolled N config admin/mod(s) as members`. It's idempotent (existing
members keep their nickname/pause state). To moderate **without** receiving
the message firehose, an admin uses `/pause` (stays a member, keeps powers,
receives nothing). An admin who `/leave`s is re-enrolled on the next restart
— remove them from the config for a permanent opt-out.

## Test checklist

| # | Action | Expected result |
|---|--------|-----------------|
| 1 | **Tester** sends `/join` | Refused: *"This is a closed group — you need to be invited. Give an admin your address to be added:"* followed by the tester's own 32-hex hash. Tester is **not** added. |
| 2 | Tester copies that hash and sends it to you out-of-band | (You now have the tester's address.) |
| 3 | **Operator** sends `/adduser <tester hash>` | Reply: *"Added `<8hex>` and sent them a welcome."* (or *"…they'll be welcomed once we hear from them."* if the daemon hasn't heard the tester yet — after step 1 it usually has). |
| 4 | Watch the **tester** client | Receives *"You've been added to Test Group. Send /? for help, /leave to exit."* plus any recent history replay. |
| 5 | Tester sends a normal chat message | It's forwarded to other members (they're a full member now). |
| 6 | **Operator** sends `/removeuser <tester hash or nick>` | Reply: *"Removed `<label>`. They can't rejoin until an admin runs /adduser."* |
| 7 | **Tester** sends `/join` again | Refused with the same closed-group bounce — confirms removal blocks re-entry while locked. |
| 8 | **Operator** re-adds with `/adduser`, tester confirms welcome again | Re-invite works. |

## Negative / guardrail checks

| # | Action | Expected |
|---|--------|----------|
| 9 | **Tester** (a non-admin) sends `/adduser <somehash>` | *"Only mods or admins can add users."* |
| 10 | **Operator** sends `/adduser not-a-hash` | *"That doesn't look like a valid address — expected 32 hex characters."* |
| 11 | **Operator** `/adduser` the same tester twice | Second time: *"`<8hex>` is already in the group."* |
| 12 | **Operator** `/ban` a user, then `/adduser` that same hash | *"`<8hex>` is banned. /unban them first, then /adduser."* |
| 13 | Confirm **you (config admin) can still `/join`** while locked | You're admitted — proves an operator can't lock themselves out. |

## Behind the scenes to verify

- **Prune exemption / persistence:** after step 3 (before the tester ever
  speaks), open `state.json` — the tester's entry should have
  `"invited": true`. After the tester sends any message/command (step 5)
  it should flip to absent/false. Restart the daemon between those and
  confirm the flag survives.
- **Deferred welcome:** for a stronger test of step 3's second variant,
  `/adduser` a brand-new hash the daemon has *never* heard from (a fresh
  identity that hasn't announced). The operator reply should be *"…welcomed
  once we hear from them"*, and the welcome should arrive later once that
  client announces / messages.

## Release decision

Ship only if:

- locked `/join` is reliably refused (1, 7),
- invites deliver the welcome **and** replay (3–5),
- removal blocks re-entry (6–7),
- you can't lock yourself out (13).

If the deferred-welcome case is flaky over your transport, that's a
delivery/path issue to note — the invite still succeeds, only the
greeting is delayed.
