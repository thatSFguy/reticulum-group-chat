# reticulum-forwarding-service (`fwdsvc`)

A Reticulum/LXMF group-chat relay written in pure Go. Users send LXMF
messages to the service and it forwards each message to every other
roster member, creating a many-to-many group chat over any
Reticulum-supported transport.

- **No third-party Reticulum library.** Implements the protocol
  layers we need directly from
  [the spec](https://github.com/thatSFguy/reticulum-specifications).
- **Verified against upstream Python `rns` + `LXMF`** at the byte level
  (static test vectors plus a live subprocess interop test).
- **Live-tested end-to-end** with a mobile LXMF client over a public
  Reticulum testnet entry node.
- **Single static binary** that runs unattended on small Linux
  hardware (Debian, Raspberry Pi arm64/armv7), x86_64 servers,
  Windows, or macOS.

## Quick start

1. **Download a pre-built binary** from
   [the latest release](https://github.com/thatSFguy/reticulum-forwarding-service/releases/latest)
   for your platform (linux-amd64, linux-arm64, linux-armv7, windows-amd64,
   darwin-arm64). On Linux/macOS, `chmod +x fwdsvc-…`.

2. **Make a config dir** and copy the example config:

   ```sh
   mkdir -p ~/.fwdsvc
   curl -L https://raw.githubusercontent.com/thatSFguy/reticulum-forwarding-service/main/configs/fwdsvc.example.toml \
     -o ~/.fwdsvc/config.toml
   ```

3. **Edit `~/.fwdsvc/config.toml`** — set `display_name`, point at a
   reachable Reticulum peer in `[[interfaces]]`, leave `admins = []`
   for now (we'll add yours below). The example config is annotated.

4. **Run it once** to generate an identity:

   ```sh
   ./fwdsvc -config ~/.fwdsvc/config.toml
   ```

   The first lines on stdout will be:

   ```
   fwdsvc 1.2.0 starting (linux/amd64)
   fwdsvc 2026/05/06 16:00:00 interface tcp_client connected: …
   fwdsvc 2026/05/06 16:00:00 service identity hash: 359fc3967f984a529874d0960c6ee782
   fwdsvc 2026/05/06 16:00:00 delivery destination : 4c87fb86ccfdff39a3d1e22060ba1789
   ```

   The **delivery destination** (second hash) is what people will
   message in their LXMF client. Share that with your group.

5. **Add yourself as admin.** From your LXMF client (Sideband, your
   own mobile-app, etc.) send the service a message — anything will
   do. Watch the log; you'll see:

   ```
   new sender contact: full dest_hash = 0b0501efed0844bb064bc6df4cba43bb
   ```

   Stop the service (Ctrl-C), put that 32-character hex string into
   `admins` in `config.toml`, and restart. You're now an admin.

   ```toml
   admins = [
     "0b0501efed0844bb064bc6df4cba43bb",
   ]
   ```

6. **From the LXMF client send `/join`** to opt in. Then `/?` to see
   your commands. Your friends do the same against the same delivery
   destination hash and they're all in the chat.

## Behaviour

- **Explicit `/join`** — first non-command message from a new sender
  gets a private invitation reply explaining the service. The message
  is **not** forwarded and the sender is **not** added to the roster
  until they explicitly send `/join`. Avoids the "I sent one test
  message and now strangers are getting it" UX.
- **Replay on join.** New (and returning) members receive the most
  recent buffered messages so they can pick up the conversation.
  Defaults: last 100 messages, nothing older than 7 days. Configurable.
- **Pause without leaving.** A member can `/pause` to stop receiving
  forwarded messages (their own messages also stop being forwarded
  while paused). `/resume` reverses it. The roster entry stays put.
- **Per-message char cap** (`service.max_inbound_chars`, default 500)
  rejects oversized non-command messages with a polite reply, separate
  from the lower wire-format size limit.
- **Auto-prune.** Members whose Reticulum identity hasn't announced or
  messaged in 4 weeks are removed.
- **Forwarded content sanitised.** Bytes outside the printable +
  whitespace range (TAB/LF/CR) are replaced with `?` before forwarding,
  so a sender can't inject ANSI escape sequences that would mess up
  receivers' terminal displays.
- **Outbound retry queue.** Every outbound message goes through a
  persistent queue that mirrors LXMF's `LXMRouter.process_outbound`
  retry policy: up to 5 attempts at 10-second intervals (≈50 s total
  budget), with a 7-second `path?`-backed defer when the recipient
  hasn't announced yet. A single packet collision on a half-duplex
  segment no longer drops the message, and the queue persists to
  `outbound.json` so a service restart resumes pending sends rather
  than losing them. See
  [`flows/lxmf-outbound-retry.md`](https://github.com/thatSFguy/reticulum-specifications/blob/master/flows/lxmf-outbound-retry.md)
  in the spec repo for the upstream-equivalent state machine this
  mirrors.
- **Announce cache survives restart.** Verified announces (peer
  public key + transport_id + last_seen) persist to `announces.json`,
  so after a restart every previously-known peer is immediately
  addressable instead of waiting up to one `announce_interval`
  (10 minutes default) for them to re-announce. Entries older than
  30 days are dropped at load time.

## Commands

The `/?` reply is **role-aware** — non-members only see commands that
work for them, mods see the moderation set.

| Command                   | Who          | Effect                                                            |
|---------------------------|--------------|-------------------------------------------------------------------|
| `/?` or `/help`           | anyone       | List commands available to you                                    |
| `/users`                  | anyone       | List roster (paused members marked `[paused]`)                    |
| `/mods`                   | anyone       | List configured mods                                              |
| `/admin`                  | anyone       | List configured admins                                            |
| `/join`                   | non-members  | Opt in: receive forwarded messages, your messages get forwarded   |
| `/leave`                  | members      | Leave the chat (you can `/join` again later)                      |
| `/pause`                  | members      | Stop receiving forwarded messages (and stop forwarding yours)     |
| `/resume`                 | members      | Reverse `/pause`                                                  |
| `/nick <newname>`         | members      | Change own nickname (1–24 chars from `[A-Za-z0-9_-]`)             |
| `/nick <user> <newname>`  | mods, admins | Change another user's nickname                                    |
| `/kick <user>`            | mods, admins | Remove from roster (user can `/join` again)                       |
| `/ban <user>`             | mods, admins | Add to banlist; future `/join`s and messages refused              |
| `/unban <user>`           | mods, admins | Remove from banlist                                               |
| `/announce`               | mods, admins | Broadcast a fresh Reticulum announce immediately                  |

`<user>` accepts a nickname (case-insensitive) or a destination-hash
prefix (≥4 hex chars).

## Configuration

The config is a single TOML file. Default location is
`~/.fwdsvc/config.toml`; override with `-config <path>`.

```toml
# admins / mods are LXMF DESTINATION hashes (16 raw bytes / 32 hex
# chars, the lxmf.delivery destination hash of the user's identity —
# NOT the raw identity hash).
#
# Find a user's destination hash: have them send the service ANY
# message. The forwarder logs `new sender contact: full dest_hash =
# <32 hex chars>` on first contact. Copy that into the list and
# restart.
#
# IMPORTANT: admins / mods MUST be at the TOP of the file, before any
# [section] header — TOML scopes top-level keys to whichever section
# is currently active, so admins/mods after a section get silently
# parsed under that section instead of at the root.
admins = [
  # "0b0501efed0844bb064bc6df4cba43bb",   # your dest_hash here
]
mods = [
  # "ffeeddccbbaa99887766554433221100",
]

[service]
# Shown in our LXMF announces. Visible to all Reticulum nodes.
display_name = "Group Chat - send /join"

# Where the service stores its identity, roster, and replay buffer.
# Tilde is expanded.
identity_path = "~/.fwdsvc/identity"
state_path    = "~/.fwdsvc/state.json"
history_path  = "~/.fwdsvc/history.json"
# Optional: append the daemon's stdout log to a file too. Useful for
# troubleshooting (records every inbound command, every reply, and any
# truncation events). Empty/unset = stdout only.
log_path      = "~/.fwdsvc/fwdsvc.log"

# Drop a member from the roster if we haven't heard an announce or
# message from them in this long. Defaults to 4 weeks.
prune_after = "4w"

# How often to run the prune sweep.
prune_interval = "1h"

# How often to re-broadcast our own announce so other Reticulum
# nodes can learn / refresh our path. Upstream Python rnsd uses
# 5–15 minutes; 30s is fine for a small relay.
announce_interval = "10m"

# Maximum number of UTF-8 characters allowed in an inbound non-
# command message. Anything longer is rejected with a polite reply
# and not forwarded. Spam-prevention policy limit, separate from the
# lower wire-format size cap (~280 bytes after [nick] prefix).
# Set to 0 to disable.
max_inbound_chars = 500

# Maximum number of members in the chat. /join attempts past this cap
# are refused with a "the chat is full" reply. Existing and paused
# members both count toward the limit. 0 = unlimited (default).
max_members = 0

[[interfaces]]
# How fwdsvc reaches the rest of the Reticulum mesh. We currently
# only support tcp_client (dial out to a TCPServerInterface peer).
# The peer can be a community-run testnet node, your own rnsd, or
# any other reachable Reticulum endpoint.
type = "tcp_client"
addr = "rns.michmesh.net:7822"
# Optional dial timeout; 0 = stdlib default (~30s).
timeout = "10s"

# Multiple interfaces are supported — fwdsvc broadcasts on all of
# them. Useful if you want both a community testnet node and a local
# rnsd you're running.
#[[interfaces]]
#type = "tcp_client"
#addr = "10.0.0.42:4242"

[replay]
# When a new (or returning) user joins, replay this many recent
# messages to them, skipping anything older than max_age. Set
# count = 0 to disable replay entirely.
count   = 100
max_age = "7d"
```

### Setting admins and mods (step-by-step)

The friction here is that you need each admin/mod's **destination
hash**, which only their LXMF client knows. The simplest workflow:

1. Start `fwdsvc` with `admins = []`.
2. Have the prospective admin send the service a message from their
   LXMF client (any message — they'll get a "Welcome…/join" invitation
   back, that's expected on first contact).
3. The forwarder logs:
   ```
   fwdsvc 2026/05/06 14:24:11 new sender contact: full dest_hash = 0b0501efed0844bb064bc6df4cba43bb
   ```
4. Stop the service (Ctrl-C). Add the hex string to `admins` (or `mods`):
   ```toml
   admins = [
     "0b0501efed0844bb064bc6df4cba43bb",
   ]
   ```
5. Restart. The admin now sees mod commands in `/?` and can `/announce`,
   `/kick`, `/ban`, etc.

To **remove** an admin/mod, edit the config and restart. Admin/mod
membership is config-only on day one — there's no `/promote` runtime
command (avoidable but explicit by design — config edits are auditable).

### Storage layout

Default state directory is `~/.fwdsvc/`:

| File             | Purpose                                                          |
|------------------|------------------------------------------------------------------|
| `config.toml`    | The config file (you create this).                               |
| `identity`       | The service's 64-byte Reticulum identity (do not share).         |
| `state.json`     | Roster + banlist. Atomic writes; safe across crashes.            |
| `history.json`   | Recent-message ring buffer for replay-on-join.                   |
| `outbound.json`  | Pending outbound messages — queue with attempt counters and next-attempt timestamps so retries survive restarts. |
| `announces.json` | Cached `KnownIdentity` per peer (public key + `transport_id` + `last_seen`) so a restart doesn't have to wait for re-announces. Entries older than 30 days are dropped at load. |

## Wire-format features implemented

These are the parts of the Reticulum / LXMF stack the service speaks.
Every item below has at least one of: a static byte-level test vector
against canonical Python output, a passing live subprocess interop
test against `rns 1.2.0` + `LXMF 0.9.6`, or a confirmed live round-trip
with a third-party LXMF client.

- **Identity** — X25519 + Ed25519 keypair, on-disk format, identity_hash
  and destination_hash derivation (SPEC §1).
- **Token cipher** — AES-256-CBC + HMAC-SHA256 + HKDF-SHA256 with the
  `identity_hash` salt gotcha (SPEC §3).
- **Packet header** — HEADER_1 / HEADER_2 codec including the
  hashable-part rule that makes proofs survive HEADER_1↔HEADER_2 in
  flight (SPEC §2).
- **HDLC framing** — for `tcp_client` interfaces (SPEC §8.2).
- **Announce** — build, parse, verify (with and without ratchet),
  including the SPEC §9.3 msgpack `bin`-vs-`str` gotcha for
  `app_data`.
- **Opportunistic LXMF** — full sign / encrypt / decrypt / verify in
  both directions, including SPEC §5.6 dual-msgpack-variant tolerance.
- **PROOF emission** (SPEC §6.5) — every inbound CTX_NONE DATA at a
  SINGLE destination is acknowledged with a 64-byte implicit-form
  proof so senders' `PacketReceipt`s resolve.
- **Path requests** (SPEC §7.1) — when a sender we can't verify
  contacts us, we issue a `path?` broadcast; a path-aware relay's
  path-response announce gives us their public key. Per-target 60 s
  dedup window with periodic sweep.
- **HEADER_2 originator conversion** (SPEC §2.3) — outbound DATA to a
  multi-hop recipient is HEADER_2 with the cached next-hop transport_id
  so it can actually reach them.
- **Receive-side Reticulum Link** (SPEC §6) — full LINKREQUEST /
  LRPROOF handshake (byte-exact against the spec test vector),
  ECDH+HKDF session keys, link-form Token cipher, link-DATA framing,
  SPEC §6.5.6 explicit-form 96-byte link PROOFs. This means peers can
  send us LXMF longer than the ~280-byte opportunistic cap and we'll
  parse and surface them. (Send-side link selection, KEEPALIVE, and
  link expiry are still TODO.)

## Limitations

The implementation is intentionally minimal — just enough Reticulum +
LXMF to run a leaf-node group-chat hub. Notable gaps:

- **Forwarder routes opportunistic + Link automatically.** Short
  messages (≤ ~280 bytes content) ship in a single Token-encrypted
  Reticulum DATA packet (opportunistic, fire-and-forget). Longer
  messages fall through to a per-recipient Reticulum Link send: we
  open the link lazily, send the LXMF body in direct form, and block
  for the responder's link DATA proof. Idle links auto-close after
  15 minutes; KEEPALIVE packets fire every 4 minutes to keep busy
  links alive on the responder side. Multi-hop responders are reached
  via HEADER_2 LINKREQUEST + transport_id from their announce. Long
  list replies (e.g. `/users` against a large roster) return the full
  list — they ride the same opportunistic-or-Link routing as forwarded
  messages, so size is no longer a constraint. The truncation helper
  still exists for callers that want a per-command cap (set
  `Dispatcher.MaxReplyContentBytes`); production wiring leaves it at
  0 = unlimited.
- **Single TCP interface type** — `tcp_client` only. No LoRa /
  RNode-serial, no UDP, no AutoInterface (LAN multicast), no I2P. A
  Pi with a real LoRa modem will need to run upstream `rnsd`
  alongside `fwdsvc` and connect `fwdsvc` to `rnsd` over TCP.
- **No transit relay.** We don't forward third-party packets; we're
  a leaf node only.
- **No automatic reconnect.** If the TCP interface drops, the service
  logs and continues; you have to restart it (use systemd
  `Restart=on-failure`).
- **No ratchets / forward secrecy.** Long-term X25519 key is used for
  every Token cipher. Future-key compromise means past messages are
  decryptable.
- **No stamps / proof-of-work anti-spam.** Peers requiring stamps
  silently reject our outbound LXMF.
- **No fields** (attachments, stickers, embedded LXMs, telemetry).
  Inbound `fields` parsed and discarded; outbound is always empty.

## Verification

Three increasingly strong levels of test:

```sh
# 1. Default unit + spec test vectors. Static byte-level equality
#    against canonical Python rns 1.2.0 / LXMF 0.9.6 vectors loaded
#    from ../reticulum-specifications/test-vectors/ (skipped cleanly
#    if the spec sibling repo isn't checked out).
go test ./...

# 2. Live Python subprocess interop. Spawns a Python helper that
#    drives upstream rns + LXMF directly and exchanges fresh
#    announce + opportunistic-LXMF bytes with the Go code in BOTH
#    directions. Requires `pip install rns lxmf` and `python` on
#    PATH. Skipped otherwise.
go test -tags=interop ./tests/interop/...
```

Plus a **live mesh interop check** during development: the service was
run against a community-run testnet entry node (`rns.michmesh.net`,
`rns.chicagonomad.net`) and exercised end-to-end with a mobile LXMF
client — announce propagation, opportunistic LXMF send, PROOF
emission, path-request resolving an unannounced sender, and `/?`
round-tripping back to the mobile UI.

## Build from source

Requires Go 1.26 or newer.

```sh
git clone https://github.com/thatSFguy/reticulum-forwarding-service
cd reticulum-forwarding-service
go mod tidy
go build -o fwdsvc ./cmd/fwdsvc
go test ./...
```

Cross-compile for every supported platform:

```sh
./scripts/build-all.sh
ls -lh build/
```

## Running as a systemd service

A minimal `fwdsvc.service`:

```ini
[Unit]
Description=Reticulum forwarding service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=fwdsvc
ExecStart=/usr/local/bin/fwdsvc -config /etc/fwdsvc/config.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Adjust paths in `config.toml` (`identity_path`, `state_path`,
`history_path`) accordingly — `~/` won't expand under a system user
without `$HOME`.

## License

MIT.

## Contributing

This implementation tracks
[the canonical Reticulum/LXMF spec](https://github.com/thatSFguy/reticulum-specifications)
directly. Wire-format changes should reference the relevant SPEC.md
section number in the commit message and either include a static test
vector or pass live interop. See the local `AGENTS.md` (gitignored)
for the full contributor / agent rules.

Issues that find a discrepancy between this implementation and
upstream Python `rns` / `LXMF`: please cite the upstream source
file:line and a runtime reproduction in the report.
