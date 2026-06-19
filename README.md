# reticulum-forwarding-service (`fwdsvc`)

**A Reticulum group chat.** `fwdsvc` is a small daemon that hosts a
multi-user text chat over the [Reticulum
Network](https://reticulum.network), using [LXMF](https://github.com/markqvist/LXMF)
for message delivery. Each chat is one running service. Anyone with the
service's destination hash can `/join`, send messages, and have them
fanned out to every other member — a many-to-many group chat over
whatever Reticulum transport(s) you have available (LoRa, TCP/IP, your
own mesh, etc.).

If you've used IRC, Matrix, or Telegram groups, the user experience is
similar. The difference is that the chat travels over Reticulum, so it
works on radios with no Internet, can be relayed across mixed
LoRa+TCP+I2P meshes, and the operator is just one person running this
binary on a Pi.

- **No third-party Reticulum library.** Pure-Go implementation of the
  protocol layers we need, written directly against
  [the spec](https://github.com/thatSFguy/reticulum-specifications).
- **Verified against upstream Python `rns` + `LXMF`** at the byte level
  (static test vectors plus a live subprocess interop harness running
  on CI).
- **Live-tested end-to-end** with Sideband, NomadNet, and MeshChat over
  public Reticulum testnet entry nodes.
- **One static binary** — runs unattended on a Raspberry Pi, a Debian
  server, macOS, or Windows. No runtime, no Python, no daemon zoo.

---

## Table of contents

1. [What this is, and how it works](#what-this-is-and-how-it-works)
2. [Features](#features)
3. [Install and first run](#install-and-first-run)
4. [Commands](#commands)
5. [Configuration reference](#configuration-reference)
6. [Deployment recipes](#deployment-recipes)
7. [Operations](#operations)
8. [Wire-format support](#wire-format-support)
9. [Limitations](#limitations)
10. [Build from source](#build-from-source)
11. [Project info](#project-info)

---

## What this is, and how it works

Reticulum gives every participant a cryptographic **identity** — a
keypair stored in a small file. From the identity you derive a
**destination hash**, a 16-byte address other peers route to. Reticulum
**announces** propagate destination → identity bindings across the
mesh so anyone in range can encrypt to anyone else.

LXMF rides on top of Reticulum: signed, encrypted, store-and-forward
messages addressed to a destination hash, deliverable opportunistically
(one Reticulum packet) or over a Reticulum **Link** for larger payloads.

`fwdsvc` is one LXMF endpoint that behaves like a chatroom:

```
┌──────────┐                ┌──────────┐                ┌──────────┐
│ Alice    │   /join, msg   │ fwdsvc   │   forwarded    │ Bob      │
│ Sideband │ ─────────────▶ │ daemon   │ ─────────────▶ │ NomadNet │
└──────────┘                │          │                └──────────┘
                            │ roster:  │
┌──────────┐                │  Alice   │                ┌──────────┐
│ Carol    │   /join, msg   │  Bob     │   forwarded    │ Dave     │
│ MeshChat │ ─────────────▶ │  Carol   │ ─────────────▶ │ Sideband │
└──────────┘                │  Dave    │                └──────────┘
                            └──────────┘
```

- Each message Alice sends to the daemon's destination hash is
  forwarded to every other member of the roster, prefixed with
  `[Alice] ` so receivers see who said what.
- The daemon never sees plaintext from any peer except via its own
  identity's decryption, and it re-encrypts per recipient on the way
  out — same trust model as any LXMF peer.
- Joining is by sending `/join`. Roster membership is auto-pruned for
  anyone who's been silent (no announce, no message) for four weeks by
  default.

### Glossary

| Term | Meaning |
|---|---|
| **Identity** | 64-byte X25519 + Ed25519 keypair on disk (or in `service.identity_b64`). Lost identity = lost destination hash = your roster has to re-add you. |
| **Destination hash** | 16-byte / 32-hex-char address. The thing your users put in their LXMF client to message the service. |
| **Announce** | A signed broadcast that teaches the mesh "destination `D` belongs to identity `I`, reachable via these hops." `fwdsvc` re-announces itself every `announce_interval` (default 10 min). |
| **Roster** | The set of members. Living in `state.json`. |
| **Replay** | When a new member joins, the daemon ships them the most recent N messages so they can pick up the conversation. |
| **Opportunistic / Link / Resource** | The three LXMF delivery paths, picked automatically by payload size. See [Wire-format support](#wire-format-support). |

---

## Features

- **Explicit `/join`** opt-in. A first message from a stranger gets a
  private invitation reply, not a forward. Avoids the "I sent one test
  message and now strangers are getting it" UX.
- **Default nickname from announces.** A member with no nickname set
  picks one up automatically from their announced display name,
  sanitised to `[A-Za-z0-9_-]{1,24}` (`"Bob & Alice"` → `"Bob_Alice"`;
  all-emoji collapses to empty and stays unset). Applied at `/join`
  time and on every subsequent announce until a nickname exists, so a
  user who joined before their first announce arrived still gets named
  once it does. `/nick` is authoritative: once set, announces never
  overwrite.
- **Replay on join.** New (and returning) members receive the most
  recent buffered messages so they can read the prior conversation.
  Defaults: last 100 messages, nothing older than 7 days. Configurable.
- **Pause without leaving.** A member can `/pause` to stop receiving
  (and sending) forwards while staying on the roster. `/resume` reverses.
- **Per-message char cap** (`max_inbound_chars`, default 500). Oversize
  non-command messages get a polite reject reply and aren't forwarded.
- **Auto-prune.** Members silent for `prune_after` (default 4 weeks)
  are removed automatically; they can `/join` again any time.
- **Forwarded content sanitised.** Bytes outside printable + TAB/LF/CR
  become `?` before forwarding — no ANSI-escape injection into other
  users' terminals.
- **Outbound retry queue.** Every outbound message goes through a
  persistent queue mirroring LXMF's `LXMRouter.process_outbound`
  policy: 5 attempts at 10-second intervals, 7-second `path?`-backed
  defer when the recipient hasn't announced. Survives restarts via
  `outbound.json`. Drained by a 4-worker pool so a slow send to one
  recipient doesn't block command replies to others. Picker
  prioritises by recipient recency (peers we just heard announce go
  first).
- **Announce cache survives restart.** Verified announces persist to
  `announces.json` — after a restart, every previously-known peer is
  immediately addressable instead of waiting up to one
  `announce_interval` for them to re-announce. Entries older than
  30 days are dropped at load time.
- **Three LXMF delivery paths, picked automatically.**
  Opportunistic (one packet, fire-and-forget) for small replies; Link
  DATA (one Token-framed packet over a Reticulum Link) for medium
  payloads; SPEC §10 Resource transfer for anything bigger (long
  `/users` replies on big rosters, long chat messages, etc.).
- **Mod / admin moderation.** Config-file `admins` and `mods` lists
  get `/kick`, `/ban`, `/unban`, `/announce`, `/path`, and the
  cross-user form of `/nick`.
- **Bind-once identity.** Embed your identity in `config.toml` via
  `identity_b64` and the config file is the single source of truth —
  reinstall on any machine, same destination hash, same chat for
  everyone.
- **Self-healing TCP interface.** `tcp_client` interfaces auto-redial
  with capped exponential backoff after any drop (peer restart, NAT
  timeout, transient network failure). TCP keepalive on dialed sockets
  surfaces silent peer drops within ~2 minutes instead of waiting for
  the next outbound write to fail. The service does not need to be
  restarted after an upstream blip.

---

## Install and first run

### 1. Get the binary

[Download the latest release](https://github.com/thatSFguy/reticulum-forwarding-service/releases/latest)
for your platform:

| Asset | Target |
|---|---|
| `fwdsvc-linux-amd64`       | x86_64 Linux (Debian/Ubuntu/etc.) |
| `fwdsvc-linux-arm64`       | ARM64 Linux (RPi 4/5 64-bit, most ARM SBCs) |
| `fwdsvc-linux-armv7`       | 32-bit ARMv7 (RPi 2/3 32-bit) |
| `fwdsvc-linux-armv6`       | 32-bit ARMv6 (RPi Zero, RPi 1) |
| `fwdsvc-darwin-arm64`      | Apple Silicon macOS |
| `fwdsvc-windows-amd64.exe` | x86_64 Windows |

On Linux/macOS, `chmod +x fwdsvc-…` after download.

Or [build from source](#build-from-source).

### 2. Make a config

```sh
mkdir -p ~/.fwdsvc
curl -L https://raw.githubusercontent.com/thatSFguy/reticulum-forwarding-service/main/configs/fwdsvc.example.toml \
  -o ~/.fwdsvc/config.toml
```

Open `~/.fwdsvc/config.toml` and edit:

- `display_name` — what your service shows in its announces. Visible
  to every Reticulum node it reaches.
- `[[interfaces]]` `addr` — a reachable Reticulum peer to dial. A
  community testnet node (`rns.chicagonomad.net:4242`,
  `rns.michmesh.net:7822`, etc.) works for getting started; for
  production you'd point at a local `rnsd` you control or your own
  TCP-attached gateway.
- Leave `admins = []` for now; you'll add yourself in step 4.

### 3. Run it once to generate an identity

```sh
./fwdsvc -config ~/.fwdsvc/config.toml
```

First lines on stdout:

```
fwdsvc 1.3.6 starting (linux/amd64)
fwdsvc 2026/05/11 16:00:00 interface tcp_client connected: rns.chicagonomad.net:4242
fwdsvc 2026/05/11 16:00:00 service identity hash: 359fc3967f984a529874d0960c6ee782
fwdsvc 2026/05/11 16:00:00 delivery destination : 4c87fb86ccfdff39a3d1e22060ba1789
fwdsvc 2026/05/11 16:00:00 display name        : My Group Chat
```

The **delivery destination** (second hash) is the address your users
will message in their LXMF client. Share that with your group — it's
the chat's stable identifier.

### 4. Add yourself as admin

From your LXMF client (Sideband on phone, NomadNet on desktop,
MeshChat, etc.) send the service any short message. The forwarder will
log:

```
new sender contact: full dest_hash = 0b0501efed0844bb064bc6df4cba43bb
```

Stop the service (Ctrl-C), put that 32-character hex string in
`admins`, and restart:

```toml
admins = [
  "0b0501efed0844bb064bc6df4cba43bb",
]
```

> **Important:** `admins` and `mods` MUST be top-level keys in
> `config.toml`, before any `[section]` header. TOML scopes top-level
> keys to whichever section is currently active, so putting them after
> `[service]` silently makes them `service.admins`.

### 5. Join from your client

From your LXMF client, send `/join` to the daemon's delivery
destination. You'll get a confirmation reply and from now on every
forwarded message from other members lands in your inbox.

Send `/?` to see the commands available to you (admins see the full
moderation set).

Your friends do the same against the same delivery destination, and
they're all in the chat.

---

## Commands

`/?` (or `/help`) replies are **role-aware** — non-members only see
commands that work for them, mods see the moderation set, admins see
everything.

### User commands

| Command | Who | Effect |
|---|---|---|
| `/?` or `/help`           | anyone      | List commands available to you |
| `/about` or `/version`    | anyone      | Show version and repo URL |
| `/users`                  | anyone      | List roster (paused members marked `[paused]`) |
| `/mods`                   | anyone      | List configured mods |
| `/admin`                  | anyone      | List configured admins |
| `/join`                   | non-members | Opt in: receive forwarded messages, your messages get forwarded |
| `/leave`                  | members     | Leave the chat (you can `/join` again later) |
| `/pause`                  | members     | Stop receiving forwards (and stop forwarding yours) |
| `/resume`                 | members     | Reverse `/pause` |
| `/textonly`               | members     | Skip attachments — receive only the text body of forwarded messages. Intended for users on slow / metered links. |
| `/showall`                | members     | Reverse `/textonly` — resume receiving attachments. |
| `/nick <newname>`         | members     | Change own nickname (1–24 chars from `[A-Za-z0-9_-]`) |

### Mod / admin commands

| Command | Who | Effect |
|---|---|---|
| `/nick <user> <newname>`  | mods, admins | Change another user's nickname |
| `/kick <user>`            | mods, admins | Remove from roster (user can `/join` again) |
| `/ban <user>`             | mods, admins | Add to banlist; future `/join`s and messages refused |
| `/unban <user>`           | mods, admins | Remove from banlist |
| `/announce`               | mods, admins | Broadcast a fresh Reticulum announce immediately |
| `/path <user>`            | mods, admins | Show what the transport knows about reaching `<user>`: cached announce age, hop count, next-hop transport_id, whether an Active Link is open. Mostly for troubleshooting delivery problems. |

`<user>` accepts a **nickname** (case-insensitive) or a
**destination-hash prefix** (≥ 4 hex chars). When two members would
match the prefix, the daemon refuses with a disambiguation reply.

### Examples

```
> /join
Joined. You'll receive forwarded messages from now on. /pause to mute,
/leave to exit, /? for help.

> /nick Alice
Nickname set to Alice.

> /users
Users (3):
  Alice — 0b0501ef
  Bob — ffeeddcc
  (no nick) — 1234abcd

> Hi everyone!
(message fans out to Bob and the unnicked user with prefix `[Alice] Hi everyone!`)
```

---

## Configuration reference

The config is a single TOML file. Default location is
`~/.fwdsvc/config.toml`; override with `-config <path>`.

### Root-level keys

| Key | Type | Default | Description |
|---|---|---|---|
| `admins` | array of hex strings | `[]` | Destination hashes of admins. Get all the mod commands. |
| `mods`   | array of hex strings | `[]` | Destination hashes of mods. Get the moderation commands minus admin-only ones. |

Both lists MUST be declared at the top of the file, before any
`[section]` header.

### `[service]`

| Key | Type | Default | Description |
|---|---|---|---|
| `display_name`       | string   | `"Group Chat - send /join"` | Shown in announces. |
| `identity_path`      | path     | `~/.fwdsvc/identity`        | Where the service's identity is stored. Ignored if `identity_b64` is set. |
| `identity_b64`       | string   | unset                       | Base64 of the 64-byte identity. When set, this is authoritative and `identity_path` is ignored. See [Identity backup](#identity-backup). |
| `state_path`         | path     | `~/.fwdsvc/state.json`      | Roster + banlist. |
| `history_path`       | path     | `~/.fwdsvc/history.json`    | Replay ring buffer. |
| `log_path`           | path     | unset                       | If set, append the daemon log to this file (in addition to stdout). |
| `prune_after`        | duration | `"4w"`                      | Drop a member who's been silent (no announce, no message) for this long. |
| `prune_interval`     | duration | `"1h"`                      | How often the prune sweep runs. |
| `announce_interval`  | duration | `"10m"`                     | How often we re-announce ourselves. |
| `max_inbound_chars`  | int      | `500`                       | Reject non-command messages longer than this many UTF-8 chars. `0` disables. |
| `max_members`        | int      | `0`                         | Cap on roster size. `/join` past the cap is refused. `0` = unlimited. |
| `forward_attachments`| bool     | `true`                      | Pass LXMF non-text fields (images, etc.) through forwarding. `false` drops all attachments silently. |
| `max_attachment_bytes`| int     | `32768`                     | Per-field msgpack size cap. Oversize attachments are dropped with an inline `[image not forwarded: …]` note; text body still delivers. `0` disables the cap. |
| `forwarded_fields`   | int list | `[6, 48, 49, 64, 65, 66]`   | Allowlist of LXMF field keys to forward when `forward_attachments=true`. Default covers `FIELD_IMAGE` (6) plus the upstream LXMF 1.0.0 message-meta fields: reply-to (`FIELD_REPLY_TO 0x30`=48 message-id, `FIELD_REPLY_QUOTE 0x31`=49 quoted text), tap-back reactions (`FIELD_REACTION 0x40`=64), comments (`FIELD_COMMENT 0x41`=65), and continuations (`FIELD_CONTINUATION 0x42`=66). Add `5` for files, `7` for audio once your senders/receivers handle them. |
| `id_cache_ttl`       | duration | `24h`                       | How long fwdsvc remembers each fan-out's per-recipient LXMF `message_id` so reactions and reply-to fields can be rewritten per recipient (v1.6.0+). `0` disables — reactions then show "[someone reacted]" without landing on a bubble. Going longer just grows memory; each cache entry is ~50 bytes × roster size. |
| `id_cache_max`       | int      | `10000`                     | Hard cap on `id_cache_ttl` entry count (LRU evicts oldest). One fan-out to N recipients counts as N entries. `0` = unbounded. |

Durations are Go `time.ParseDuration` plus `d` (days) and `w`
(weeks): `"30s"`, `"5m"`, `"24h"`, `"7d"`, `"4w"`.

### `[[interfaces]]`

Repeated table — one entry per Reticulum I/O interface. Currently only
`tcp_client` is supported.

| Key | Type | Default | Description |
|---|---|---|---|
| `type`    | string   | required | `"tcp_client"`. |
| `addr`    | string   | required | `host:port` of a `TCPServerInterface` peer to dial. |
| `timeout` | duration | `"0"`    | Dial timeout. `0` = stdlib default (~30 s). |

```toml
[[interfaces]]
type    = "tcp_client"
addr    = "rns.chicagonomad.net:4242"
timeout = "10s"

[[interfaces]]
type = "tcp_client"
addr = "10.0.0.42:4242"   # your own rnsd on the LAN
```

`fwdsvc` broadcasts on **all** interfaces; redundancy is fine.

### `[replay]`

| Key | Type | Default | Description |
|---|---|---|---|
| `count`   | int      | `100` | Max messages replayed when a member joins (or rejoins). `0` disables replay entirely. |
| `max_age` | duration | `"7d"` | Skip messages older than this in replay. |

---

## Deployment recipes

### Linux + systemd (recommended)

1. Put the binary in `/usr/local/bin/fwdsvc` and `chmod 755` it.
2. Create a system user:
   ```sh
   sudo useradd --system --home /var/lib/fwdsvc --create-home --shell /usr/sbin/nologin fwdsvc
   ```
3. Put `config.toml` at `/etc/fwdsvc/config.toml`. Make sure
   `identity_path`, `state_path`, `history_path` all point under
   `/var/lib/fwdsvc/` (e.g. `/var/lib/fwdsvc/identity`) — `~/`
   doesn't expand under a system user.
4. Drop this in `/etc/systemd/system/fwdsvc.service`:
   ```ini
   [Unit]
   Description=Reticulum forwarding service (group chat)
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   User=fwdsvc
   Group=fwdsvc
   ExecStart=/usr/local/bin/fwdsvc -config /etc/fwdsvc/config.toml
   Restart=on-failure
   RestartSec=5
   # Optional hardening:
   NoNewPrivileges=true
   ProtectSystem=strict
   ProtectHome=true
   ReadWritePaths=/var/lib/fwdsvc
   PrivateTmp=true

   [Install]
   WantedBy=multi-user.target
   ```
5. Enable and start:
   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now fwdsvc
   sudo journalctl -u fwdsvc -f
   ```

### Raspberry Pi

Same as Linux + systemd. Pick the right binary for your Pi:

- Pi 4/5 with 64-bit OS → `fwdsvc-linux-arm64`
- Pi 2/3 with 32-bit OS → `fwdsvc-linux-armv7`
- Pi Zero / Pi 1 → `fwdsvc-linux-armv6`

If you have a real LoRa modem (RNode, etc.), run upstream
[`rnsd`](https://github.com/markqvist/Reticulum) alongside `fwdsvc`
with the radio attached, and point `fwdsvc` at `rnsd` via
`tcp_client → 127.0.0.1:4242`. `fwdsvc` doesn't speak serial / LoRa
directly — `rnsd` is the radio half.

### Windows

`fwdsvc-windows-amd64.exe` runs the same way:

```powershell
.\fwdsvc-windows-amd64.exe -config "$env:USERPROFILE\.fwdsvc\config.toml"
```

For unattended startup, register it with **Task Scheduler** to run on
boot as a specific user (Action = "Start a program", Program =
`fwdsvc-windows-amd64.exe`, Arguments = `-config ...\config.toml`,
Trigger = "At startup", Settings = "Restart on failure"). Or use NSSM
to install it as a Windows service if you prefer that workflow.

### macOS

Either a launchd `plist` in `~/Library/LaunchAgents/` or just running
under a `tmux`/`screen` session. The binary is the same Mach-O
universal-ish format; allow it through Gatekeeper the first time:
`xattr -d com.apple.quarantine fwdsvc-darwin-arm64`.

### Identity backup

If you redeploy to a different machine and only carry `config.toml`
over, you'd lose the service's identity — and therefore its
destination hash — without it. To make `config.toml` self-sufficient:

1. Run `fwdsvc` once. It writes `~/.fwdsvc/identity.b64.txt` (mode
   0600) on first-run identity generation. Same secrecy class as the
   identity file itself.
2. Open that file and copy the base64 string.
3. In `config.toml` under `[service]`:
   ```toml
   identity_b64 = "<paste here>"
   ```
4. Restart. The log will read:
   ```
   identity loaded from config (identity_b64); ignoring …/identity
   ```

After that, `config.toml` alone is enough to restore the service on
any machine — same identity, same destination hash, same chat for
every existing member.

---

## Operations

### State on disk

Everything lives in the directory whose paths you configured in
`[service]` (default `~/.fwdsvc/`):

| File                | Purpose | Backup-worthy? |
|---------------------|---------|---|
| `config.toml`       | Your config. Optionally embeds the identity. | **Yes** |
| `identity`          | Service identity (64 bytes). Lose it → lose your destination hash. | **Yes** (or use `identity_b64`) |
| `identity.b64.txt`  | Base64 form of `identity`, written on first-run for backup. | Yes |
| `state.json`        | Roster + banlist. Atomic writes. | Yes |
| `history.json`      | Replay ring buffer. | Optional (loss only affects replay-on-join) |
| `outbound.json`     | Pending outbound retries. | Optional (loss costs at most a few queued messages) |
| `announces.json`    | Cached peer paths. | No (regenerates from inbound announces) |
| `fwdsvc.log`        | If `log_path` is set, the rolling daemon log. | No |

### Logs

Without `log_path`, everything goes to stdout — let systemd journal
or your terminal absorb it. With `log_path`, both stdout and the
file get the same lines. Each log line is `RFC3339`-ish timestamped
to the microsecond. Examples worth recognising:

| Pattern | Meaning |
|---|---|
| `interface tcp_client connected: …`         | TCP interface up. |
| `announce verified (new\|returning): …`     | We learned a path to a peer. |
| `cmd from=<hash> name=/<cmd>`               | A command arrived. |
| `cmd reply queued: …`                       | The reply went onto the outbound queue. |
| `outbound: attempt N/5 to <hash> failed: …` | A delivery attempt failed; retrying. |
| `outbound: failing message id=… after 5 attempts: …` | Gave up after the retry budget. |
| `resource sender: ADV retry N/4 for <hash>` | Resource transfer's ADV phase is retrying because the receiver hasn't requested any parts yet. |
| `nick from announce: adopted "X" for …`     | Auto-defaulted a nickname from an inbound announce (v1.3.5+). |
| `tcp interface … disconnected: … — reconnecting` | Upstream TCP drop; supervisor will redial with backoff (v1.3.6+). |
| `tcp interface … reconnected`               | Reconnect succeeded; interface is live again (v1.3.6+). |

### Scaling and resource use

A few load-related facts worth knowing before you grow the roster past
a few dozen — none are currently a problem at typical sizes but they
shape what you'd notice first if you pushed harder:

- **Outbound queue depth scales linearly with active roster.** Each
  inbound chat message produces one `outbound.json` entry per active
  (non-paused) recipient. A 60-member roster + one message in flight =
  up to ~59 pending entries. They drain promptly when recipients are
  reachable; an unreachable recipient stays queued for up to
  `5 × 10s ≈ 50s` before the queue gives up.
- **Drain concurrency is fixed at 4 workers**, not scaled with roster
  size (`outboundWorkers` constant in `internal/service/outbound.go`).
  Four is enough that a slow send to one recipient doesn't head-of-line
  block the others. For very large rosters (hundreds of members) on a
  fast interface, raising the constant and rebuilding would speed up
  fan-out.
- **No upper bound on pending depth.** Nothing rejects new messages
  when the queue is long. In steady state the queue is bounded by chat
  cadence × the per-recipient retry window, not by anything explicit.
  Worth knowing if you ever script a flood through the relay.
- **`outbound.json` is rewritten on every `Enqueue`** — fanning out
  one message to N recipients does N full-file writes, each marshaling
  up to N entries (O(N²) in disk write volume per fan-out). Negligible
  at current sizes; the first thing that would need a batched-persist
  refactor if the roster grew toward several hundred.
- **Attachments are not persisted.** Per-message LXMF fields (e.g. a
  forwarded `FIELD_IMAGE`) live in memory only — a crash between
  enqueue and send drops the image but keeps the text body, which
  re-sends on restart. Acceptable degradation; sender can always
  resend.
- **History buffer is bounded** by `replay.count` (default 100). Older
  forwarded lines roll off when a new one is appended.

### Troubleshooting

**My users never see replies to `/users` (or other commands).** A
slow or stale path causes Link / Resource sends to time out. Try
`/announce` from an admin to push a fresh announce of the daemon
into the mesh, and have the affected user re-announce from their
client. Use `/path <user>` (admin) to see what the daemon knows
about reaching them — if `LinkActive=false` and the announce is
many hours old, the path is the problem, not `fwdsvc`. Restarting
the affected user's client usually re-announces it immediately.

**My users never see ANY messages from me.** Verify the daemon is
actually reaching the network: look for `interface tcp_client
connected` at startup, and `announce verified` lines (which mean
inbound traffic is flowing). If neither shows up after 30s, the
configured `[[interfaces]]` address isn't reachable from this host.

**`/join` worked but nothing forwards.** Check the sender isn't
paused (`/users` would show `[paused]`). Check the daemon log — if
a forward fails 5/5 times for a recipient, you'll see one
`failing message id=…` line and that recipient missed that message,
but the chat continues for everyone else.

**The destination hash changed after a redeploy.** You lost the
identity. Either restore the `identity` file or, better, set
`identity_b64` in `config.toml` so this can never happen again.

**Path table looks stale.** `rm ~/.fwdsvc/announces.json` and
restart — the cache will rebuild from live announces (cost: one
`announce_interval` of waiting for path discovery).

### Upgrading

1. Stop the service.
2. Replace the binary.
3. Start the service.

The on-disk state format is stable; new versions read older
`state.json`, `history.json`, `outbound.json`, `announces.json`
files. If a future release ever breaks compatibility it'll be called
out in the release notes.

### Removing an admin or mod

There is no `/promote` or `/demote` runtime command — admin/mod
membership is config-only by design (auditable via `git diff`). Edit
`admins` or `mods` in `config.toml`, restart.

---

## Wire-format support

Below are the parts of the Reticulum / LXMF stack `fwdsvc` actually
speaks. Each one has at least one of: a static byte-level test
vector against canonical Python output, a passing live subprocess
interop test against `rns 1.2.0` + `LXMF 0.9.6`, or confirmed live
round-trip with a third-party LXMF client.

- **Identity** — X25519 + Ed25519 keypair, on-disk format, identity
  and destination hash derivation (SPEC §1).
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
  multi-hop recipient is HEADER_2 with the cached next-hop
  `transport_id`.
- **Reticulum Link** (SPEC §6) — full LINKREQUEST / LRPROOF handshake
  (byte-exact against the spec test vector), ECDH+HKDF session keys,
  link-form Token cipher, link-DATA framing, SPEC §6.5.6 explicit-form
  96-byte link PROOFs. Idle links auto-close after 15 min;
  KEEPALIVE every 4 min.
- **Resource transfer** (SPEC §10) — full sender and receiver. Send:
  link-encrypt the body, slice into raw-ciphertext parts, advertise
  via msgpack ADV, fulfill receiver-driven REQs, validate the
  receiver's RESOURCE_PRF in constant time. Receive: parse ADV,
  fetch parts, verify, decrypt. Up to 256 KiB / 74 parts per
  resource; inbound `c=1` (bz2-compressed) and `n>74` ADVs are
  rejected (bomb defense — see
  [`docs/resource-security-audit.md`](docs/resource-security-audit.md)).

Delivery-path selection is automatic: ≤ ~280 bytes is opportunistic,
≤ 431 bytes plaintext over a Reticulum Link is single-packet Link
DATA, anything bigger is Resource transfer over that same Link. So
long `/users` replies on a big roster ship the full list — size is
not a delivery constraint.

---

## Limitations

The implementation is intentionally minimal — just enough Reticulum +
LXMF to run a group-chat hub. Notable gaps:

- **Single TCP interface type** — `tcp_client` only. No LoRa /
  RNode-serial, no UDP, no AutoInterface (LAN multicast), no I2P. A
  Pi with a real LoRa modem will need to run upstream `rnsd`
  alongside `fwdsvc` and point `fwdsvc` at `rnsd` over TCP.
- **No transit relay.** `fwdsvc` is a leaf node — it doesn't forward
  third-party packets.
- **No automatic TCP reconnect.** If the configured `tcp_client`
  interface drops, the service logs and continues; you have to
  restart it. Use systemd `Restart=on-failure` (already in the
  recipe above).
- **No ratchets / forward secrecy.** Long-term X25519 key is used
  for every Token cipher. Future-key compromise means past messages
  are decryptable.
- **No stamps / proof-of-work anti-spam.** Peers that *require*
  stamps will silently reject our outbound LXMF.
- **Limited LXMF field support.** `FIELD_IMAGE` (6) and the upstream
  LXMF 1.0.0 message-meta fields — reply-to (`0x30`=48 + `0x31`=49),
  reactions (`FIELD_REACTION 0x40`=64), comments (`0x41`=65), and
  continuations (`0x42`=66) — are forwarded through group chat by
  default; `FIELD_FILE_ATTACHMENTS` (5) and `FIELD_AUDIO` (7) can
  be enabled per-operator via `forwarded_fields`. Stickers, embedded
  LXMs, telemetry, icon-appearance, and command fields are still
  parsed but discarded.
- **Reactions / reply-to lifetime.** Because the relay re-emits each
  forwarded message under its own identity, every recipient computes
  a different `message_id` for the same bubble — so cross-client
  reactions and replies need per-recipient rewriting. fwdsvc does
  this in-memory via a TTL cache (`id_cache_ttl`, default 24h), so
  reactions / replies to messages relayed within that window bind
  correctly on every other member's client. Past the TTL (or after a
  service restart, since the cache is not persisted) the binding
  falls back to legacy behavior — reactions don't render, replies
  show only their `fields[0x31]` quote preview.
- **No voice / audio.** Text-only. We register only the
  `lxmf.delivery` aspect — never `call.audio`. Some MeshChat users
  see a brief "incoming call" notification attributed to `fwdsvc`
  shortly after our announce. Audit on our side ruled out every
  code path that could possibly target a `call.audio` dest_hash;
  suspected upstream cause + diagnostic ask in
  [`docs/meshchat-call-codec-mismatch-issue.md`](docs/meshchat-call-codec-mismatch-issue.md).
  Not a `fwdsvc` bug.
- **IFAC packets rejected.** Packets with the IFAC flag set are
  refused at parse with `errIFACUnsupported`. Real IFAC support
  would require new interface config and is not on the roadmap.

---

## Build from source

Requires Go 1.26 or newer.

```sh
git clone https://github.com/thatSFguy/reticulum-forwarding-service
cd reticulum-forwarding-service
go mod tidy
go build -o fwdsvc ./cmd/fwdsvc
go test ./...
```

Cross-compile every release target into `build/`:

```sh
./scripts/build-all.sh
ls -lh build/
```

### Verification

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
#    PATH. Skipped otherwise. Also runs on CI on every push.
go test -tags=interop ./tests/interop/...
```

Plus a **live mesh interop check** during development: the service
runs against a community-run testnet entry node
(`rns.chicagonomad.net`, `rns.michmesh.net`) and is exercised
end-to-end with Sideband / NomadNet / MeshChat — announce
propagation, opportunistic LXMF send, PROOF emission, path-request
resolving an unannounced sender, Link + Resource delivery,
round-tripping back to the mobile UI.

---

## Project info

### License

MIT.

### Contributing

This implementation tracks
[the canonical Reticulum / LXMF spec](https://github.com/thatSFguy/reticulum-specifications)
directly. Wire-format changes should reference the relevant SPEC.md
section number in the commit message and either include a static test
vector or pass live interop.

Issues that find a discrepancy between this implementation and
upstream Python `rns` / `LXMF`: please cite the upstream
`file:line` and a runtime reproduction in the report.
