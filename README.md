# reticulum-forwarding-service (`fwdsvc`)

A Reticulum/LXMF group-chat relay written in pure Go, with no third-party
Reticulum library — implements the protocol layers we need directly from
[the spec](https://github.com/thatSFguy/reticulum-specifications) and
verifies wire-format correctness against the upstream Python `rns` + `LXMF`
reference implementation.

Users send LXMF messages to this service and it forwards each message to
every other roster member, creating a many-to-many group chat. Designed to
run unattended on small Linux hardware: Debian, Raspberry Pi (arm64/armv7),
x86_64.

## Behaviour

- **Join by sending a message.** The first non-command message from a new
  Reticulum identity adds them to the roster.
- **Replay on join.** New (and returning) members receive the most recent
  messages so they can pick up the conversation. Defaults: last 100 messages,
  nothing older than 7 days.
- **Auto-prune.** Members whose Reticulum identity hasn't announced in
  4 weeks are removed.
- **Slash commands** for moderation:

  | Command                   | Who          | Effect                                                            |
  |---------------------------|--------------|-------------------------------------------------------------------|
  | `/?` or `/help`           | anyone       | List commands                                                     |
  | `/users`                  | anyone       | List roster                                                       |
  | `/mods`                   | anyone       | List mods                                                         |
  | `/admin`                  | anyone       | List admins                                                       |
  | `/nick <newname>`         | anyone       | Change own nickname                                               |
  | `/nick <user> <newname>`  | mods, admins | Change another user's nickname                                    |
  | `/kick <user>`            | mods, admins | Remove from roster (user can rejoin by sending another message)   |
  | `/ban <user>`             | mods, admins | Add to banlist; future messages dropped                           |
  | `/unban <user>`           | mods, admins | Remove from banlist                                               |

  `<user>` accepts a nickname (case-insensitive) or an identity-hash prefix
  (>=4 hex chars).

## Limitations

The implementation is intentionally minimal — just enough Reticulum + LXMF
to run a leaf-node group-chat hub. If any of these matter for your
deployment, the service won't fit as-is.

### Message size

- **Opportunistic single-packet delivery only.** Messages must fit in one
  Reticulum DATA packet. After Token cipher overhead (32 + 16 + 32 = 80
  bytes), LXMF body framing (16 + 64 ≈ 96 bytes), msgpack overhead, and
  the underlying interface MTU, you have **roughly 250–400 bytes of
  message body**. Longer messages **fail to send** — they don't fall back
  to link-based delivery, they just error out.
- **Forwarded messages add a `[nickname] ` prefix**, eating ~10–25 bytes
  off the recipient's view of the limit.
- **No fragmentation / Reticulum Resource transfer.** SPEC §10 resource
  fragmentation isn't implemented.

### Transport

- **Only one interface type: `tcp_client`.** We dial out to a TCP
  Reticulum peer and exchange HDLC-framed packets. **No LoRa / RNode
  serial, no UDP, no AutoInterface (LAN multicast), no I2P.** A Pi with
  a real LoRa modem will need to run upstream `rnsd` alongside `fwdsvc`
  and let `fwdsvc` connect to `rnsd` over TCP.
- **No transit relay.** We don't forward third-party packets. Other
  Reticulum nodes can't route through us.
- **No HEADER_2 originator conversion** (SPEC §2.3). Outbound packets
  always use HEADER_1; multi-hop delivery relies on the receiving
  `rnsd` auto-filling the transport_id, which only works for 0/1-hop
  destinations. A peer 2+ hops away may not receive our messages.
- **No automatic reconnect.** If the TCP interface drops, the service
  logs and continues; you have to restart it. (Use systemd `Restart=on-failure`.)

### LXMF features deferred

- **No link-based delivery.** Messages requiring an established Reticulum
  Link (anything over the size limit, or any peer on a high-latency path
  where opportunistic timeouts) won't work.
- **No propagation node / store-and-forward.** If a recipient is offline
  when a message is forwarded to them, the message is **lost from their
  perspective**. Replay-on-join only kicks in for users joining or
  rejoining after a kick/prune — it does not cover daily reachability
  gaps. Long-offline-then-online is not handled.
- **No ratchets / forward secrecy.** Every Token-encrypted message uses
  the recipient's long-term X25519 key. If the long-term key is later
  compromised, all past messages are decryptable. We accept and ignore
  the `ratchet_pub` field on inbound announces; we never rotate our own.
- **No stamps / proof-of-work anti-spam.** SPEC §5.7 stamps are not
  enforced (we accept everything) and not generated (peers requiring
  stamp-cost > 0 will silently reject our outbound LXMF). Our own
  announces declare `stamp_cost = 0`.
- **No tickets** (the pre-shared shortcut around stamp PoW).
- **No msgpack `fields` content.** Outbound messages always carry an
  empty fields dict. Inbound parsing accepts and discards any fields
  present. So no attachments, stickers, embedded LXMs, or telemetry
  on either direction.

### Identity / trust

- **Trust on first announce (TOFU).** The first signed announce we hear
  from any destination is taken at face value. SPEC §4.5 step 4 then
  rejects subsequent attempts to override the public key for that
  destination — so you can't be silently MitM'd after the first contact,
  but the first contact has no out-of-band verification.
- **Lost identities cannot recover the same destination.** Per SPEC, a
  user who loses their identity material gets a different identity_hash
  on regeneration → different destination_hash → effectively a new
  user from our perspective. Their old roster entry will eventually
  prune; their new one is a fresh join.
- **Senders MUST announce before messaging.** We can't decrypt to a
  recipient whose public key we haven't heard, and we can't verify a
  signature from a sender whose Ed25519 pub we haven't cached. A peer
  whose first packet is an LXMF (no prior announce) will be rejected.

### Service design

- **Single chat room.** No multi-room support. One process, one roster.
- **No runtime promotion.** `[admins]` and `[mods]` are config-file only.
  No `/promote` command. Edit the file and restart to change.
- **No DM support.** Every non-command message is forwarded to the entire
  roster. No private message paths.
- **No edit / delete.** Forwarded messages are immutable; a sender cannot
  retract or amend.

## Build

Requires Go 1.26 or newer.

If you don't have Go installed yet:

- **Windows:** download the `.msi` from https://go.dev/dl/ and run it.
  After install, open a fresh PowerShell and confirm `go version` works.
- **Debian / Ubuntu:** `sudo apt install golang-go` (check version is >= 1.26;
  if not, install from https://go.dev/dl/).
- **Raspberry Pi:** prefer cross-compiling from a development machine.

First-time build:

```sh
go mod tidy
go build -o fwdsvc ./cmd/fwdsvc
go test ./...
```

Cross-compile for Raspberry Pi:

```sh
GOOS=linux GOARCH=arm64 go build -o fwdsvc-arm64 ./cmd/fwdsvc        # Pi 4/5
GOOS=linux GOARCH=arm GOARM=7 go build -o fwdsvc-armv7 ./cmd/fwdsvc  # Pi 2/3/Zero 2
```

Or use `scripts/build-rpi.sh`.

## Run

1. Copy `configs/fwdsvc.example.toml` to `~/.fwdsvc/config.toml` and edit:
   - Set `display_name` to whatever you want users to see in announces.
   - Set at least one `[[interfaces]]` entry with `type = "tcp_client"`
     pointing at a reachable Reticulum peer (e.g.
     `amsterdam.connect.reticulum.network:4965` for the public testnet, or
     a local `rnsd` if you're running one).
   - Add the identity hash of at least one admin to `admins = [...]`.
     (You can run the service once first, copy the printed identity hash,
     then add it.)
2. Run it:

   ```sh
   ./fwdsvc -config ~/.fwdsvc/config.toml
   ```

   On first run the service generates its identity at `identity_path` and
   prints its destination hash on stdout. Share that hash with the people
   who should be able to message the service.

This service does **not** read `~/.reticulum/config` — it implements the
Reticulum protocol itself, so the `[[interfaces]]` block in
`config.toml` is the entire interface config.

## Storage layout

Default state directory is `~/.fwdsvc/`:

| File           | Purpose                                                   |
|----------------|-----------------------------------------------------------|
| `config.toml`  | The config file (you create this).                        |
| `identity`     | The service's 64-byte Reticulum identity (do not share).  |
| `state.json`   | Roster + banlist.                                         |
| `history.json` | Recent-message ring buffer for replay-on-join.            |

## Verification

The implementation is checked at two levels:

- **Static byte-level test vectors** — `go test ./...` includes tests
  that load the canonical Python `rns` 1.2.0 / `LXMF` 0.9.6 wire-byte
  vectors from `../reticulum-specifications/test-vectors/{identities,
  announces,lxmf}.json` and assert byte-exact equality on identity
  derivation, announce build (with and without ratchet), Token
  decrypt, and LXMF body build. Tests skip cleanly if the spec
  sibling repo isn't present.

- **Live subprocess interop** — `go test -tags=interop ./tests/interop/...`
  spawns a Python helper that drives upstream `rns` + `LXMF` directly
  and exchanges fresh announce + opportunistic-LXMF bytes with the Go
  code in **both directions**. Requires `pip install rns lxmf` (rns
  >= 1.2.0, LXMF >= 0.9.6) and `python` on PATH. Skips otherwise.

## License

MIT.
