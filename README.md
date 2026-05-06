# reticulum-forwarding-service (`fwdsvc`)

A Reticulum/LXMF group-chat relay. Users send LXMF messages to this service and
the service forwards each message to every other roster member, creating a
many-to-many group chat over any Reticulum-supported transport (LoRa, TCP,
packet radio, I2P, ...).

Designed to run unattended on small Linux hardware: Debian, Raspberry Pi
(arm64/armv7), x86_64.

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

Optional: live interop test against upstream Python `rns` + `LXMF`. Requires
`pip install rns lxmf` (rns >= 1.2.0, LXMF >= 0.9.6) and `python` on PATH.
Exchanges live announce + opportunistic-LXMF bytes with a Python subprocess
in both directions:

```sh
go test -tags=interop ./tests/interop/...
```

Cross-compile for Raspberry Pi:

```sh
GOOS=linux GOARCH=arm64 go build -o fwdsvc-arm64 ./cmd/fwdsvc        # Pi 4/5
GOOS=linux GOARCH=arm GOARM=7 go build -o fwdsvc-armv7 ./cmd/fwdsvc  # Pi 2/3/Zero 2
```

Or use `scripts/build-rpi.sh`.

## Run

1. Make sure Reticulum is configured (`~/.reticulum/config` with at least one
   interface). If you've never run Reticulum before, install `rnsd` or
   `nomadnet` once and let it generate the default config.
2. Copy `configs/fwdsvc.example.toml` to `~/.fwdsvc/config.toml` and edit:
   - Set `display_name` to whatever you want users to see in announces.
   - Add the identity hash of at least one admin (yours, probably) to
     `[admins]`.
3. Run it:

   ```sh
   ./fwdsvc -config ~/.fwdsvc/config.toml
   ```

   On first run the service generates its identity at `identity_path` and
   prints its destination hash on stdout. Share that hash with the people
   who should be able to message the service.

## Storage layout

Default state directory is `~/.fwdsvc/`:

| File           | Purpose                                          |
|----------------|--------------------------------------------------|
| `config.toml`  | The config file (you create this).               |
| `identity`     | The service's Reticulum identity (do not share). |
| `state.json`   | Roster + banlist.                                |
| `history.json` | Recent-message ring buffer for replay-on-join.   |

## License

MIT.
