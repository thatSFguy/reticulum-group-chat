# Multi-group example: 2 public + 2 private

Four independent chats on one machine, one `fwdsvc` process per config:

| Config | Group | Mode |
|---|---|---|
| `group-a-public.toml`  | Group A | public (anyone can `/join`) |
| `group-b-public.toml`  | Group B | public |
| `group-c-private.toml` | Group C | private (`locked = true` + `admins`) |
| `group-d-private.toml` | Group D | private |

**The rule that makes them separate groups:** each config has its own
`identity_path`, `state_path`, and `history_path`. Sharing any of those
between two instances makes them the same destination and duplicates every
message. They may share the same upstream `[[interfaces]]` peer.

## Run them (systemd)

Place the four files in `/etc/fwdsvc/` and use the templated unit from the
README's "Running multiple groups in parallel" section
(`/etc/systemd/system/fwdsvc@.service`, which runs
`fwdsvc -config /etc/fwdsvc/%i.toml`):

```sh
sudo systemctl enable --now \
  fwdsvc@group-a-public \
  fwdsvc@group-b-public \
  fwdsvc@group-c-private \
  fwdsvc@group-d-private

sudo journalctl -u fwdsvc@group-c-private -f   # confirm: "locked (invite-only): true"
```

## Or run them by hand

```sh
fwdsvc -config group-a-public.toml &
fwdsvc -config group-b-public.toml &
fwdsvc -config group-c-private.toml &
fwdsvc -config group-d-private.toml &
```

`pgrep -af fwdsvc` should list exactly four processes. Don't wrap these in a
restart script that starts a new instance without killing the old one —
that's the classic way to end up with duplicate/echoed messages (fwdsvc will
now refuse the duplicate start, but the orphan still needs cleaning up).

## Before first start

- **Private groups:** put your client's LXMF destination hash in the
  `admins` list at the top of `group-c-private.toml` /
  `group-d-private.toml`. Config admins are auto-enrolled and bypass the
  lock, so you won't lock yourself out. Invite others with `/adduser <hash>`.
- **All groups:** replace the `addr` in `[[interfaces]]` with your Reticulum
  peer (a community node or a local `rnsd`). On first run each instance
  generates its own identity and logs its `delivery destination` hash — that
  hash is what members point their client at.
