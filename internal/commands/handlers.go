package commands

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/config"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/roster"
)

// Role of the sender invoking a command. Computed from config (admins/mods)
// at dispatch time.
type Role int

const (
	RoleUser Role = iota
	RoleMod
	RoleAdmin
)

func (r Role) atLeastMod() bool { return r == RoleMod || r == RoleAdmin }

// Dispatcher dispatches parsed commands. It's stateless apart from the
// references it holds; safe to share across the inbox goroutine.
type Dispatcher struct {
	Cfg    *config.Config
	Roster *roster.Roster
}

// Dispatch returns the reply to send back to the sender. An empty string
// means "no reply" (we currently always reply, but this leaves room).
func (d *Dispatcher) Dispatch(senderHash string, parsed Parsed) string {
	role := d.role(senderHash)
	switch parsed.Name {
	case "?", "help":
		return helpText()
	case "users":
		return d.listUsers()
	case "mods":
		return d.listConfigList("mods", d.Cfg.Mods)
	case "admin", "admins":
		return d.listConfigList("admins", d.Cfg.Admins)
	case "nick":
		return d.handleNick(senderHash, role, parsed.Args)
	case "kick":
		return d.handleKick(role, parsed.Args)
	case "ban":
		return d.handleBan(role, parsed.Args)
	case "unban":
		return d.handleUnban(role, parsed.Args)
	default:
		return fmt.Sprintf("unknown command /%s — try /?", parsed.Name)
	}
}

func (d *Dispatcher) role(senderHash string) Role {
	switch {
	case d.Cfg.IsAdmin(senderHash):
		return RoleAdmin
	case d.Cfg.IsMod(senderHash):
		return RoleMod
	default:
		return RoleUser
	}
}

func helpText() string {
	return strings.Join([]string{
		"Commands:",
		"  /? or /help                 — this message",
		"  /users                      — list members",
		"  /mods                       — list mods",
		"  /admin                      — list admins",
		"  /nick <newname>             — change your nickname",
		"  /nick <user> <newname>      — (mods/admins) change another user's nickname",
		"  /kick <user>                — (mods/admins) remove user; they can rejoin",
		"  /ban <user>                 — (mods/admins) ban; future messages dropped",
		"  /unban <user>               — (mods/admins) lift a ban",
		"<user> = nickname or hex hash prefix (>=4 chars)",
	}, "\n")
}

func (d *Dispatcher) listUsers() string {
	users := d.Roster.List()
	if len(users) == 0 {
		return "No users."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Users (%d):\n", len(users))
	for _, u := range users {
		nick := u.Nickname
		if nick == "" {
			nick = "(no nick)"
		}
		fmt.Fprintf(&b, "  %s — %s\n", nick, u.Hash[:8])
	}
	return strings.TrimRight(b.String(), "\n")
}

func (d *Dispatcher) listConfigList(label string, hashes []string) string {
	if len(hashes) == 0 {
		return fmt.Sprintf("No %s configured.", label)
	}
	sorted := append([]string(nil), hashes...)
	sort.Strings(sorted)
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%d):\n", titleCase(label), len(sorted))
	for _, h := range sorted {
		nick := ""
		if u, ok := d.Roster.Get(h); ok && u.Nickname != "" {
			nick = u.Nickname
		}
		if nick != "" {
			fmt.Fprintf(&b, "  %s — %s\n", nick, h[:8])
		} else {
			fmt.Fprintf(&b, "  %s\n", h[:8])
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

var nickRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,24}$`)

func (d *Dispatcher) handleNick(senderHash string, role Role, args []string) string {
	switch len(args) {
	case 1:
		newNick := args[0]
		if !nickRE.MatchString(newNick) {
			return "Nickname must be 1-24 chars from [A-Za-z0-9_-]."
		}
		if !d.Roster.Has(mustHexBytes(senderHash)) {
			return "You aren't in the roster yet — send a message first."
		}
		if err := d.Roster.SetNickname(senderHash, newNick); err != nil {
			return "Couldn't change nickname: " + err.Error()
		}
		return "Nickname set to " + newNick + "."
	case 2:
		if !role.atLeastMod() {
			return "Only mods or admins can change someone else's nickname."
		}
		target, err := d.Roster.Resolve(args[0])
		if err != nil {
			return err.Error()
		}
		newNick := args[1]
		if !nickRE.MatchString(newNick) {
			return "Nickname must be 1-24 chars from [A-Za-z0-9_-]."
		}
		if err := d.Roster.SetNickname(target.Hash, newNick); err != nil {
			return "Couldn't change nickname: " + err.Error()
		}
		return fmt.Sprintf("Set %s's nickname to %s.", target.Hash[:8], newNick)
	default:
		return "Usage: /nick <newname>   or   /nick <user> <newname>"
	}
}

func (d *Dispatcher) handleKick(role Role, args []string) string {
	if !role.atLeastMod() {
		return "Only mods or admins can kick."
	}
	if len(args) != 1 {
		return "Usage: /kick <user>"
	}
	target, err := d.Roster.Resolve(args[0])
	if err != nil {
		return err.Error()
	}
	removed, err := d.Roster.Remove(target.Hash)
	if err != nil {
		return "Couldn't kick: " + err.Error()
	}
	if !removed {
		return fmt.Sprintf("%s was not in the roster.", target.Hash[:8])
	}
	label := target.Nickname
	if label == "" {
		label = target.Hash[:8]
	}
	return fmt.Sprintf("Kicked %s. They can rejoin by sending a message.", label)
}

func (d *Dispatcher) handleBan(role Role, args []string) string {
	if !role.atLeastMod() {
		return "Only mods or admins can ban."
	}
	if len(args) != 1 {
		return "Usage: /ban <user>"
	}
	target, err := d.Roster.Resolve(args[0])
	if err != nil {
		return err.Error()
	}
	if err := d.Roster.Ban(target.Hash); err != nil {
		return "Couldn't ban: " + err.Error()
	}
	label := target.Nickname
	if label == "" {
		label = target.Hash[:8]
	}
	return fmt.Sprintf("Banned %s. Their messages will be dropped.", label)
}

func (d *Dispatcher) handleUnban(role Role, args []string) string {
	if !role.atLeastMod() {
		return "Only mods or admins can unban."
	}
	if len(args) != 1 {
		return "Usage: /unban <user>"
	}
	hash := strings.ToLower(strings.TrimSpace(args[0]))
	// Banlist holds full hashes only; accept full hex match against the banlist.
	for _, h := range d.Roster.Banlist() {
		if h == hash {
			ok, err := d.Roster.Unban(h)
			if err != nil {
				return "Couldn't unban: " + err.Error()
			}
			if ok {
				return "Unbanned " + h[:8] + "."
			}
		}
	}
	// Allow prefix match across banlist for convenience.
	var matches []string
	for _, h := range d.Roster.Banlist() {
		if strings.HasPrefix(h, hash) {
			matches = append(matches, h)
		}
	}
	switch len(matches) {
	case 0:
		return fmt.Sprintf("%s is not banned.", hash)
	case 1:
		ok, err := d.Roster.Unban(matches[0])
		if err != nil {
			return "Couldn't unban: " + err.Error()
		}
		if ok {
			return "Unbanned " + matches[0][:8] + "."
		}
		return "Unbanned."
	default:
		return fmt.Sprintf("%q matches multiple banned users: %s", hash, strings.Join(shortHashes(matches), ", "))
	}
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	c := s[0]
	if c >= 'a' && c <= 'z' {
		c -= 'a' - 'A'
	}
	return string(c) + s[1:]
}

func shortHashes(hs []string) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		if len(h) >= 8 {
			out[i] = h[:8]
		} else {
			out[i] = h
		}
	}
	return out
}

// mustHexBytes converts a hex hash to bytes; the roster API takes bytes,
// but at the command layer we already have hex. For Has() lookups we
// convert here. Returns nil on bad hex (only happens for malformed source
// hashes, which never get this far).
func mustHexBytes(h string) []byte {
	if len(h) != 32 {
		return nil
	}
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		hi := hexNibble(h[2*i])
		lo := hexNibble(h[2*i+1])
		if hi < 0 || lo < 0 {
			return nil
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out
}

func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}
