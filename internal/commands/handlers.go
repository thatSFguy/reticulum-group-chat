package commands

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/config"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/roster"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/version"
)

// Role of the sender invoking a command. RoleUser is the default —
// in-config admins/mods take precedence over membership state.
type Role int

const (
	RoleUser Role = iota
	RoleMod
	RoleAdmin
)

func (r Role) atLeastMod() bool { return r == RoleMod || r == RoleAdmin }

// Caller bundles everything a command handler needs to know about the
// sender: their hash (hex + bytes), their role from the config (user /
// mod / admin), whether they're currently in the roster (Member),
// whether they're paused, and whether they're on text-only delivery.
// Derived once per inbound command.
type Caller struct {
	Hash      string // lowercase hex
	HashBytes []byte
	Role      Role
	Member    bool
	Paused    bool
	TextOnly  bool
}

// PathInfo is the routing snapshot returned by Dispatcher.PathLookup.
// All fields zero-valued means "no announce cached for this destination."
// Used by the /path command so an operator (and the user themselves) can
// see exactly what the service knows about reaching a target — separates
// "we don't know about you yet" from "we know you but the path is bad."
type PathInfo struct {
	Known       bool      // true when an announce has been cached
	LastSeen    time.Time // wall-clock of the most recent verified announce
	Hops        int       // hop count at last announce
	NextHopHex  string    // hex of TransportID for multi-hop peers; "" when direct
	LinkActive  bool      // an Active outbound Link to this dest currently exists
}

// Dispatcher dispatches parsed commands. It's stateless apart from the
// references it holds; safe to share across the inbox goroutine.
type Dispatcher struct {
	Cfg    *config.Config
	Roster *roster.Roster

	// Announce, when set, is invoked by the /announce command to trigger
	// an immediate fresh announce broadcast. Mod/admin only.
	Announce func() error

	// PathLookup, when set, is invoked by the /path command to query the
	// transport for routing info on a target dest_hash (lowercase hex,
	// 32 chars). Returns PathInfo{Known:false} if the destination has
	// never announced. Mod/admin only — exposes routing topology.
	PathLookup func(destHashHex string) PathInfo

	// OnJoin is invoked AFTER a user successfully /joins so the service
	// layer can fire replay-on-join for them. Called with the joiner's
	// hex hash; safe to call from the dispatcher goroutine.
	OnJoin func(senderHash string)

	// LookupAnnouncedName, when set, returns the announced display name
	// for a 16-byte destination hash (from the LXMF app_data blob on
	// the peer's most recent verified announce), or an empty string if
	// no announce has been heard. /join uses this to default a fresh
	// member's nickname to their announced name — sanitized through
	// SanitizeNickname so it conforms to nickRE. Mods can /nick to
	// override later. No-op when the peer never announced a display
	// name or when the field is nil (e.g. unit tests).
	LookupAnnouncedName func(hashBytes []byte) string

	// MaxReplyContentBytes caps the byte length of a single command reply
	// so that, after msgpack wrapping in an opportunistic LXMF packet, it
	// still fits in the upstream single-packet limit (295 bytes msgpack —
	// see lxmf.MaxOpportunisticPayload). List replies (/users, /mods,
	// /admin, ambiguous-unban) are line-truncated with a "...and N more"
	// footer when over budget. 0 disables truncation (used by tests).
	MaxReplyContentBytes int

	// OverflowLog, when non-nil, is invoked with the full untruncated
	// reply text whenever a list reply would overflow MaxReplyContentBytes.
	// Lets the operator see the full list in the troubleshooting log even
	// though the user receives a truncated version.
	OverflowLog func(format string, args ...any)
}

// Dispatch handles a single command and returns the reply text. An empty
// return means "no reply" (we currently always reply, but this leaves
// room).
func (d *Dispatcher) Dispatch(senderHash string, parsed Parsed) string {
	caller := d.deriveCaller(senderHash)
	switch parsed.Name {
	case "?", "help":
		return helpText(caller)
	case "about", "version":
		return aboutText()
	case "users":
		return d.listUsers()
	case "mods":
		return d.listConfigList("mods", d.Cfg.Mods)
	case "admin", "admins":
		return d.listConfigList("admins", d.Cfg.Admins)
	case "join":
		return d.handleJoin(caller)
	case "leave":
		return d.handleLeave(caller)
	case "pause":
		return d.handlePause(caller)
	case "resume":
		return d.handleResume(caller)
	case "textonly":
		return d.handleTextOnly(caller)
	case "showall":
		return d.handleShowAll(caller)
	case "nick":
		return d.handleNick(caller, parsed.Args)
	case "kick":
		return d.handleKick(caller.Role, parsed.Args)
	case "ban":
		return d.handleBan(caller.Role, parsed.Args)
	case "unban":
		return d.handleUnban(caller.Role, parsed.Args)
	case "announce":
		return d.handleAnnounce(caller.Role)
	case "path":
		return d.handlePath(caller.Role, parsed.Args)
	default:
		// Echo the unknown command name back to the sender, but strip
		// non-printable bytes from it first. parsed.Name comes from
		// strings.Fields(content)[0] and is lowercased, but it can still
		// contain ESC, BEL, CSI, DEL, etc. — a sender could otherwise
		// inject ANSI sequences into their own reply, and any operator
		// reading the daemon log would also see them. Defense in depth.
		return fmt.Sprintf("unknown command /%s — try /?", scrubControlBytes(parsed.Name))
	}
}

func (d *Dispatcher) deriveCaller(senderHash string) *Caller {
	sh := strings.ToLower(senderHash)
	c := &Caller{Hash: sh, HashBytes: mustHexBytes(sh)}
	switch {
	case d.Cfg.IsAdmin(sh):
		c.Role = RoleAdmin
	case d.Cfg.IsMod(sh):
		c.Role = RoleMod
	default:
		c.Role = RoleUser
	}
	if c.HashBytes != nil {
		c.Member = d.Roster.Has(c.HashBytes)
	}
	if c.Member {
		if u, ok := d.Roster.Get(sh); ok {
			c.Paused = u.Paused
			c.TextOnly = u.TextOnly
		}
	}
	return c
}

// helpText is the /? and /help reply, tailored to the caller's role and
// membership so they only see commands they can actually use.
//
// MUST fit in a single opportunistic LXMF packet — the sender of /? has
// no chunked or link-based reply path. TestHelpTextFitsOpportunisticPacket
// guards the byte budget across all caller states.
// aboutText is the /about (and /version alias) reply. Plain
// version + repo URL, ASCII-only, well under the opportunistic
// single-packet cap so it always ships fire-and-forget.
func aboutText() string {
	return "fwdsvc v" + version.Version + "\nSource: " + version.RepoURL
}

func helpText(c *Caller) string {
	var b strings.Builder
	b.WriteString("Commands:\n")
	b.WriteString("/?, /help\n")
	b.WriteString("/about - version + repo\n")
	b.WriteString("/users /mods /admin - lists\n")

	if !c.Member {
		b.WriteString("/join - join the chat\n")
	} else {
		b.WriteString("/nick NAME - rename self\n")
		b.WriteString("/leave - leave the chat\n")
		b.WriteString("/pause /resume - mute/unmute\n")
		b.WriteString("/textonly /showall - skip media\n")
	}

	if c.Role.atLeastMod() {
		b.WriteString("/nick USER NAME - mod\n")
		b.WriteString("/kick /ban /unban /path USER - mod\n")
		b.WriteString("/announce - mod\n")
		b.WriteString("USER = nick or hex (>=4)")
	} else if c.Member {
		// regular member sees the legend so /nick NAME is unambiguous
		b.WriteString("USER = nick or hex (>=4)")
	}
	return b.String()
}

func (d *Dispatcher) listUsers() string {
	users := d.Roster.List()
	if len(users) == 0 {
		return "No users."
	}
	header := fmt.Sprintf("Users (%d):", len(users))
	lines := make([]string, 0, len(users))
	for _, u := range users {
		nick := u.Nickname
		if nick == "" {
			nick = "(no nick)"
		}
		mark := ""
		if u.Paused {
			mark = " [paused]"
		}
		lines = append(lines, fmt.Sprintf("  %s — %s%s", nick, u.Hash[:8], mark))
	}
	return d.fitList("/users", header, lines)
}

func (d *Dispatcher) listConfigList(label string, hashes []string) string {
	if len(hashes) == 0 {
		return fmt.Sprintf("No %s configured.", label)
	}
	sorted := append([]string(nil), hashes...)
	sort.Strings(sorted)
	header := fmt.Sprintf("%s (%d):", titleCase(label), len(sorted))
	lines := make([]string, 0, len(sorted))
	for _, h := range sorted {
		nick := ""
		if u, ok := d.Roster.Get(h); ok && u.Nickname != "" {
			nick = u.Nickname
		}
		if nick != "" {
			lines = append(lines, fmt.Sprintf("  %s — %s", nick, h[:8]))
		} else {
			lines = append(lines, fmt.Sprintf("  %s", h[:8]))
		}
	}
	return d.fitList("/"+label, header, lines)
}

// fitList renders header + lines joined by '\n' and truncates to fit
// MaxReplyContentBytes. Truncation is line-aligned: it keeps as many
// whole lines as fit, then appends "  ...and N more (see operator log)".
// If MaxReplyContentBytes == 0 the full list is returned unmodified.
//
// `cmd` is the originating command name ("/users") used purely as a
// label in the operator log when truncation fires.
func (d *Dispatcher) fitList(cmd, header string, lines []string) string {
	full := header
	if len(lines) > 0 {
		full = header + "\n" + strings.Join(lines, "\n")
	}
	if d.MaxReplyContentBytes <= 0 || len(full) <= d.MaxReplyContentBytes {
		return full
	}

	// Try increasing footers and pick the largest prefix that fits.
	// Keep at least the header and one line if possible.
	var b strings.Builder
	b.WriteString(header)
	used := len(header)
	kept := 0
	for i, line := range lines {
		footer := fmt.Sprintf("\n  ...and %d more (see operator log)", len(lines)-i)
		// Need room for "\n" + line, OR "\n" + line + footer if this is the last we'd keep.
		need := 1 + len(line)
		// If this line plus the worst-case future footer (one more remaining) doesn't fit, stop.
		nextFooter := fmt.Sprintf("\n  ...and %d more (see operator log)", len(lines)-i-1)
		if used+need+len(nextFooter) > d.MaxReplyContentBytes && len(lines)-i-1 > 0 {
			b.WriteString(footer)
			break
		}
		// If this line plus current truncation footer would overflow even
		// without further lines, stop now and emit footer covering the
		// current+remaining lines.
		if used+need > d.MaxReplyContentBytes {
			b.WriteString(footer)
			break
		}
		b.WriteByte('\n')
		b.WriteString(line)
		used += need
		kept++
	}
	if kept == len(lines) {
		// All lines fit after all — shouldn't reach here given the early
		// return, but guard against off-by-one.
		return full
	}

	if d.OverflowLog != nil {
		d.OverflowLog("%s reply truncated: %d/%d entries fit in %d bytes; full reply:\n%s",
			cmd, kept, len(lines), d.MaxReplyContentBytes, full)
	}
	return b.String()
}

func (d *Dispatcher) handleJoin(c *Caller) string {
	if c.Member {
		return "You're already in the chat. Send /pause to mute, /leave to exit."
	}
	if c.HashBytes == nil {
		return "Couldn't join: malformed sender hash."
	}
	if d.Roster.IsBanned(c.HashBytes) {
		return "You're banned from this chat."
	}
	// Enforce the configured member cap. Existing + paused members both
	// count; only fully-removed (kicked / left / pruned) entries free a
	// slot. Skipped when MaxMembers == 0.
	if max := d.Cfg.Service.MaxMembers; max > 0 {
		if cur := d.Roster.Len(); cur >= max {
			return fmt.Sprintf("Sorry, the chat is full (%d/%d members). Please try again later.", cur, max)
		}
	}
	if _, err := d.Roster.AddOrUpdate(c.HashBytes, time.Now()); err != nil {
		return "Couldn't join: " + err.Error()
	}
	// Default nickname to the announced display name, sanitized. Only
	// applied when the joining user has no nickname yet (so re-joiners
	// keep whatever they previously set via /nick).
	if d.LookupAnnouncedName != nil {
		if existing, ok := d.Roster.Get(c.Hash); ok && existing.Nickname == "" {
			if announced := d.LookupAnnouncedName(c.HashBytes); announced != "" {
				if sanitized := SanitizeNickname(announced); sanitized != "" {
					_ = d.Roster.SetNickname(c.Hash, sanitized)
				}
			}
		}
	}
	if d.OnJoin != nil {
		d.OnJoin(c.Hash)
	}
	return "Joined. You'll receive forwarded messages from now on. /pause to mute, /leave to exit, /? for help."
}

func (d *Dispatcher) handleLeave(c *Caller) string {
	if !c.Member {
		return "You're not in the chat."
	}
	if _, err := d.Roster.Remove(c.Hash); err != nil {
		return "Couldn't leave: " + err.Error()
	}
	return "Left the chat. Send /join any time to come back."
}

func (d *Dispatcher) handlePause(c *Caller) string {
	if !c.Member {
		return "You're not in the chat. Send /join first."
	}
	if c.Paused {
		return "You're already paused. Send /resume to come back."
	}
	if err := d.Roster.SetPaused(c.Hash, true); err != nil {
		return "Couldn't pause: " + err.Error()
	}
	return "Paused. You won't receive forwarded messages until you /resume."
}

func (d *Dispatcher) handleResume(c *Caller) string {
	if !c.Member {
		return "You're not in the chat. Send /join first."
	}
	if !c.Paused {
		return "You're not paused."
	}
	if err := d.Roster.SetPaused(c.Hash, false); err != nil {
		return "Couldn't resume: " + err.Error()
	}
	return "Resumed. You'll receive forwarded messages again."
}

// handleTextOnly puts the caller into text-only delivery mode: future
// forwards strip image/file/audio fields but keep the chat text body.
// Intended for users on slow or metered links who want to stay in the
// conversation without paying for every attachment. Reversed by
// /showall.
func (d *Dispatcher) handleTextOnly(c *Caller) string {
	if !c.Member {
		return "You're not in the chat. Send /join first."
	}
	if c.TextOnly {
		return "You're already on text-only. Send /showall to start receiving attachments again."
	}
	if err := d.Roster.SetTextOnly(c.Hash, true); err != nil {
		return "Couldn't switch to text-only: " + err.Error()
	}
	return "Text-only mode on. You'll get the chat text but no image/file attachments. Send /showall to switch back."
}

// handleShowAll reverses /textonly — caller resumes receiving every
// allowed field type along with the chat body.
func (d *Dispatcher) handleShowAll(c *Caller) string {
	if !c.Member {
		return "You're not in the chat. Send /join first."
	}
	if !c.TextOnly {
		return "You're already receiving everything."
	}
	if err := d.Roster.SetTextOnly(c.Hash, false); err != nil {
		return "Couldn't switch back: " + err.Error()
	}
	return "Showing all. You'll receive image and other attachments again."
}

var nickRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,24}$`)

// SanitizeNickname maps an arbitrary announced display name into the
// nickRE alphabet so it can be used as a default nickname when a user
// joins. Any character outside [A-Za-z0-9_-] is replaced with `_`,
// consecutive `_` runs collapse, and leading/trailing `_-` are trimmed.
// Truncated to 24 chars. Returns empty when nothing usable survives
// (e.g. an all-emoji display name) — caller MUST treat empty as "no
// default available" and leave the nickname unset.
//
// Sanitization rules are intentionally lossy + deterministic so two
// peers who announce "Bob & Alice" don't collide on "Bob" vs.
// "BobAlice" — they both land on "Bob_Alice".
func SanitizeNickname(raw string) string {
	var b strings.Builder
	prevUnderscore := false
	for _, r := range raw {
		ok := (r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '-'
		switch {
		case ok:
			b.WriteRune(r)
			prevUnderscore = false
		case r == '_' || r == ' ' || r == '\t':
			if !prevUnderscore && b.Len() > 0 {
				b.WriteByte('_')
				prevUnderscore = true
			}
		default:
			// Any other rune (punctuation, emoji, control chars,
			// non-Latin alphabets the regex rejects) collapses into
			// the same `_` substitution as whitespace. This keeps
			// "Bob.Alice", "Bob Alice", "Bob_Alice" all mapping to
			// "Bob_Alice".
			if !prevUnderscore && b.Len() > 0 {
				b.WriteByte('_')
				prevUnderscore = true
			}
		}
		if b.Len() >= 24 {
			break
		}
	}
	out := b.String()
	out = strings.Trim(out, "_-")
	if len(out) > 24 {
		out = out[:24]
	}
	return out
}

func (d *Dispatcher) handleNick(c *Caller, args []string) string {
	switch len(args) {
	case 0:
		return "Usage: /nick <newname>   (mod/admin: /nick <user> <newname>)"
	case 1:
		if !c.Member {
			return "Send /join first."
		}
		newNick := args[0]
		if !nickRE.MatchString(newNick) {
			return "Nickname must be 1-24 chars from [A-Za-z0-9_-] (no spaces)."
		}
		if err := d.Roster.SetNickname(c.Hash, newNick); err != nil {
			return "Couldn't change nickname: " + err.Error()
		}
		return "Nickname set to " + newNick + "."
	case 2:
		// A regular member who typed `/nick FIRST LAST` almost certainly
		// meant to set their own nickname to "FIRST LAST" — not to rename
		// some other user named FIRST. Disambiguate with a clear "no
		// spaces" error rather than silently routing them to the
		// permission-denied branch.
		if !c.Role.atLeastMod() {
			return "Nicknames can't contain spaces. Use a single word from [A-Za-z0-9_-] (1-24 chars)."
		}
		target, err := d.Roster.Resolve(args[0])
		if err != nil {
			return err.Error()
		}
		newNick := args[1]
		if !nickRE.MatchString(newNick) {
			return "Nickname must be 1-24 chars from [A-Za-z0-9_-] (no spaces)."
		}
		if err := d.Roster.SetNickname(target.Hash, newNick); err != nil {
			return "Couldn't change nickname: " + err.Error()
		}
		return fmt.Sprintf("Set %s's nickname to %s.", target.Hash[:8], newNick)
	default:
		// 3+ tokens. Whether the caller is a mod or not, the most likely
		// intent is a multi-word nickname. Tell them so explicitly.
		if !c.Role.atLeastMod() {
			return "Nicknames can't contain spaces. Use a single word from [A-Za-z0-9_-] (1-24 chars)."
		}
		return "Usage: /nick <newname>   or   /nick <user> <newname>   (no spaces in either argument)"
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
	return fmt.Sprintf("Kicked %s. They can rejoin with /join.", label)
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

// handlePath answers /path <user> for mods/admins. Resolves the target via
// the roster (nick or >=4-char hex prefix), then queries PathLookup for
// what the transport actually knows: cached announce, hops, multi-hop
// next-hop, and whether an Active Link is open. The intent is exactly
// the operator-side diagnostic for "messages queue and time out 5/5
// times" — separates "we don't know this peer" from "we know them but
// the path is bad."
func (d *Dispatcher) handlePath(role Role, args []string) string {
	if !role.atLeastMod() {
		return "Only mods or admins can /path."
	}
	if len(args) != 1 {
		return "Usage: /path <user>"
	}
	if d.PathLookup == nil {
		return "Path lookup not wired (server bug)."
	}
	target, err := d.Roster.Resolve(args[0])
	if err != nil {
		return err.Error()
	}
	info := d.PathLookup(target.Hash)

	label := target.Nickname
	if label == "" {
		label = "(no nick)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Path to %s (%s):\n", label, target.Hash[:8])
	if !info.Known {
		b.WriteString("  no announce cached — they haven't reached us")
		return b.String()
	}
	fmt.Fprintf(&b, "  hops: %d\n", info.Hops)
	age := time.Since(info.LastSeen).Round(time.Second)
	fmt.Fprintf(&b, "  announce age: %s\n", age)
	if info.NextHopHex != "" {
		fmt.Fprintf(&b, "  next hop: %s (multi-hop)\n", info.NextHopHex[:8])
	} else {
		b.WriteString("  next hop: direct\n")
	}
	if info.LinkActive {
		b.WriteString("  link: active")
	} else {
		b.WriteString("  link: none")
	}
	return b.String()
}

func (d *Dispatcher) handleAnnounce(role Role) string {
	if !role.atLeastMod() {
		return "Only mods or admins can /announce."
	}
	if d.Announce == nil {
		return "Announce hook not wired (server bug)."
	}
	if err := d.Announce(); err != nil {
		return "Announce failed: " + err.Error()
	}
	return "OK, announced."
}

// scrubControlBytes replaces every C0 control byte (0x00-0x1F except TAB,
// LF, CR) and DEL (0x7F) with '?'. Used on attacker-influenced strings
// echoed back into a reply (e.g. an unknown command name) so a sender
// can't slip ANSI escape sequences into their own reply or into the
// operator log line that includes that reply. Multi-byte UTF-8
// continuation bytes (0x80-0xBF) pass through unchanged so emoji and
// other non-ASCII content survive.
func scrubControlBytes(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7F {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7F {
			b[i] = '?'
		} else {
			b[i] = c
		}
	}
	return string(b)
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

// mustHexBytes converts a hex hash to bytes; returns nil on bad hex.
// Keeps the dispatcher decoupled from encoding/hex to avoid imports
// bouncing around.
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
