package commands

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thatSFguy/reticulum-go/lxmf"
	"github.com/thatSFguy/reticulum-group-chat/internal/groupinfo"
)

// handleInfo answers /info — the one command deliberately open to
// non-members.
//
// The point of the feature (issue #20) is that someone who has heard our
// announce and has no idea what the group is can ask, so gating it on
// membership the way /users is gated would make it useless. What makes that
// safe is that the reply is bounded at the source: /setinfo refuses any
// description that would push this reply past one opportunistic packet (see
// InfoOverflow), so an unauthenticated /info flood costs one packet per
// request rather than a link setup and Resource transfer per request.
//
// The tail of the reply is tailored to the caller because "what is this and
// how do I get in" is one question: a stranger gets the join instruction for
// whichever mode the group is in, and a member gets a pointer to /pins
// instead, since they are already in and the pins are the part they have not
// necessarily read.
func (d *Dispatcher) handleInfo(c *Caller) string {
	if d.Info == nil {
		return "Group info not wired (server bug)."
	}
	return d.renderInfo(c, d.Info.Info(), d.Info.PinCount())
}

// renderInfo builds the /info reply for caller c as if the description were
// info and pins pins were held. Split out of handleInfo so InfoOverflow can
// size a candidate description before it is stored, from the same code that
// will later send it — a separate size estimate would drift the first time
// someone reworded the join hint.
func (d *Dispatcher) renderInfo(c *Caller, info string, pins int) string {
	var b strings.Builder
	b.WriteString(d.Cfg.Service.DisplayName)
	if info != "" {
		b.WriteString("\n")
		b.WriteString(info)
	} else if c.Role == RoleAdmin {
		b.WriteString("\nNo description set — /setinfo <text> to add one.")
	} else {
		b.WriteString("\nNo description set.")
	}

	switch {
	case c.Member:
		if pins > 0 {
			fmt.Fprintf(&b, "\n%d pinned — /pins", pins)
		}
	case d.Cfg.Service.Locked:
		// Same bounce /join gives a stranger on a locked group: echo them
		// their own destination hash so they can hand it to an admin
		// without digging it out of their client. It is already in the
		// envelope they sent us, so there is no disclosure in it.
		b.WriteString("\nInvite-only. Give an admin your address to be added:\n")
		b.WriteString(c.Hash)
	default:
		b.WriteString("\n/join to take part, /? for help.")
	}
	return b.String()
}

// singlePacketReplyBytes is the largest command reply, in bytes, that goes
// out as one opportunistic packet rather than over a Link.
//
// Measured rather than written down. The budget is upstream LXMF's
// 295-byte ENCRYPTED_PACKET_MAX_CONTENT, but that caps the msgpack PAYLOAD,
// not the text — the timestamp, empty title, fields map and bin headers come
// out of it first — and an earlier version of this feature got the
// difference wrong: a 256-byte description under a 32-byte display name
// overflowed even a single Link packet. Asking lxmf.CheckOpportunisticSize,
// the same check Delivery.Send makes, with the same nil title and fields the
// command-reply path sends, means this number is whatever the library will
// actually do. Payload size grows monotonically with content length, so
// probing upward to the first refusal finds the exact edge.
//
// A recipient who announces a stamp cost spends 34 of those bytes on the
// stamp and gets the reply over a Link instead — but as a single Link DATA
// packet (LinkMDU 431), not a Resource, so the bound still holds.
var singlePacketReplyBytes = sync.OnceValue(func() int {
	n := 0
	for lxmf.CheckOpportunisticSize(nil, []byte(strings.Repeat("x", n+1)), nil) == nil {
		n++
	}
	return n
})

// InfoOverflow reports how many bytes too long the /info reply would be for
// description info, against the single-packet budget; zero or negative
// means it fits. It sizes every reply shape /info can produce under the
// current config — a stranger on an open group, a stranger on a locked one
// (whose reply echoes a full 32-hex address), and a member with a full pin
// list — and returns the worst.
//
// The display name counts against the same budget and is not ours to
// bound: it is config, and an operator can lengthen it at any restart. So
// /setinfo checks this before storing, and the service checks it again at
// startup against whatever description is already stored.
func (d *Dispatcher) InfoOverflow(info string) int {
	stranger := &Caller{Hash: strings.Repeat("0", 32)}
	member := &Caller{Hash: stranger.Hash, Member: true}
	worst := 0
	for _, c := range []*Caller{stranger, member} {
		if n := len(d.renderInfo(c, info, groupinfo.MaxPins)); n > worst {
			worst = n
		}
	}
	return worst - singlePacketReplyBytes()
}

// handleSetInfo implements /setinfo [text] — admin-only, empty clears.
//
// Admin rather than mod, per the request in issue #20: the description is
// what every passer-by sees of the group, so it sits with whoever owns the
// group's identity rather than with day-to-day moderation. Pins are the
// mod-level surface.
func (d *Dispatcher) handleSetInfo(c *Caller, text string) string {
	if c.Role != RoleAdmin {
		return "Only admins can set the group description."
	}
	if d.Info == nil {
		return "Group info not wired (server bug)."
	}
	if strings.TrimSpace(text) == "" {
		if d.Info.Info() == "" {
			return "No description is set. Usage: /setinfo <text>"
		}
		if err := d.Info.SetInfo(""); err != nil {
			return "Couldn't clear the description: " + err.Error()
		}
		return "Cleared the group description."
	}
	clean := scrubControlBytes(strings.TrimSpace(text))
	if len(clean) > groupinfo.MaxInfoBytes {
		return fmt.Sprintf("That's %d bytes and the limit is %d — /info answers non-members, so it's capped to one packet on a slow link. Trim %d.",
			len(clean), groupinfo.MaxInfoBytes, len(clean)-groupinfo.MaxInfoBytes)
	}
	// The hard cap above is a ceiling on what we store; this is the limit
	// that matters on the wire, and it is usually tighter, because the
	// display name and join hint share the same packet. Reported as the
	// room actually left, so the admin is not told "256" and then refused
	// at 214.
	if over := d.InfoOverflow(clean); over > 0 {
		room := len(clean) - over
		if room <= 0 {
			return fmt.Sprintf("The display name %q already fills the one packet /info has to fit in, so there's no room for a description. Shorten display_name in the config first.",
				d.Cfg.Service.DisplayName)
		}
		return fmt.Sprintf("That's %d bytes; with this group's display name, /info has room for %d — it answers non-members, so it has to fit in one packet. Trim %d.",
			len(clean), room, over)
	}
	if err := d.Info.SetInfo(clean); err != nil {
		return "Couldn't set the description: " + err.Error()
	}
	return fmt.Sprintf("Group description set (%d/%d bytes). Anyone can read it with /info.",
		len(clean), len(clean)-d.InfoOverflow(clean))
}

// handlePins answers /pins.
//
// Members only, for the reason /users is members-only: the pins are
// group-internal content and the reply is O(pins), so leaving it open would
// hand an unauthenticated 5-byte request a multi-KiB reply with a full retry
// budget behind it. /info is the surface for strangers; this one is not.
func (d *Dispatcher) handlePins(c *Caller) string {
	if d.Info == nil {
		return "Group info not wired (server bug)."
	}
	if !c.Member && c.Role == RoleUser {
		return "Only members can read the pins. Send /join first."
	}
	pins := d.Info.Pins()
	if len(pins) == 0 {
		if c.Role.atLeastMod() {
			return "No pinned messages. /pin <text> to add one."
		}
		return "No pinned messages."
	}
	out := groupinfo.Render(pins, time.Now())
	if c.Role.atLeastMod() {
		out += "\n/unpin <n> to remove one."
	}
	return out
}

// handlePin implements /pin <text> — mod and admin only.
//
// The pinned text is the mod's own words rather than a reference to an
// existing message, which is a deliberate departure from how pinning works
// in a centralised chat. fwdsvc re-emits every message under its own
// identity, so the message_id a member would quote back at us is one of N
// per-recipient views that exists only in their client and in the idmap
// cache (CLAUDE.md §2) — it is not a stable, group-wide handle we could
// store and re-render for a joiner months later. Storing the text sidesteps
// the whole problem and survives the id cache's TTL.
func (d *Dispatcher) handlePin(c *Caller, text string) string {
	if !c.Role.atLeastMod() {
		return "Only mods or admins can pin messages."
	}
	if d.Info == nil {
		return "Group info not wired (server bug)."
	}
	clean := collapseLines(scrubControlBytes(strings.TrimSpace(text)))
	if clean == "" {
		return "Usage: /pin <text>"
	}
	if len(clean) > groupinfo.MaxPinBytes {
		return fmt.Sprintf("That pin is %d bytes and the limit is %d — every joiner receives the whole list. Trim %d.",
			len(clean), groupinfo.MaxPinBytes, len(clean)-groupinfo.MaxPinBytes)
	}
	nick := ""
	if u, ok := d.Roster.Get(c.Hash); ok {
		nick = u.Nickname
	}
	err := d.Info.AddPin(groupinfo.Pin{
		At:     time.Now(),
		By:     c.Hash,
		ByNick: nick,
		Text:   clean,
	})
	if errors.Is(err, groupinfo.ErrPinsFull) {
		return fmt.Sprintf("The pin list is full (%d). /unpin <n> to make room.", groupinfo.MaxPins)
	}
	if err != nil {
		return "Couldn't pin: " + err.Error()
	}
	return fmt.Sprintf("Pinned as #%d. Members see it with /pins; new members get the list right after their history replay.",
		d.Info.PinCount())
}

// handleUnpin implements /unpin <n>, where n is the number /pins printed.
func (d *Dispatcher) handleUnpin(c *Caller, args []string) string {
	if !c.Role.atLeastMod() {
		return "Only mods or admins can unpin messages."
	}
	if d.Info == nil {
		return "Group info not wired (server bug)."
	}
	if len(args) != 1 {
		return "Usage: /unpin <n>   (the number shown by /pins)"
	}
	n, err := strconv.Atoi(args[0])
	if err != nil {
		return "Give the pin's number as shown by /pins, e.g. /unpin 2."
	}
	removed, ok, err := d.Info.RemovePin(n)
	if err != nil {
		return "Couldn't unpin: " + err.Error()
	}
	if !ok {
		switch count := d.Info.PinCount(); count {
		case 0:
			return "There are no pinned messages."
		case 1:
			return "There's only one pin — /unpin 1."
		default:
			return fmt.Sprintf("No pin #%d — pins are numbered 1-%d.", n, count)
		}
	}
	return fmt.Sprintf("Unpinned #%d (%q). %d left.", n, ellipsize(removed.Text, 40), d.Info.PinCount())
}

// collapseLines folds every run of whitespace containing a line break into a
// single space. Pins render as a numbered list that a mod then addresses by
// number, and an embedded newline makes the list ambiguous to read — line 3
// of the reply stops being pin 3. Ordinary interior spacing is left alone.
func collapseLines(s string) string {
	if !strings.ContainsAny(s, "\n\r") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	pendingBreak := false
	for _, r := range s {
		switch r {
		case '\n', '\r':
			pendingBreak = true
		case ' ', '\t':
			if !pendingBreak {
				b.WriteRune(r)
			}
		default:
			if pendingBreak {
				if b.Len() > 0 {
					b.WriteByte(' ')
				}
				pendingBreak = false
			}
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// ellipsize shortens s to at most max bytes for an echo-back confirmation,
// cutting on a rune boundary so the reply can't carry a half-encoded
// character.
func ellipsize(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return groupinfo.TruncateText(s, max-1) + "…"
}
