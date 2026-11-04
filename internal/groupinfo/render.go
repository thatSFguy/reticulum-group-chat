package groupinfo

import (
	"fmt"
	"strings"
	"time"
)

// Render formats the pin list as the single block that both the /pins reply
// and the on-join playback send.
//
// One rendering, one message, deliberately. Sending each pin as its own
// message would multiply every join by len(pins) outbound queue entries,
// each carrying its own retry budget — the amplification the replay cooldown
// exists to bound. It also keeps the two surfaces identical: a member who
// reads the pins on join and then types /pins later sees the same text, so
// the numbers in "unpin 3" mean the same thing in both places.
//
// Returns "" for an empty list; callers decide what (if anything) to say
// instead, since "No pinned messages." is right for /pins and silence is
// right for a join.
func Render(pins []Pin, now time.Time) string {
	if len(pins) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Pinned (%d):", len(pins))
	for i, p := range pins {
		who := p.ByNick
		if who == "" && len(p.By) >= 8 {
			who = p.By[:8]
		}
		age := HumanAge(now.Sub(p.At))
		switch {
		case who == "" && p.At.IsZero():
			fmt.Fprintf(&b, "\n%d. %s", i+1, scrub(p.Text))
		case who == "":
			fmt.Fprintf(&b, "\n%d. [%s] %s", i+1, age, scrub(p.Text))
		case p.At.IsZero():
			fmt.Fprintf(&b, "\n%d. [%s] %s", i+1, who, scrub(p.Text))
		default:
			fmt.Fprintf(&b, "\n%d. [%s, %s] %s", i+1, who, age, scrub(p.Text))
		}
	}
	return b.String()
}

// HumanAge renders a duration as "5s", "12m", "3h", "4d", always rounding
// down. Mirrors service.humanizeAge so a pin's age and a replayed message's
// age read identically in the same join burst; they are separate functions
// because the alternative is the service package importing a formatter from
// a storage package, or this package importing the service.
func HumanAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// scrub replaces every C0 control byte (except TAB/LF/CR) and DEL with '?'.
//
// Pin text is scrubbed on the way IN as well (commands.handlePin), so this is
// the second layer: the JSON file is operator-editable and seedable by hand,
// and a pin loaded from it goes to every member and every future joiner
// without passing back through the command path. Rendering is the last point
// where the bytes are still ours, so it is the right place to guarantee a pin
// cannot drive ANSI escapes on a CLI client. Continuation bytes (0x80-0xBF)
// pass through so emoji and non-Latin text survive.
func scrub(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7F {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if c := b[i]; (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7F {
			b[i] = '?'
		}
	}
	return string(b)
}
