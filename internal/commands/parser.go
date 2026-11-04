package commands

import "strings"

// IsCommand returns true if the message body looks like a slash command.
// Surrounding whitespace is allowed.
func IsCommand(content string) bool {
	return strings.HasPrefix(strings.TrimLeft(content, " \t"), "/")
}

type Parsed struct {
	Name string   // lowercased, no leading slash
	Args []string // whitespace-split remainder
	Rest string   // remainder with interior whitespace intact
	Raw  string
}

func Parse(content string) Parsed {
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "/") {
		return Parsed{Raw: content}
	}
	rest := strings.TrimPrefix(trimmed, "/")
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return Parsed{Raw: content}
	}
	return Parsed{
		Name: strings.ToLower(fields[0]),
		Args: fields[1:],
		// Rest exists for the commands whose argument is free text rather
		// than a token — /setinfo and /pin. Args is Fields-split, which
		// collapses every run of whitespace, so reassembling a description
		// from it silently rewrites "a  b" as "a b" and drops any line
		// breaks the author typed. Taken from `rest` (not Raw) so the
		// leading slash and surrounding whitespace are already gone, and
		// with the ORIGINAL-case fields[0] trimmed off, since Name has been
		// lowercased and would not match a "/SetInfo".
		Rest: strings.TrimSpace(strings.TrimPrefix(rest, fields[0])),
		Raw:  content,
	}
}
