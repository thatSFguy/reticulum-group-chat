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
		Raw:  content,
	}
}
