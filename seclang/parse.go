// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package seclang

import (
	"errors"
	"fmt"
	"strings"
)

// Errors a caller may want to distinguish.
var (
	// ErrNoConfidence reports Options.DefaultConfidence left unset. Deliberate:
	// a SecLang rule arrives with no measured false-positive rate, and picking
	// a tier for the caller would assert something nobody has checked.
	ErrNoConfidence = errors.New("seclang: Options.DefaultConfidence must be set")

	// ErrUntranslatable reports a directive ParseStrict would not approximate.
	ErrUntranslatable = errors.New("seclang: directive cannot be translated faithfully")

	// ErrSyntax reports malformed input.
	ErrSyntax = errors.New("seclang: syntax error")
)

// directive is one parsed SecLang statement.
type directive struct {
	Name string   // SecRule, SecAction, ...
	Args []string // the unquoted arguments
	Line int
}

// parse splits SecLang source into directives.
//
// The lexing rules are ModSecurity's and are more awkward than they look:
// arguments may be quoted with single or double quotes, a backslash at end of
// line continues the directive, and a '#' inside a quoted argument is data
// rather than a comment. A naive line-splitter mangles most of the Core Rule
// Set, whose action lists routinely span several lines and contain '#'.
func parse(name string, src []byte) ([]directive, error) {
	var out []directive
	lines := splitLines(src)

	for i := 0; i < len(lines); i++ {
		raw, start := lines[i], i+1

		// Join continuations before anything else, so a quoted argument split
		// across lines is lexed as one string.
		for strings.HasSuffix(strings.TrimRight(raw, " \t"), `\`) && i+1 < len(lines) {
			trimmed := strings.TrimRight(raw, " \t")
			raw = trimmed[:len(trimmed)-1] + " " + strings.TrimLeft(lines[i+1], " \t")
			i++
		}

		args, err := lexArgs(raw)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", location(name), start, err)
		}
		if len(args) == 0 {
			continue
		}
		out = append(out, directive{Name: args[0], Args: args[1:], Line: start})
	}
	return out, nil
}

func location(name string) string {
	if name == "" {
		return "<input>"
	}
	return name
}

// splitLines splits on \n and drops a trailing \r, without allocating a slice
// per line beyond the result.
func splitLines(src []byte) []string {
	s := string(src)
	out := strings.Split(s, "\n")
	for i := range out {
		out[i] = strings.TrimSuffix(out[i], "\r")
	}
	return out
}

// lexArgs splits one logical line into arguments.
//
// A '#' begins a comment only outside quotes: CRS action lists contain
// "msg:'... # ...'" and a comment rule that ignores quoting truncates them.
func lexArgs(line string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inCur := false

	i := 0
	for i < len(line) {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			if inCur {
				args = append(args, cur.String())
				cur.Reset()
				inCur = false
			}
			i++

		case c == '#' && !inCur:
			// A comment runs to end of line, but only where an argument could
			// have started.
			return args, nil

		case c == '"' || c == '\'':
			quote := c
			i++
			inCur = true
			terminated := false
			for i < len(line) && !terminated {
				switch {
				case line[i] == '\\' && i+1 < len(line):
					// ModSecurity keeps the backslash for the operator to see:
					// "\\." inside an @rx is a literal dot, and unescaping here
					// would hand the regex engine a different pattern.
					cur.WriteByte(line[i])
					cur.WriteByte(line[i+1])
					i += 2
				case line[i] == quote:
					i++
					terminated = true
				default:
					cur.WriteByte(line[i])
					i++
				}
			}
			if !terminated {
				return nil, fmt.Errorf("%w: unterminated %c-quoted argument", ErrSyntax, quote)
			}

		default:
			inCur = true
			cur.WriteByte(c)
			i++
		}
	}
	if inCur {
		args = append(args, cur.String())
	}
	return args, nil
}

// splitActions splits a SecLang action list on commas outside quotes.
//
// "msg:'a,b',id:1" is two actions, not three, and a comma-splitter that ignores
// quoting silently corrupts every CRS message.
func splitActions(s string) []string {
	var out []string
	var cur strings.Builder
	var quote byte

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && i+1 < len(s) {
				cur.WriteByte(c)
				cur.WriteByte(s[i+1])
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			cur.WriteByte(c)
		case c == '\'' || c == '"':
			quote = c
			cur.WriteByte(c)
		case c == ',':
			if t := strings.TrimSpace(cur.String()); t != "" {
				out = append(out, t)
			}
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if t := strings.TrimSpace(cur.String()); t != "" {
		out = append(out, t)
	}
	return out
}

// action is one parsed action, "name" or "name:value".
type action struct {
	Name  string
	Value string
}

// parseAction splits an action into its name and value, unquoting the value.
func parseAction(s string) action {
	name, value, found := strings.Cut(s, ":")
	a := action{Name: strings.TrimSpace(name)}
	if !found {
		return a
	}
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if q := value[0]; (q == '\'' || q == '"') && value[len(value)-1] == q {
			value = value[1 : len(value)-1]
		}
	}
	a.Value = value
	return a
}

// parseOperator splits a SecLang operator argument into its name, its argument,
// and whether it was negated.
//
// "!@rx foo" is negation, "@rx foo" is not, and a bare "foo" means @rx with an
// implicit operator — which is how a surprising amount of older SecLang is
// written.
func parseOperator(s string) (name, arg string, negated bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "!") {
		negated = true
		s = strings.TrimSpace(s[1:])
	}
	if !strings.HasPrefix(s, "@") {
		return "rx", s, negated
	}
	s = s[1:]
	name, arg, _ = strings.Cut(s, " ")
	return strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(arg), negated
}

// splitVariables splits a SecLang variable list on '|' outside brackets.
//
// "ARGS|REQUEST_HEADERS:User-Agent|!ARGS:token" is three entries, and the
// colon-qualified and '!'-excluded forms both have to survive the split.
func splitVariables(s string) []string {
	var out []string
	var cur strings.Builder
	depth := 0

	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '[':
			depth++
			cur.WriteByte(c)
		case ']':
			depth--
			cur.WriteByte(c)
		case '|':
			if depth > 0 {
				cur.WriteByte(c)
				continue
			}
			if t := strings.TrimSpace(cur.String()); t != "" {
				out = append(out, t)
			}
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if t := strings.TrimSpace(cur.String()); t != "" {
		out = append(out, t)
	}
	return out
}
