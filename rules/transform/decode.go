// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package transform

import "github.com/gsoultan/gwaf/rules"

// The transforms in this file exist because rules people already have depend on
// them, and the cost of not having them was measured rather than guessed.
//
// test/pentest ran the Core Rule Set, converted, against the same corpus as
// gwaf's own ruleset and scored zero on every XSS category. The reason was one
// transform: CRS 941100 *is* the @detectXSS rule and carries t:cssDecode, so the
// converter skipped it, while @detectSQLi (942100) carries no such transform,
// converted, and scored 3/3. One missing normalization cost an entire detection
// tier.
//
// They are anti-evasion transforms, so they take hostile input by definition and
// each has a fuzz target. Where a decoder has to choose, it decodes *more*
// rather than less: seeing a payload that was not there costs a false positive
// on one rule, and missing one costs the block.

// All is every transform this package provides.
//
// It exists so the tests that hold the package to its own contracts — the
// MaxOutputLen bound and the fuzz corpus — cannot be narrower than the package.
// Both used to carry a hand-written list, and both had silently fallen behind:
// EscapeDecode shipped without ever being fuzzed, and it is the transform that
// walks backslash escapes over attacker bytes. Adding a transform below adds it
// to those tests by construction.
var All = []rules.Transform{
	Lowercase, RemoveWhitespace, CompressWhitespace, URLDecode, NormalizePath,
	EscapeDecode, CSSDecode, CmdLine, ReplaceComments, RemoveCommentsChar,
	Base64Decode,
}

// CSSDecode resolves CSS escape sequences.
//
// CSS lets any character be written as a backslash followed by up to six hex
// digits, so "\65 xpression" and "\000065xpression" are both "expression" to a
// browser and neither is to a string match. This is a live XSS evasion, not a
// theoretical one — it is why CRS applies it to its XSS rules.
//
// The grammar (CSS Syntax Level 3, §4.3.7): a backslash followed by hex digits
// consumes up to six of them and one optional trailing whitespace, which is the
// delimiter that lets "\65 x" mean "ex" rather than "\65x". A backslash before a
// newline is a line continuation and both go. A backslash before anything else
// escapes it literally.
//
// Values above U+00FF are reduced to their low byte rather than encoded as
// UTF-8. That matches ModSecurity, and it keeps the output no longer than the
// input, which is what lets match spans stay meaningful.
var CSSDecode rules.Transform = cssDecode{}

type cssDecode struct{}

func (cssDecode) Name() string { return "css_decode" }

// Every escape consumes at least two input bytes and yields at most one, so the
// output can only shrink.
func (cssDecode) MaxOutputLen(n int) int { return n }

func (cssDecode) Apply(dst, src []byte) ([]byte, bool) {
	if indexByteIn(src, '\\') < 0 {
		return src, false
	}

	dst = dst[:0]
	for i := 0; i < len(src); {
		if src[i] != '\\' || i+1 >= len(src) {
			dst = append(dst, src[i])
			i++
			continue
		}

		// "\<newline>" is a line continuation: both bytes disappear.
		if src[i+1] == '\n' {
			i += 2
			continue
		}
		// "\r\n" counts as one newline for the continuation rule.
		if src[i+1] == '\r' {
			i += 2
			if i < len(src) && src[i] == '\n' {
				i++
			}
			continue
		}

		if _, ok := unhex(src[i+1]); !ok {
			// Not a hex escape: the backslash is dropped and the character it
			// escaped is taken literally.
			dst = append(dst, src[i+1])
			i += 2
			continue
		}

		// Up to six hex digits. Reducing modulo 256 as we go keeps the value in
		// range without needing a wider type, and matches taking the low byte.
		var v int
		j := i + 1
		for n := 0; n < 6 && j < len(src); n++ {
			h, ok := unhex(src[j])
			if !ok {
				break
			}
			v = (v<<4 | int(h)) & 0xff
			j++
		}
		dst = append(dst, byte(v))

		// One whitespace character after the digits is the delimiter and is
		// consumed with them. Only one: "\65  x" keeps the second space.
		if j < len(src) {
			switch src[j] {
			case ' ', '\t', '\n', '\f':
				j++
			case '\r':
				j++
				if j < len(src) && src[j] == '\n' {
					j++
				}
			}
		}
		i = j
	}
	return dst, true
}

// CmdLine normalizes shell command lines the way ModSecurity's t:cmdLine does.
//
// The evasion it answers is that a shell reads "c^md", `"c"md`, "c\md" and
// "cmd" identically while a string match reads four different things. Windows
// cmd.exe treats the caret as an escape, and every shell treats quotes and
// backslashes as syntax rather than data.
//
// So: drop the characters that are shell syntax rather than command text, turn
// argument separators into spaces, close up the space an attacker inserted
// before a path or a call, collapse runs of whitespace, and fold case.
var CmdLine rules.Transform = cmdLine{}

type cmdLine struct{}

func (cmdLine) Name() string { return "cmd_line" }

// Only deletions, one-for-one replacements and run collapsing.
func (cmdLine) MaxOutputLen(n int) int { return n }

func (cmdLine) Apply(dst, src []byte) ([]byte, bool) {
	dst = dst[:0]
	for _, c := range src {
		switch c {
		case '\\', '"', '\'', '^':
			// Shell quoting and escaping: syntax, not command text.
			continue
		case ',', ';':
			c = ' '
		case '\t', '\r', '\n', '\v', '\f':
			c = ' '
		default:
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
		}

		if c == ' ' {
			// Collapse runs, and drop a leading space outright.
			if len(dst) == 0 || dst[len(dst)-1] == ' ' {
				continue
			}
		}
		// A space before a path separator or a call is how "cat /etc/passwd"
		// becomes "cat  /etc/passwd" and slips a literal.
		if (c == '/' || c == '(') && len(dst) > 0 && dst[len(dst)-1] == ' ' {
			dst = dst[:len(dst)-1]
		}
		dst = append(dst, c)
	}
	// A trailing space carries no information and would defeat a suffix match.
	if len(dst) > 0 && dst[len(dst)-1] == ' ' {
		dst = dst[:len(dst)-1]
	}

	if len(dst) == len(src) && string(dst) == string(src) {
		return src, false
	}
	return dst, true
}

// ReplaceComments replaces each C-style comment with a single space.
//
// "SEL/**/ECT" is one of the oldest SQL-injection evasions there is, and the
// replacement is a space rather than nothing on purpose: a comment is a token
// separator to the parser, so deleting it would weld "SEL" to "ECT" and invent a
// keyword the origin never sees. An unterminated comment runs to the end, which
// is what the databases that accept it do.
//
// Exactly one space per comment, and adjacent whitespace is left alone: that is
// ModSecurity's behaviour, and a rule written against it pairs this with
// t:compressWhitespace when it cares. Collapsing here would catch marginally
// more and would mean an imported rule behaves differently from the rule that
// was written, which is the thing this package refuses to do.
var ReplaceComments rules.Transform = replaceComments{}

type replaceComments struct{}

func (replaceComments) Name() string { return "replace_comments" }

// The shortest comment is "/**/", four bytes, replaced by one.
func (replaceComments) MaxOutputLen(n int) int { return n }

func (replaceComments) Apply(dst, src []byte) ([]byte, bool) {
	if !containsPair(src, '/', '*') {
		return src, false
	}

	dst = dst[:0]
	for i := 0; i < len(src); {
		if src[i] == '/' && i+1 < len(src) && src[i+1] == '*' {
			i += 2
			for i < len(src) {
				if src[i] == '*' && i+1 < len(src) && src[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			dst = append(dst, ' ')
			continue
		}
		dst = append(dst, src[i])
		i++
	}
	return dst, true
}

// RemoveCommentsChar removes comment-introducing sequences without removing what
// they comment out.
//
// Where ReplaceComments handles a balanced comment, this handles the halves:
// "--", "#", "/*" and "*/" left dangling to terminate a statement or to break a
// keyword apart. Removing the marker and keeping the text is what makes
// "UNION--SELECT" read as "UNIONSELECT" rather than disappearing.
var RemoveCommentsChar rules.Transform = removeCommentsChar{}

type removeCommentsChar struct{}

func (removeCommentsChar) Name() string { return "remove_comments_char" }

func (removeCommentsChar) MaxOutputLen(n int) int { return n }

func (removeCommentsChar) Apply(dst, src []byte) ([]byte, bool) {
	changed := false
	for i := range src {
		if src[i] == '#' ||
			(i+1 < len(src) && ((src[i] == '-' && src[i+1] == '-') ||
				(src[i] == '/' && src[i+1] == '*') ||
				(src[i] == '*' && src[i+1] == '/'))) {
			changed = true
			break
		}
	}
	if !changed {
		return src, false
	}

	dst = dst[:0]
	for i := 0; i < len(src); {
		if src[i] == '#' {
			i++
			continue
		}
		if i+1 < len(src) {
			a, b := src[i], src[i+1]
			if (a == '-' && b == '-') || (a == '/' && b == '*') || (a == '*' && b == '/') {
				i += 2
				continue
			}
		}
		dst = append(dst, src[i])
		i++
	}
	return dst, true
}

// Base64Decode decodes base64, forgiving whatever is not base64.
//
// Rules use it where an application base64-encodes a field, so the payload the
// origin acts on is the decoded form and matching the encoded form matches
// nothing. It is deliberately lenient about padding and skips characters outside
// the alphabet, because the decoder the application uses usually is too, and a
// strict decoder here is an evasion: an attacker adds one stray byte and the
// transform declines to look.
//
// A trailing group of fewer than two characters carries no whole byte and is
// dropped, which is what every base64 decoder does with it.
var Base64Decode rules.Transform = base64Decode{}

type base64Decode struct{}

func (base64Decode) Name() string { return "base64_decode" }

// Four input characters yield three bytes, so the output is always smaller.
func (base64Decode) MaxOutputLen(n int) int { return n }

func (base64Decode) Apply(dst, src []byte) ([]byte, bool) {
	dst = dst[:0]

	var quad [4]byte
	n := 0
	for _, c := range src {
		v, ok := unbase64(c)
		if !ok {
			continue // padding, whitespace, or noise
		}
		quad[n] = v
		n++
		if n == 4 {
			dst = append(dst,
				quad[0]<<2|quad[1]>>4,
				quad[1]<<4|quad[2]>>2,
				quad[2]<<6|quad[3])
			n = 0
		}
	}
	// Partial groups: two characters make one byte, three make two.
	switch n {
	case 2:
		dst = append(dst, quad[0]<<2|quad[1]>>4)
	case 3:
		dst = append(dst, quad[0]<<2|quad[1]>>4, quad[1]<<4|quad[2]>>2)
	}

	if len(dst) == len(src) && string(dst) == string(src) {
		return src, false
	}
	return dst, true
}

func unbase64(c byte) (byte, bool) {
	switch {
	case c >= 'A' && c <= 'Z':
		return c - 'A', true
	case c >= 'a' && c <= 'z':
		return c - 'a' + 26, true
	case c >= '0' && c <= '9':
		return c - '0' + 52, true
	case c == '+':
		return 62, true
	case c == '/':
		return 63, true
	}
	return 0, false
}

// containsPair reports whether src contains the two-byte sequence a,b.
func containsPair(src []byte, a, b byte) bool {
	for i := 0; i+1 < len(src); i++ {
		if src[i] == a && src[i+1] == b {
			return true
		}
	}
	return false
}
