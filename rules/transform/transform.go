// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package transform provides the built-in value normalizations.
//
// Each transform returns false from Apply when it changed nothing, which lets
// the engine keep using the original bytes instead of copying. Already-normal
// traffic is the common case, so this is a large part of why benign requests
// allocate nothing.
//
// These are the materialised implementations. They are deliberately simple and
// obviously correct: docs/CONCEPT.md §3 plans to fold streamable transforms
// into the matcher itself, and when that lands these become the differential
// fuzz oracle it is validated against. Keeping them straightforward is what
// makes them usable as an oracle.
package transform

import "github.com/gsoultan/gwaf/rules"

// Lowercase folds ASCII upper case to lower case.
//
// Only ASCII is folded. Unicode case folding can change byte length, which
// would invalidate the offsets that match spans are reported in, and it opens a
// normalization-mismatch surface of its own.
var Lowercase rules.Transform = lowercase{}

type lowercase struct{}

func (lowercase) Name() string { return "lowercase" }

func (lowercase) MaxOutputLen(n int) int { return n }

func (lowercase) Apply(dst, src []byte) ([]byte, bool) {
	changed := false
	for i := range len(src) {
		if src[i] >= 'A' && src[i] <= 'Z' {
			changed = true
			break
		}
	}
	if !changed {
		return src, false
	}
	dst = dst[:0]
	for _, c := range src {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst, true
}

// RemoveWhitespace strips ASCII whitespace.
//
// Attackers insert whitespace to break up keywords ("UNI ON SELECT"); origins
// often ignore it. Stripping it before matching removes that gap.
var RemoveWhitespace rules.Transform = removeWhitespace{}

type removeWhitespace struct{}

func (removeWhitespace) Name() string { return "remove_whitespace" }

func (removeWhitespace) MaxOutputLen(n int) int { return n }

func (removeWhitespace) Apply(dst, src []byte) ([]byte, bool) {
	changed := false
	for _, c := range src {
		if isSpace(c) {
			changed = true
			break
		}
	}
	if !changed {
		return src, false
	}
	dst = dst[:0]
	for _, c := range src {
		if !isSpace(c) {
			dst = append(dst, c)
		}
	}
	return dst, true
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	default:
		return false
	}
}

// URLDecode decodes percent-encoding and, per the form-encoding convention,
// '+' as space.
//
// Malformed escapes are left verbatim rather than dropped or guessed. Guessing
// is precisely how a WAF and an origin come to disagree about what a request
// says, and that disagreement is the CVE-2026-21876 bug class. When gwaf cannot
// determine the decoding, it must not invent one — docs/CONCEPT.md §4 handles
// genuine ambiguity by evaluating every plausible reading rather than picking.
var URLDecode rules.Transform = urlDecode{}

type urlDecode struct{}

func (urlDecode) Name() string { return "url_decode" }

func (urlDecode) MaxOutputLen(n int) int { return n }

func (urlDecode) Apply(dst, src []byte) ([]byte, bool) {
	changed := false
	for _, c := range src {
		if c == '%' || c == '+' {
			changed = true
			break
		}
	}
	if !changed {
		return src, false
	}

	dst = dst[:0]
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '+':
			dst = append(dst, ' ')
			i++
		case c == '%' && i+2 < len(src):
			hi, ok1 := unhex(src[i+1])
			lo, ok2 := unhex(src[i+2])
			if ok1 && ok2 {
				dst = append(dst, hi<<4|lo)
				i += 3
				continue
			}
			// Malformed escape: keep it verbatim.
			dst = append(dst, c)
			i++
		default:
			dst = append(dst, c)
			i++
		}
	}
	return dst, true
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// CompressWhitespace collapses runs of ASCII whitespace to a single space.
//
// Unlike RemoveWhitespace this preserves token boundaries, which matters for
// operators that care about word structure.
var CompressWhitespace rules.Transform = compressWhitespace{}

type compressWhitespace struct{}

func (compressWhitespace) Name() string { return "compress_whitespace" }

func (compressWhitespace) MaxOutputLen(n int) int { return n }

func (compressWhitespace) Apply(dst, src []byte) ([]byte, bool) {
	changed := false
	for i, c := range src {
		if isSpace(c) && (c != ' ' || (i > 0 && isSpace(src[i-1]))) {
			changed = true
			break
		}
	}
	if !changed {
		return src, false
	}
	dst = dst[:0]
	prevSpace := false
	for _, c := range src {
		if isSpace(c) {
			if !prevSpace {
				dst = append(dst, ' ')
			}
			prevSpace = true
			continue
		}
		dst = append(dst, c)
		prevSpace = false
	}
	return dst, true
}

// NormalizePath resolves "." and ".." segments and collapses duplicate
// separators, so that traversal attempts are compared in canonical form.
//
// Backslashes are treated as separators: Windows origins accept them, and a WAF
// that did not would miss "..\..\" traversal against those origins.
var NormalizePath rules.Transform = normalizePath{}

type normalizePath struct{}

func (normalizePath) Name() string { return "normalize_path" }

// MaxOutputLen reserves one byte beyond the input length.
//
// Every emitted segment is followed by a separator and the trailing one is
// removed at the end, so the buffer transiently holds one byte more than the
// final result: "/a/b" becomes "/a/b/" before the trim. The bound has to cover
// that peak, not just the final length — otherwise append grows the engine's
// scratch buffer and the transform allocates on every request.
func (normalizePath) MaxOutputLen(n int) int { return n + 1 }

func (normalizePath) Apply(dst, src []byte) ([]byte, bool) {
	needs := false
	for i, c := range src {
		if c == '\\' || c == '.' || (c == '/' && i > 0 && src[i-1] == '/') {
			needs = true
			break
		}
	}
	if !needs {
		return src, false
	}

	// Split on either separator, resolving segments as we go.
	//
	// ".." pops the previous segment by scanning backwards through the output
	// rather than keeping a stack of segment offsets. A stack would be an
	// auxiliary allocation on the hot path — escape analysis cannot keep it on
	// the stack once it is appended to — and the backwards scan is amortised
	// linear over the whole path, since each byte is passed at most twice.
	dst = dst[:0]
	absolute := len(src) > 0 && (src[0] == '/' || src[0] == '\\')

	// base marks the end of the prefix that ".." can never pop past: the root
	// separator of an absolute path, or the leading "../" run of a relative
	// one. One ".." cannot cancel another, so leading ones extend base instead
	// of becoming poppable segments — otherwise "../../x" would collapse to "x".
	base := 0
	if absolute {
		dst = append(dst, '/')
		base = 1
	}

	start := 0
	for i := 0; i <= len(src); i++ {
		if i < len(src) && src[i] != '/' && src[i] != '\\' {
			continue
		}
		seg := src[start:i]
		start = i + 1

		switch {
		case len(seg) == 0 || (len(seg) == 1 && seg[0] == '.'):
			// An empty segment or "." contributes nothing.
		case len(seg) == 2 && seg[0] == '.' && seg[1] == '.':
			if len(dst) > base {
				// dst ends with "<segment>/"; drop it.
				d := len(dst) - 1
				for d > base && dst[d-1] != '/' {
					d--
				}
				dst = dst[:d]
			} else if !absolute {
				// Traversal above the start of a relative path is meaningful
				// and must be preserved, not silently dropped.
				dst = append(dst, ".."...)
				dst = append(dst, '/')
				base = len(dst)
			}
			// An absolute path cannot escape its root, so ".." at base is a
			// no-op rather than an error.
		default:
			dst = append(dst, seg...)
			dst = append(dst, '/')
		}
	}

	// Drop the trailing separator unless the input had one or the result is the
	// bare root.
	if n := len(dst); n > 1 && dst[n-1] == '/' {
		last := src[len(src)-1]
		if last != '/' && last != '\\' {
			dst = dst[:n-1]
		}
	}
	return dst, true
}

// EscapeDecode resolves backslash escape sequences the way a JavaScript or C
// string literal would: \xHH, \uHHHH, \0NNN, and the single-character escapes.
//
// SecLang spells this t:jsDecode and t:escapeSeqDecode, and between them they
// are 35 of CRS's directives — the largest transform in the ruleset that gwaf
// could not express.
//
// # Why a transform rather than a reading
//
// gwaf usually answers "the origin might decode this differently" with a
// *reading*: every plausible decoding is evaluated and a rule matches under any
// of them. That is the right shape for ambiguity the WAF cannot resolve, and it
// is what makes the CVE-2026-21876 class impossible here.
//
// This is not that. A backslash escape is unambiguous — "\x41" is "A" to every
// consumer that reads escapes at all — so there is nothing to enumerate. Making
// it a reading would add a decode pass to every value in every request to serve
// the rules that ask for it; as a transform it costs only where it is requested.
// With the latency budget already thin, that distinction is the whole argument.
var EscapeDecode rules.Transform = escapeDecode{}

type escapeDecode struct{}

func (escapeDecode) Name() string { return "escape_decode" }

// MaxOutputLen: decoding only ever shortens, since every escape is at least two
// bytes in and one byte out.
func (escapeDecode) MaxOutputLen(n int) int { return n }

func (escapeDecode) Apply(dst, src []byte) ([]byte, bool) {
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
		switch c := src[i+1]; {
		case c == 'x' || c == 'u':
			// Hex escapes. A malformed or truncated one is kept verbatim --
			// backslash included -- because "\x" is not an escape and pretending
			// it decodes to "x" would silently rewrite the value.
			width := 2
			if c == 'u' {
				width = 4
			}
			if i+1+width >= len(src) {
				dst = append(dst, src[i])
				i++
				continue
			}
			var v rune
			ok := true
			for k := 0; k < width; k++ {
				d, valid := unhex(src[i+2+k])
				if !valid {
					ok = false
					break
				}
				v = v<<4 | rune(d)
			}
			if !ok {
				dst = append(dst, src[i])
				i++
				continue
			}
			dst = appendRuneTo(dst, v)
			i += 2 + width
		case c >= '0' && c <= '7':
			// Octal, one to three digits.
			v, n := 0, 0
			for n < 3 && i+1+n < len(src) && src[i+1+n] >= '0' && src[i+1+n] <= '7' {
				v = v*8 + int(src[i+1+n]-'0')
				n++
			}
			if v > 0xFF {
				v = 0xFF
			}
			dst = append(dst, byte(v))
			i += 1 + n
		default:
			if b, ok := simpleEscape(c); ok {
				dst = append(dst, b)
				i += 2
				continue
			}
			// An escaped ordinary character is that character: "\q" is "q",
			// which is how a shell or a string literal reads it, and it is the
			// form "c\at" uses to hide "cat".
			dst = append(dst, c)
			i += 2
		}
	}
	return dst, true
}

// simpleEscape covers the single-character escapes both JavaScript and C share.
//
// "\a" is deliberately absent. JavaScript has no such escape and drops the
// backslash, and t:jsDecode is 28 of the 35 directives this transform serves, so
// JavaScript's reading is the one that matches most of the corpus. It also keeps
// "c\at" decoding to "cat", which is the evasion an attacker is actually
// writing, rather than to a bell character nobody sent.
func simpleEscape(c byte) (byte, bool) {
	switch c {
	case 'n':
		return '\n', true
	case 'r':
		return '\r', true
	case 't':
		return '\t', true
	case 'v':
		return '\v', true
	case 'f':
		return '\f', true
	case 'b':
		return '\b', true
	case '0':
		return 0, true
	}
	return 0, false
}

func indexByteIn(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// appendRuneTo writes r as UTF-8, or as a single byte when it fits, so a
// "A" and an "\x41" produce the same result.
func appendRuneTo(dst []byte, r rune) []byte {
	if r < 0x80 {
		return append(dst, byte(r))
	}
	var buf [4]byte
	n := encodeRune(buf[:], r)
	return append(dst, buf[:n]...)
}

func encodeRune(p []byte, r rune) int {
	switch {
	case r < 0x800:
		p[0] = 0xC0 | byte(r>>6)
		p[1] = 0x80 | byte(r)&0x3F
		return 2
	case r < 0x10000:
		p[0] = 0xE0 | byte(r>>12)
		p[1] = 0x80 | byte(r>>6)&0x3F
		p[2] = 0x80 | byte(r)&0x3F
		return 3
	default:
		p[0] = 0xF0 | byte(r>>18)
		p[1] = 0x80 | byte(r>>12)&0x3F
		p[2] = 0x80 | byte(r>>6)&0x3F
		p[3] = 0x80 | byte(r)&0x3F
		return 4
	}
}
