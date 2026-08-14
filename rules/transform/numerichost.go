// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package transform

import "github.com/gsoultan/gwaf/rules"

// NumericHost rewrites an IPv4 address written in any form inet_aton accepts
// into its dotted-quad spelling.
//
// # Why a transform and not a rule literal
//
// A rule that lists the spellings of an address is enumerating an infinite set.
// inet_aton takes one, two, three or four parts; each part may be decimal,
// octal or hexadecimal; and a short form spreads the remaining bytes over the
// last part. 169.254.169.254 is therefore also 2852039166, 0xa9fea9fe,
// 0251.0376.0251.0376, 169.16689662, 0xa9.254.0xa9.254 and dozens more, and
// listing them is the regex-bag approach this project is defined against. The
// address is a *number*; the spelling is an encoding of it. So this decodes the
// encoding and lets the rule keep matching one literal.
//
// libcurl, PHP, Java and glibc's getaddrinfo all accept these forms, which is
// what makes the rewrite a reading an origin really performs rather than a
// theoretical one.
//
// # Why it is safe to run on ordinary traffic
//
// A token is rewritten only when every part parses and the whole token is
// consumed, so "10.0.1.2" survives untouched (it is already canonical) and
// "report.2026.final" is not a host at all. A value with no candidate returns
// the input slice and copies nothing, which is the same contract every other
// transform here keeps.
//
// A bare integer is deliberately *not* rewritten. "2130706433" is a plausible
// identifier, and turning every large number in every parameter into an address
// would invent hosts nobody sent -- the mistake ClassBestFit avoids by folding
// only punctuation. A token has to look like an address, which here means it
// carries a dot or a hex marker.
var NumericHost rules.Transform = numericHost{}

type numericHost struct{}

func (numericHost) Name() string { return "numeric_host" }

// MaxOutputLen bounds growth. The longest dotted-quad is 15 bytes and the
// shortest input that produces one is 3 ("1.1"), so a token can grow. Five times
// the input covers the worst case with room to spare.
func (numericHost) MaxOutputLen(n int) int { return n*5 + 16 }

func (numericHost) Apply(dst, src []byte) ([]byte, bool) {
	if !hasNumericHostCandidate(src) {
		return src, false
	}

	dst = dst[:0]
	changed := false
	for i := 0; i < len(src); {
		if !hostTokenStart(src, i) {
			dst = append(dst, src[i])
			i++
			continue
		}
		end := hostTokenEnd(src, i)
		tok := src[i:end]
		if addr, ok := parseNumericHost(tok, inHostPosition(src, i, end)); ok {
			before := len(dst)
			dst = appendDottedQuad(dst, addr)
			// A four-part decimal address renders to the bytes it arrived as.
			// Reporting that as a change would copy the value for nothing, and
			// the contract here is that already-normal traffic copies nothing.
			if !equalBytes(dst[before:], tok) {
				changed = true
			}
			i = end
			continue
		}
		// Not an address after all: copy the token verbatim rather than
		// re-examining every byte inside it.
		dst = append(dst, src[i:end]...)
		i = end
	}
	if !changed {
		return src, false
	}
	return dst, true
}

// hasNumericHostCandidate is the cheap pre-check that keeps ordinary traffic
// free. A rewrite needs a digit, and it needs either a dot or an "x" for the hex
// marker; text carrying none of that cannot contain a token this rewrites.
func hasNumericHostCandidate(src []byte) bool {
	digit, mark := false, false
	for _, c := range src {
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case c == '.' || c == 'x' || c == 'X':
			mark = true
		}
		if digit && mark {
			return true
		}
	}
	return false
}

// hostTokenStart reports whether a host token may begin at i: it starts with a
// digit and sits at a boundary, so the digits inside "v1.2.3" or "abc123" are
// not mistaken for one.
func hostTokenStart(src []byte, i int) bool {
	if src[i] < '0' || src[i] > '9' {
		return false
	}
	if i == 0 {
		return true
	}
	switch src[i-1] {
	case '/', '@', ':', '=', ',', '[', '(', '"', '\'', ' ', '\t':
		return true
	}
	return false
}

// inHostPosition reports whether the token at src[i:end] sits where a host is
// written rather than where a number is.
//
// A value that is nothing but the token is a host: a parameter carrying exactly
// "127.1" is an address. Otherwise the preceding byte decides, and the two cases
// are genuinely different -- after "//", "@", ":" or "[" the grammar is a URL
// authority and a bare number there is a host, while after a space or a comma
// it is prose and "price 1.5" is a price.
func inHostPosition(src []byte, i, end int) bool {
	if i == 0 {
		return end == len(src) || src[end] == '/' || src[end] == ':'
	}
	switch src[i-1] {
	case '/', '@', ':', '[':
		return true
	}
	return false
}

// hostTokenEnd returns the index just past the token beginning at i.
func hostTokenEnd(src []byte, i int) int {
	j := i
	for j < len(src) {
		c := src[j]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
			c == '.' || c == 'x' || c == 'X' {
			j++
			continue
		}
		break
	}
	return j
}

// maxHostToken bounds the token examined. The longest legal spelling is a
// four-part dotted-hex form; anything longer is not an address and is not worth
// parsing.
const maxHostToken = 24

// parseNumericHost decodes one inet_aton spelling into a 32-bit address.
//
// Returns false unless the whole token is consumed, every part is in range, and
// the token carries a dot or a hex marker -- a bare integer is left alone.
//
// whole says the token is the entire value. It decides the ambiguous case: a
// short form whose last part fits in one byte is indistinguishable from an
// ordinary decimal number, so "1.5" in a sentence stays a number while a
// parameter that is exactly "127.1" is read as the address it plainly is. A
// short form whose last part *cannot* fit in one byte -- "169.16689662" -- is
// unambiguous wherever it appears, because no ordinary decimal is written that
// way and inet_aton has only one reading of it.
func parseNumericHost(tok []byte, whole bool) (uint32, bool) {
	if len(tok) == 0 || len(tok) > maxHostToken {
		return 0, false
	}
	if tok[len(tok)-1] == '.' {
		return 0, false
	}

	var parts [4]uint64
	n := 0
	sawDot, sawHex := false, false

	for i := 0; i < len(tok); {
		if n == 4 {
			return 0, false
		}
		v, w, hex, ok := parseHostPart(tok[i:])
		if !ok {
			return 0, false
		}
		sawHex = sawHex || hex
		parts[n] = v
		n++
		i += w
		if i < len(tok) {
			if tok[i] != '.' {
				return 0, false
			}
			sawDot = true
			i++
		}
	}
	if n == 0 || (!sawDot && !sawHex) {
		return 0, false
	}

	// inet_aton: the last part spreads over the bytes the earlier parts left.
	// a.b.c.d gives one byte each; a.b.c gives b and c the low two bytes; a.b
	// gives b the low three; a alone is the whole address.
	for i := 0; i < n-1; i++ {
		if parts[i] > 0xff {
			return 0, false
		}
	}
	last := parts[n-1]
	span := uint(8 * (5 - n)) // 4 parts -> 8 bits, 1 part -> 32 bits
	if span < 32 && last >= uint64(1)<<span {
		return 0, false
	}
	if span == 32 && last > 0xffffffff {
		return 0, false
	}

	// The ambiguous shape: fewer than four parts, no hex marker, and a last
	// part small enough to be an ordinary number. Only read it as an address
	// when it is the whole value.
	if n < 4 && !sawHex && last <= 0xff && !whole {
		return 0, false
	}

	var addr uint32
	for i := 0; i < n-1; i++ {
		addr |= uint32(parts[i]) << uint(8*(3-i))
	}
	return addr | uint32(last), true
}

// parseHostPart reads one part and reports its value, width, and whether it was
// written in hex. Leading "0x" is hexadecimal and a leading "0" is octal, which
// is what inet_aton does and what a rule listing decimal spellings misses.
func parseHostPart(s []byte) (val uint64, width int, hex bool, ok bool) {
	if len(s) == 0 || s[0] < '0' || s[0] > '9' {
		return 0, 0, false, false
	}
	base, i := uint64(10), 0
	if s[0] == '0' {
		if len(s) > 1 && (s[1] == 'x' || s[1] == 'X') {
			if len(s) < 3 || unhexDigit(s[2]) < 0 {
				return 0, 0, false, false
			}
			base, i, hex = 16, 2, true
		} else {
			base, i = 8, 1
			// A bare "0" is a legal part on its own.
			if len(s) == 1 || s[1] == '.' {
				return 0, 1, false, true
			}
		}
	}

	start := i
	for i < len(s) {
		d := unhexDigit(s[i])
		if d < 0 || uint64(d) >= base {
			break
		}
		val = val*base + uint64(d)
		if val > 0xffffffff {
			return 0, 0, false, false
		}
		i++
	}
	if i == start {
		return 0, 0, false, false
	}
	return val, i, hex, true
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func unhexDigit(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func appendDottedQuad(dst []byte, addr uint32) []byte {
	for i := 3; i >= 0; i-- {
		dst = appendUint(dst, uint64(addr>>uint(8*i))&0xff)
		if i > 0 {
			dst = append(dst, '.')
		}
	}
	return dst
}

func appendUint(dst []byte, v uint64) []byte {
	if v == 0 {
		return append(dst, '0')
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return append(dst, buf[i:]...)
}
