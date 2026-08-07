// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package interpret enumerates the plausible readings of an ambiguous value.
//
// # The problem
//
// A firewall and the origin behind it must agree on what a request says. When
// they disagree, the firewall inspects one string and the origin acts on
// another, and the gap between them is a bypass. This is not a hypothetical:
// CVE-2026-21876 (CVSS 9.3, January 2026) broke the OWASP Core Rule Set across
// ModSecurity v2, v3, and Coraza because a multipart charset was captured once
// and evaluated once, letting a UTF-7 payload through as something the origin
// would later read as HTML.
//
// The usual answer is to pick the single most likely decoding. That is a guess,
// and an attacker only has to find one origin that guesses differently.
//
// # The approach
//
// gwaf does not guess. A value that could be read several ways is evaluated
// every way, and a rule matching under any reading matches. Detection is
// therefore the union over readings, which is the safe direction: an extra
// reading can only cost work, never coverage.
//
// The cost is controlled by noticing that ambiguity is rare. Detect scans for
// the byte patterns that make a value ambiguous at all — a percent sign, a
// backslash, a UTF-7 shift — and a value containing none of them has exactly
// one reading and costs exactly what it costs today. Only genuinely ambiguous
// input pays for alternatives, and that input is precisely the input that
// deserves the scrutiny.
//
// # Bounds
//
// Readings are capped at MaxReadings. Ambiguity beyond the cap is reported
// rather than silently dropped, because a value too ambiguous to analyse is not
// the same as a value that is clean. See docs/CONCEPT.md §4.
package interpret

// Class is a bit set of the ambiguity kinds present in a value.
//
// Each class corresponds to a real disagreement observed between firewalls and
// origins, not to a theoretical encoding. Adding one means claiming some origin
// really does read input that way.
type Class uint16

const (
	// ClassDoubleEncoded marks input containing an encoded percent sign, so a
	// second decoding pass yields a different string. Proxies and application
	// servers that each decode once produce exactly this disagreement.
	ClassDoubleEncoded Class = 1 << iota

	// ClassSeparator marks a backslash, which Windows, .NET, and several Java
	// stacks treat as a path separator while POSIX origins do not.
	ClassSeparator

	// ClassNullTruncate marks an encoded or literal NUL. Handlers backed by C
	// string routines truncate there, so the origin may act on a prefix of what
	// the firewall inspected.
	//
	// This class matters for allowlist rules rather than signature rules. A
	// signature sees "/etc/passwd%00.jpg" either way, because the payload is a
	// prefix of the value. An allowlist checking "must end in .jpg" passes it
	// while the origin truncates and opens /etc/passwd — that is the gap this
	// reading closes, and it becomes load-bearing once schema validation lands.
	ClassNullTruncate

	// ClassOverlongUTF8 marks an overlong UTF-8 sequence such as %c0%ae. The
	// encoding is illegal, but permissive decoders still resolve it to ASCII —
	// historically to "." in directory traversal.
	ClassOverlongUTF8

	// ClassUTF7 marks a UTF-7 shift sequence. This is the CVE-2026-21876
	// vector: "+ADw-script+AD4-" is inert to a byte matcher and is "<script>"
	// to anything that decodes UTF-7.
	ClassUTF7

	// ClassHTMLEntity marks an HTML entity reference, which matters wherever
	// the value is reflected into a document before use.
	ClassHTMLEntity
)

// MaxReadings bounds the interpretations produced for one value, including the
// verbatim reading. It also sizes the reusable buffers in a Set.
const MaxReadings = 8

// maxEntityLen bounds how far an entity or UTF-7 run is scanned before being
// treated as literal text, so a pathological value cannot drive a long search.
const maxEntityLen = 32

// Any reports whether c names at least one ambiguity.
func (c Class) Any() bool { return c != 0 }

// Has reports whether c includes want.
func (c Class) Has(want Class) bool { return c&want != 0 }

// String implements fmt.Stringer, for compile reports and explain output.
func (c Class) String() string {
	if c == 0 {
		return "none"
	}
	var out []byte
	appendName := func(name string) {
		if len(out) > 0 {
			out = append(out, '|')
		}
		out = append(out, name...)
	}
	if c.Has(ClassDoubleEncoded) {
		appendName("double_encoded")
	}
	if c.Has(ClassSeparator) {
		appendName("separator")
	}
	if c.Has(ClassNullTruncate) {
		appendName("null_truncate")
	}
	if c.Has(ClassOverlongUTF8) {
		appendName("overlong_utf8")
	}
	if c.Has(ClassUTF7) {
		appendName("utf7")
	}
	if c.Has(ClassHTMLEntity) {
		appendName("html_entity")
	}
	return string(out)
}

// Detect reports which ambiguities are present in src.
//
// This runs on every value, so it is a single pass with no allocation and no
// decoding. It is deliberately permissive: a false positive here costs one
// extra reading, whereas a false negative is a missed interpretation and
// therefore a bypass. When in doubt, claim the ambiguity.
// ambiguityLead marks the bytes that can begin an ambiguous sequence.
//
// Detect runs on every value of every request, so its inner loop is one of the
// hottest in the engine. Almost no byte of real traffic can start an ambiguity,
// and a table lookup rejects those in a single indexed load — where the switch
// this replaced walked a chain of comparisons and lookaheads for every byte.
// The lookaheads still happen, but only for the handful of bytes that survive.
var ambiguityLead = func() (t [256]bool) {
	for _, c := range []byte{'%', '\\', 0x00, 0xc0, 0xc1, '+', '&'} {
		t[c] = true
	}
	return
}()

func Detect(src []byte) Class {
	var c Class

	for i := 0; i < len(src); i++ {
		if !ambiguityLead[src[i]] {
			continue
		}
		switch src[i] {
		case '%':
			// "%25" re-encodes a percent sign, so decoding twice differs from
			// decoding once.
			if i+2 < len(src) && src[i+1] == '2' && (src[i+2] == '5' || src[i+2] == '5'-32) {
				c |= ClassDoubleEncoded
			}
			// "%%32%65" is a malformed escape a strict decoder leaves alone but a
			// permissive one (Apache, CVE-2021-42013) collapses: the leading '%'
			// joins the decoded "2e" to form "%2e", which a second pass turns
			// into ".". A '%' immediately followed by another '%' is the lead of
			// that form, so it is a plausible double-decoding and gets its own
			// reading. A benign "%%" costs one extra reading, never a bypass.
			if i+1 < len(src) && src[i+1] == '%' {
				c |= ClassDoubleEncoded
			}
			// %00 is a NUL that a C-backed origin may truncate at.
			if i+2 < len(src) && src[i+1] == '0' && src[i+2] == '0' {
				c |= ClassNullTruncate
			}
			// Lead bytes of overlong two- and three-byte forms.
			if i+2 < len(src) {
				hi, ok1 := unhex(src[i+1])
				lo, ok2 := unhex(src[i+2])
				if ok1 && ok2 {
					b := hi<<4 | lo
					if b == 0xc0 || b == 0xc1 || b == 0xe0 {
						c |= ClassOverlongUTF8
					}
				}
			}
		case '\\':
			c |= ClassSeparator
		case 0x00:
			c |= ClassNullTruncate
		case 0xc0, 0xc1:
			// A raw overlong lead byte.
			c |= ClassOverlongUTF8
		case '+':
			// A UTF-7 shift is '+', a modified-base64 run, then an explicit '-'.
			//
			// The '-' is required here even though UTF-7 also permits implicit
			// termination by any non-base64 byte. Without it, every '+' used as
			// an encoded space — which is most query strings on the internet —
			// would be reported ambiguous and cost an extra reading. The
			// explicit form is what attack payloads use, because implicit
			// termination makes the decoder consume following text
			// unpredictably and the payload stops being reliable.
			//
			// Known limitation: an implicitly-terminated UTF-7 sequence is not
			// detected. Closing that would require reading every '+' in every
			// query string two ways, and the measured cost is not worth the
			// narrow gap. Revisit if a payload in the wild uses it.
			if j := utf7RunEnd(src, i); j > i+1 && j < len(src) && src[j] == '-' {
				c |= ClassUTF7
			}
		case '&':
			if i+1 < len(src) && (src[i+1] == '#' || isAlpha(src[i+1])) {
				c |= ClassHTMLEntity
			}
		}
	}
	return c
}

// Reading is one plausible interpretation of a value.
type Reading struct {
	// Bytes is the interpreted value. For the verbatim reading it aliases the
	// caller's input rather than copying.
	Bytes []byte

	// Class names the ambiguity this reading resolves. Zero for the verbatim
	// reading.
	Class Class
}

// Set builds and holds the readings of one value.
//
// A Set owns reusable buffers and is reset per value, so enumerating
// interpretations costs no allocation after warm-up. It is owned by one
// goroutine, like the transaction driving it.
type Set struct {
	readings [MaxReadings]Reading
	bufs     [MaxReadings][]byte
	n        int

	// truncated records that ambiguity exceeded MaxReadings. The caller must
	// treat this as a decision rather than ignoring it: a value too ambiguous
	// to enumerate has not been shown to be clean.
	truncated bool
}

// Len returns the number of readings built.
func (s *Set) Len() int { return s.n }

// At returns reading i.
func (s *Set) At(i int) Reading { return s.readings[i] }

// All returns the readings built for the current value.
func (s *Set) All() []Reading { return s.readings[:s.n] }

// Truncated reports that the value had more plausible readings than MaxReadings
// allows, so the enumeration is incomplete.
func (s *Set) Truncated() bool { return s.truncated }

// Build fills s with every plausible reading of src.
//
// The first reading is always src verbatim, so a value with no ambiguity yields
// exactly one reading and costs a single Detect pass. Alternatives are appended
// only for the classes actually present.
//
// Readings that decode to the same bytes as an earlier one are dropped: an
// alternative that says nothing new is pure cost.
func (s *Set) Build(src []byte, classes Class) {
	s.n = 0
	s.truncated = false

	// The verbatim reading is what the transform chain would have seen anyway,
	// so it is always present and never a copy.
	s.readings[s.n] = Reading{Bytes: src}
	s.n++

	if !classes.Any() {
		return
	}

	if classes.Has(ClassDoubleEncoded) {
		s.addDecoded(src, ClassDoubleEncoded, urlDecodeInto)
	}
	if classes.Has(ClassSeparator) {
		s.addDecoded(src, ClassSeparator, backslashToSlashInto)
	}
	if classes.Has(ClassNullTruncate) {
		s.addDecoded(src, ClassNullTruncate, truncateAtNullInto)
	}
	if classes.Has(ClassOverlongUTF8) {
		s.addDecoded(src, ClassOverlongUTF8, decodeOverlongInto)
	}
	if classes.Has(ClassUTF7) {
		s.addDecoded(src, ClassUTF7, decodeUTF7Into)
	}
	// The entity reading exists for origins that decode "&lt;script&gt;" and
	// then reflect the result into HTML -- a real double-decoding bug class.
	//
	// It is skipped when the value already contains raw markup, because that
	// combination is an author escaping deliberately rather than an encoding
	// trick. "Use the <code>&lt;script&gt;</code> tag" is how every
	// documentation page in existence writes about script tags, and decoding
	// the entities turns correct escaping into a blocked request. Calibration
	// found it in a CMS corpus; the ruleset had been punishing people for doing
	// the right thing.
	//
	// The cost is narrow and worth stating: an attacker who prefixes a benign
	// raw tag to an entity-encoded payload suppresses this reading. What they
	// gain still requires the origin to double-decode, and the raw tag they
	// added is itself inspected verbatim.
	if classes.Has(ClassHTMLEntity) && !hasRawMarkup(src) {
		s.addDecoded(src, ClassHTMLEntity, decodeEntitiesInto)
	}
}

// hasRawMarkup reports whether src contains a tag written literally, rather
// than one spelled out in entities.
//
// The same "'<' followed by a name" test detect/xss uses, and for the same
// reason: "if (a < b)" is arithmetic and "<code>" is markup.
func hasRawMarkup(src []byte) bool {
	for i := 0; i+1 < len(src); i++ {
		if src[i] != '<' {
			continue
		}
		c := src[i+1]
		if c == '/' && i+2 < len(src) {
			c = src[i+2]
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// addDecoded appends a reading produced by fn, unless it duplicates one already
// present or the cap has been reached.
func (s *Set) addDecoded(src []byte, class Class, fn func(dst, src []byte) []byte) {
	if s.n >= MaxReadings {
		s.truncated = true
		return
	}

	i := s.n
	s.bufs[i] = fn(s.bufs[i][:0], src)
	out := s.bufs[i]

	for j := range s.n {
		if string(s.readings[j].Bytes) == string(out) {
			return
		}
	}

	s.readings[i] = Reading{Bytes: out, Class: class}
	s.n++
}

// ---- individual interpretations --------------------------------------------
//
// Each function writes one reading into dst and returns it. They append to
// dst[:0] and never allocate when dst has capacity, which is what makes
// enumerating readings free after warm-up.

// urlDecodeInto applies one percent-decoding pass. Combined with the decode the
// transform chain already performs, this is the doubly-decoded reading.
//
// Malformed escapes are preserved verbatim rather than guessed at, matching
// rules/transform.URLDecode. The two must agree, or the alternative reading
// would itself introduce a disagreement.
func urlDecodeInto(dst, src []byte) []byte {
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
			dst = append(dst, c)
			i++
		default:
			dst = append(dst, c)
			i++
		}
	}
	return dst
}

// backslashToSlashInto reads backslashes as path separators, which Windows,
// .NET, and several Java stacks do.
func backslashToSlashInto(dst, src []byte) []byte {
	for _, c := range src {
		if c == '\\' {
			c = '/'
		}
		dst = append(dst, c)
	}
	return dst
}

// truncateAtNullInto reads the value as a C string: everything from the first
// NUL, encoded or literal, is discarded.
//
// The percent form is handled here as well as the raw byte because the origin
// may decode before the truncation happens, and gwaf cannot know which order a
// given stack uses.
func truncateAtNullInto(dst, src []byte) []byte {
	for i := 0; i < len(src); i++ {
		if src[i] == 0x00 {
			break
		}
		if src[i] == '%' && i+2 < len(src) && src[i+1] == '0' && src[i+2] == '0' {
			break
		}
		dst = append(dst, src[i])
	}
	return dst
}

// decodeOverlongInto resolves overlong UTF-8 sequences to the ASCII byte a
// permissive decoder would produce.
//
// The encoding is illegal and a correct decoder rejects it, but the ones that
// do not are the reason directory traversal via %c0%ae worked for years.
func decodeOverlongInto(dst, src []byte) []byte {
	// Percent-decode first so both %c0%ae and the raw bytes are covered.
	var scratch [512]byte
	decoded := src
	if hasPercent(src) {
		if len(src) <= len(scratch) {
			decoded = urlDecodeInto(scratch[:0], src)
		} else {
			decoded = urlDecodeInto(make([]byte, 0, len(src)), src)
		}
	}

	for i := 0; i < len(decoded); {
		c := decoded[i]
		switch {
		case (c == 0xc0 || c == 0xc1) && i+1 < len(decoded):
			// Two-byte overlong: the low six bits of the continuation byte
			// carry the ASCII value.
			cont := decoded[i+1]
			if cont&0xc0 == 0x80 {
				dst = append(dst, (c&0x1f)<<6|(cont&0x3f))
				i += 2
				continue
			}
			dst = append(dst, c)
			i++
		case c == 0xe0 && i+2 < len(decoded):
			// Three-byte overlong encoding an ASCII byte.
			c1, c2 := decoded[i+1], decoded[i+2]
			if c1&0xc0 == 0x80 && c2&0xc0 == 0x80 {
				r := rune(c&0x0f)<<12 | rune(c1&0x3f)<<6 | rune(c2&0x3f)
				if r < 0x80 {
					dst = append(dst, byte(r))
					i += 3
					continue
				}
			}
			dst = append(dst, c)
			i++
		default:
			dst = append(dst, c)
			i++
		}
	}
	return dst
}

// decodeUTF7Into resolves UTF-7 shift sequences to their ASCII equivalent.
//
// This is the CVE-2026-21876 vector. "+ADw-" is five inert bytes to a matcher
// and "<" to anything that decodes UTF-7, which historically included Internet
// Explorer and still includes several server-side charset converters. Only the
// ASCII range is resolved, because that is the range attack payloads live in.
func decodeUTF7Into(dst, src []byte) []byte {
	for i := 0; i < len(src); {
		if src[i] != '+' {
			dst = append(dst, src[i])
			i++
			continue
		}

		// "+-" is a literal plus sign.
		if i+1 < len(src) && src[i+1] == '-' {
			dst = append(dst, '+')
			i += 2
			continue
		}

		// Collect the base64 run.
		j := i + 1
		for j < len(src) && j-i <= maxEntityLen && isUTF7Base64(src[j]) {
			j++
		}
		if j == i+1 {
			dst = append(dst, '+')
			i++
			continue
		}

		dst = decodeUTF7Run(dst, src[i+1:j])

		// An explicit '-' terminates the run and is consumed.
		if j < len(src) && src[j] == '-' {
			j++
		}
		i = j
	}
	return dst
}

// decodeUTF7Run decodes one modified-base64 run into UTF-16 code units and
// appends the ASCII ones.
func decodeUTF7Run(dst, run []byte) []byte {
	var acc uint32
	var bits uint

	var units [maxEntityLen]uint16
	n := 0

	for _, c := range run {
		v, ok := utf7Value(c)
		if !ok {
			break
		}
		acc = acc<<6 | uint32(v)
		bits += 6
		if bits >= 16 {
			bits -= 16
			if n < len(units) {
				units[n] = uint16(acc >> bits)
				n++
			}
		}
	}

	for _, u := range units[:n] {
		// Only ASCII is resolved. Anything else is left out rather than
		// guessed at: inventing bytes the origin may not produce would create
		// a new disagreement instead of closing one.
		if u < 0x80 {
			dst = append(dst, byte(u))
		}
	}
	return dst
}

// decodeEntitiesInto resolves HTML entity references, which matter wherever the
// value is reflected into a document before use.
//
// Only the entities that appear in payloads are resolved, plus numeric forms.
// A general entity table would be large and would mostly add names no attacker
// needs.
func decodeEntitiesInto(dst, src []byte) []byte {
	for i := 0; i < len(src); {
		if src[i] != '&' {
			dst = append(dst, src[i])
			i++
			continue
		}

		if r, size, ok := decodeEntityAt(src[i:]); ok {
			if r < 0x80 {
				dst = append(dst, byte(r))
			} else {
				dst = appendRune(dst, r)
			}
			i += size
			continue
		}

		dst = append(dst, '&')
		i++
	}
	return dst
}

// decodeEntityAt decodes one entity reference at the start of s.
func decodeEntityAt(s []byte) (r rune, size int, ok bool) {
	if len(s) < 3 || s[0] != '&' {
		return 0, 0, false
	}

	// Numeric: &#60; or &#x3c;
	if s[1] == '#' {
		i := 2
		base := 10
		if i < len(s) && (s[i] == 'x' || s[i] == 'X') {
			base = 16
			i++
		}
		start := i
		var v rune
		for i < len(s) && i-start < 8 {
			d, ok := digitValue(s[i], base)
			if !ok {
				break
			}
			v = v*rune(base) + rune(d)
			i++
		}
		if i == start {
			return 0, 0, false
		}
		// The trailing semicolon is optional: browsers accept its absence and
		// so must anything modelling what they will do.
		if i < len(s) && s[i] == ';' {
			i++
		}
		if v > 0x10FFFF {
			return 0, 0, false
		}
		return v, i, true
	}

	// Named.
	for _, e := range namedEntities {
		if len(s) >= len(e.name) && string(s[:len(e.name)]) == e.name {
			return e.r, len(e.name), true
		}
	}
	return 0, 0, false
}

// namedEntities covers the references that appear in payloads. Longer names
// must precede shorter prefixes so the longest match wins.
var namedEntities = []struct {
	name string
	r    rune
}{
	{"&quot;", '"'},
	{"&apos;", '\''},
	{"&amp;", '&'},
	{"&lt;", '<'},
	{"&gt;", '>'},
	{"&#39;", '\''},
	{"&sol;", '/'},
	{"&bsol;", '\\'},
	{"&colon;", ':'},
	{"&lpar;", '('},
	{"&rpar;", ')'},
	{"&period;", '.'},
	{"&NewLine;", '\n'},
	{"&Tab;", '\t'},
}

// ---- helpers ---------------------------------------------------------------

func appendRune(dst []byte, r rune) []byte {
	switch {
	case r < 0x80:
		return append(dst, byte(r))
	case r < 0x800:
		return append(dst, byte(0xc0|r>>6), byte(0x80|r&0x3f))
	case r < 0x10000:
		return append(dst, byte(0xe0|r>>12), byte(0x80|r>>6&0x3f), byte(0x80|r&0x3f))
	default:
		return append(dst, byte(0xf0|r>>18), byte(0x80|r>>12&0x3f),
			byte(0x80|r>>6&0x3f), byte(0x80|r&0x3f))
	}
}

func hasPercent(s []byte) bool {
	for _, c := range s {
		if c == '%' {
			return true
		}
	}
	return false
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

func digitValue(c byte, base int) (int, bool) {
	var v int
	switch {
	case c >= '0' && c <= '9':
		v = int(c - '0')
	case c >= 'a' && c <= 'f':
		v = int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		v = int(c-'A') + 10
	default:
		return 0, false
	}
	if v >= base {
		return 0, false
	}
	return v, true
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// utf7RunEnd returns the index just past the modified-base64 run starting at
// src[start+1], bounded by maxEntityLen so a pathological value cannot drive a
// long scan.
func utf7RunEnd(src []byte, start int) int {
	j := start + 1
	for j < len(src) && j-start <= maxEntityLen && isUTF7Base64(src[j]) {
		j++
	}
	return j
}

// isUTF7Base64 reports whether c can appear in a UTF-7 modified-base64 run.
func isUTF7Base64(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '+' || c == '/'
}

// utf7Value maps a modified-base64 byte to its six-bit value.
func utf7Value(c byte) (byte, bool) {
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
	default:
		return 0, false
	}
}
