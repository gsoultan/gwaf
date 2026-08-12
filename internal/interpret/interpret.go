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

	// ClassMultiEncoded marks input encoded more than twice, and exists as its
	// own reading rather than as more passes on ClassDoubleEncoded because
	// decoding further can destroy the evidence.
	//
	// "/cgi-bin/%%32%65%%32%65%2fapp.conf" (CVE-2021-42013) is the case that
	// proved it: one pass leaves "%2e%2e/app.conf", where the traversal is
	// visible, and decoding to the fixed point yields "/cgi-bin/../app.conf",
	// which normalises to "/app.conf" and looks like an ordinary request. The
	// two readings answer different questions and both are needed.
	//
	// Detected only on "%2525", the lead of a genuine triple encoding, so an
	// ordinary doubly-encoded value costs nothing.
	ClassMultiEncoded

	// ClassPercentU marks "%uXXXX", which is IIS's own encoding and is not part
	// of any URI standard. IIS and ASP.NET decode it anyway, and everything that
	// fronts them has to know that: it is how the Unicode traversal of MS00-078
	// worked, and %u002e%u002e%u2215 still reaches an unpatched stack today.
	//
	// The reading also resolves the characters Windows best-fit maps to ASCII
	// when narrowing UTF-16 — U+2215 DIVISION SLASH and U+FF0F FULLWIDTH SOLIDUS
	// both arrive at the origin as "/". That conversion is a property of the
	// platform rather than of the encoding, which is exactly the kind of
	// disagreement this package exists to enumerate.
	ClassPercentU

	// ClassBestFit marks characters that fold onto ASCII punctuation, sent as
	// the characters themselves rather than as a %u escape.
	//
	// ClassPercentU already claims that U+FF1C and U+2215 arrive at a handler as
	// '<' and '/'. Making that claim for only one spelling is not a decision, it
	// is a gap: the pentest harness sent "＜script＞" as UTF-8 and it walked
	// through while "%uFF1Cscript%uFF1E" was blocked. Same characters, same
	// folding, and NFKC normalisation in .NET and Java reaches the same place by
	// a different route.
	//
	// Only punctuation folds, which is what keeps the reading narrow. Fullwidth
	// letters and digits are ordinary Japanese, Chinese and Korean input and are
	// left exactly as they are — a WAF that rewrote them would be inventing text
	// nobody sent, and half of Asia types them daily.
	ClassBestFit

	// ClassStringConcat marks adjacent string literals joined by "." or "+",
	// and hex escapes inside a quoted run: the pieces a language assembles into
	// an identifier before it runs.
	//
	// A red-team round of language-specific evasions produced five payloads of
	// exactly one shape:
	//
	//	('sys'.'tem')('id')                 PHP concatenation
	//	window['ale'+'rt'](1)               JavaScript concatenation
	//	"\x73\x79\x73\x74\x65\x6d"('id')   PHP hex escapes
	//
	// None contains the word it calls. A literal list for them is the regex bag
	// this project is defined against -- there are infinitely many spellings of
	// "system" -- so the answer is the same one this package gives everywhere
	// else: the origin performs a reading, so evaluate that reading.
	//
	// Only *quoted* pieces fold. An unquoted identifier beside a dot is property
	// access far more often than it is concatenation, and folding "user.name"
	// into "username" would invent text nobody sent -- the mistake ClassBestFit
	// avoids by folding only punctuation.
	ClassStringConcat
)

// MaxReadings bounds the interpretations produced for one value, including the
// verbatim reading. It also sizes the reusable buffers in a Set.
//
// Eight classes plus verbatim is nine; the tenth slot is headroom so that adding
// a class is not silently a truncation.
const MaxReadings = 10

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
	if c.Has(ClassMultiEncoded) {
		appendName("multi_encoded")
	}
	if c.Has(ClassPercentU) {
		appendName("percent_u")
	}
	if c.Has(ClassStringConcat) {
		appendName("string_concat")
	}
	if c.Has(ClassBestFit) {
		appendName("best_fit")
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
	// 0xca, 0xe2 and 0xef are the UTF-8 lead bytes of the blocks holding the
	// characters that fold onto ASCII punctuation: U+02BC, the U+20xx marks, and
	// the fullwidth forms. They are common leads, so Detect only pays a table
	// lookup for them and claims the class when the rune is actually in it.
	// The quotes lead ClassStringConcat. They are common bytes, so Detect only
	// claims the class after confirming the shape -- a quote closing, an
	// operator, and a quote opening -- which no ordinary quoted text contains.
	for _, c := range []byte{'%', '\\', 0x00, 0xc0, 0xc1, '+', '&', 0xca, 0xe2, 0xef, '\'', '"'} {
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
		case '\'', '"':
			// A closing quote, an operator, an opening quote. Whitespace is
			// allowed between because the languages allow it.
			j := i + 1
			for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
				j++
			}
			if j < len(src) && (src[j] == '.' || src[j] == '+') {
				j++
				for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
					j++
				}
				if j < len(src) && (src[j] == '\'' || src[j] == '"') {
					c |= ClassStringConcat
				}
			}

		case '%':
			// "%25" re-encodes a percent sign, so decoding twice differs from
			// decoding once.
			if i+2 < len(src) && src[i+1] == '2' && (src[i+2] == '5' || src[i+2] == '5'-32) {
				c |= ClassDoubleEncoded
				// "%2525" is a percent encoded twice over, so the value survives
				// two decoders and is still encoded. That needs the fixed-point
				// reading as well as the one-pass one.
				if i+4 < len(src) && src[i+3] == '2' && (src[i+4] == '5' || src[i+4] == '5'-32) {
					c |= ClassMultiEncoded
				}
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
			// "%u002e" is IIS's non-standard encoding. Four hex digits are
			// required, so "%username%" and "%u" alone cost nothing.
			if i+5 < len(src) && (src[i+1] == 'u' || src[i+1] == 'U') {
				if _, ok := hex4(src[i+2:]); ok {
					c |= ClassPercentU
				}
			}
			// A percent-encoded character that folds onto ASCII punctuation.
			if r, n := percentRuneAt(src, i); n > 0 {
				if _, ok := bestFitASCII[r]; ok {
					c |= ClassBestFit
				}
			}
			// "%26%2360%3B" is "&#60;" once. Readings are built before the
			// transform chain, so an entity that arrived over a query string is
			// still wearing its escapes and the literal '&' below never fires --
			// which is every entity payload a browser ever sends.
			if b, n := percentByteAt(src, i); n == 3 && b == '&' {
				if nb, _ := percentByteAt(src, i+n); nb == '#' || isAlpha(nb) {
					c |= ClassHTMLEntity
				}
			}
			// "%2B" is the only way a client can send a UTF-7 shift: a bare '+'
			// in a query string means space, so every real payload is encoded and
			// the literal-'+' case below never saw one. That made the reading
			// named for CVE-2026-21876 inert against the vector it exists for.
			if b, n := percentByteAt(src, i); n == 3 && b == '+' {
				if j := utf7RunEnd(src, i+n); j > i+n && j < len(src) && src[j] == '-' {
					c |= ClassUTF7
				}
			}
			// "%5C" is a backslash. Masked in practice by rules that match the
			// backslash form directly, but a class that is blind to the only
			// spelling a query string carries is a class waiting to be relied on.
			if b, n := percentByteAt(src, i); n == 3 && b == '\\' {
				c |= ClassSeparator
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
			// A hex or octal escape. PHP and C both read "\x73" and "\163" as
			// 's', so a value carrying one has a reading where the escapes are
			// resolved.
			//
			// Claimed here rather than from the quote, and the difference is
			// cost: a quote is a common byte and scanning forward from each one
			// for an escape was 3.5% of the benign path. A backslash is already
			// a lead, the check is two comparisons, and an escape outside quotes
			// merely produces a reading identical to the verbatim one -- which
			// Set.Build drops.
			if i+1 < len(src) {
				n := src[i+1]
				if (n == 'x' || n == 'X') && i+3 < len(src) &&
					isHexDigit(src[i+2]) && isHexDigit(src[i+3]) {
					c |= ClassStringConcat
				} else if n >= '0' && n <= '7' {
					c |= ClassStringConcat
				}
			}
		case 0x00:
			c |= ClassNullTruncate
		case 0xc0, 0xc1:
			// A raw overlong lead byte.
			c |= ClassOverlongUTF8
		case 0xca, 0xe2, 0xef:
			// A character that folds onto ASCII punctuation, sent as itself.
			if r, n := decodeRune(src[i:]); n > 0 {
				if _, ok := bestFitASCII[r]; ok {
					c |= ClassBestFit
				}
			}
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
	if classes.Has(ClassMultiEncoded) {
		s.addDecoded(src, ClassMultiEncoded, urlDecodeRepeatedInto)
	}
	if classes.Has(ClassPercentU) {
		s.addDecoded(src, ClassPercentU, decodePercentUInto)
	}
	if classes.Has(ClassStringConcat) {
		s.addDecoded(src, ClassStringConcat, foldStringConcatInto)
	}
	if classes.Has(ClassBestFit) {
		s.addDecoded(src, ClassBestFit, foldBestFitInto)
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
//
// It reads through percent escapes because the entity reading does. A value from
// a query string spells "<code>" as "%3Ccode%3E", and a guard that only saw the
// literal form would let "Use the <code>&lt;script&gt;</code> tag" build the
// decoded reading after all — which is the CMS false positive the guard exists
// to prevent, arriving by the back door.
func hasRawMarkup(src []byte) bool {
	for i := 0; i < len(src); {
		b, n := percentByteAt(src, i)
		if n == 0 {
			i++
			continue
		}
		if b != '<' {
			i += n
			continue
		}
		j := i + n
		c, cn := percentByteAt(src, j)
		if cn > 0 && c == '/' {
			c, cn = percentByteAt(src, j+cn)
		}
		if cn > 0 && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return true
		}
		i += n
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

// urlDecodeRepeatedInto decodes until the value stops changing, bounded.
//
// One extra pass covers a proxy and an origin that each decode once. It does not
// cover three, and "%25252e%25252e%25252f" walked through on exactly that
// arithmetic while the double-encoded form was blocked — a CDN in front of a
// proxy in front of an application is three decoders, and that is an ordinary
// deployment rather than an exotic one.
//
// Bounded at four passes — a CDN, a reverse proxy, an application server and a
// framework is as long as a real chain gets. It is a fixed bound rather than a
// loop to convergence because every ceiling in this engine is explicit
// (CLAUDE.md §2): each pass rescans the value, so an unbounded loop prices a
// pathological input at O(n²) and hands an attacker the fuel budget.
func urlDecodeRepeatedInto(dst, src []byte) []byte {
	dst = urlDecodeInto(dst, src)
	for pass := 0; pass < 3; pass++ {
		if !hasPercent(dst) {
			break
		}
		n := urlDecodeInPlace(dst)
		if n == len(dst) {
			break // nothing decoded; already at the fixed point
		}
		dst = dst[:n]
	}
	return dst
}

// urlDecodeInPlace decodes b into itself and returns the new length. Safe
// because decoding only ever shrinks, so the write cursor trails the read one.
func urlDecodeInPlace(b []byte) int {
	w := 0
	for i := 0; i < len(b); {
		if b[i] == '%' && i+2 < len(b) {
			hi, ok1 := unhex(b[i+1])
			lo, ok2 := unhex(b[i+2])
			if ok1 && ok2 {
				b[w] = hi<<4 | lo
				w++
				i += 3
				continue
			}
		}
		b[w] = b[i]
		w++
		i++
	}
	return w
}

// hex4 reads four hex digits and returns the value they spell.
func hex4(src []byte) (uint16, bool) {
	if len(src) < 4 {
		return 0, false
	}
	var v uint16
	for i := range 4 {
		d, ok := unhex(src[i])
		if !ok {
			return 0, false
		}
		v = v<<4 | uint16(d)
	}
	return v, true
}

// bestFitASCII maps the characters Windows narrows to an ASCII byte when it
// converts UTF-16 to a single-byte code page. Only the ones that matter for
// traversal and injection are listed: a full best-fit table is thousands of
// entries and every one of them is a claim about a code page.
var bestFitASCII = map[uint16]byte{
	0x2215: '/',  // DIVISION SLASH
	0x2044: '/',  // FRACTION SLASH
	0xFF0F: '/',  // FULLWIDTH SOLIDUS
	0xFF3C: '\\', // FULLWIDTH REVERSE SOLIDUS
	0xFF0E: '.',  // FULLWIDTH FULL STOP
	0xFF07: '\'', // FULLWIDTH APOSTROPHE
	0x2032: '\'', // PRIME
	0x02BC: '\'', // MODIFIER LETTER APOSTROPHE
	0xFF1C: '<',  // FULLWIDTH LESS-THAN SIGN
	0xFF1E: '>',  // FULLWIDTH GREATER-THAN SIGN
	0xFF08: '(',  // FULLWIDTH LEFT PARENTHESIS
	0xFF09: ')',  // FULLWIDTH RIGHT PARENTHESIS
	0xFF1D: '=',  // FULLWIDTH EQUALS SIGN
}

// percentRuneAt reads a percent-encoded UTF-8 sequence at i and returns its code
// point and the number of source bytes it occupies.
//
// It exists because readings are enumerated before the transform chain runs, so
// a value still wearing its percent-encoding is what Detect sees. "＜" on the
// wire is "%EF%BC%9C", and without reading through the escapes the fullwidth
// reading never fires for any value that arrived over a query string — which is
// all of them. The ASCII cases need no such help: "%3C" is decoded by the chain
// into a byte a rule already matches.
func percentRuneAt(src []byte, i int) (uint16, int) {
	b, n := percentByteAt(src, i)
	switch {
	case n == 0:
		return 0, 0
	case b&0xf0 == 0xe0:
		b1, n1 := percentByteAt(src, i+n)
		b2, n2 := percentByteAt(src, i+n+n1)
		if n1 == 0 || n2 == 0 || b1&0xc0 != 0x80 || b2&0xc0 != 0x80 {
			return 0, 0
		}
		return uint16(b&0x0f)<<12 | uint16(b1&0x3f)<<6 | uint16(b2&0x3f), n + n1 + n2
	case b&0xe0 == 0xc0:
		b1, n1 := percentByteAt(src, i+n)
		if n1 == 0 || b1&0xc0 != 0x80 {
			return 0, 0
		}
		return uint16(b&0x1f)<<6 | uint16(b1&0x3f), n + n1
	}
	return 0, 0
}

// percentByteAt reads one byte written as "%XX", or as itself.
func percentByteAt(src []byte, i int) (byte, int) {
	if i >= len(src) {
		return 0, 0
	}
	if src[i] == '%' && i+2 < len(src) {
		hi, ok1 := unhex(src[i+1])
		lo, ok2 := unhex(src[i+2])
		if ok1 && ok2 {
			return hi<<4 | lo, 3
		}
		return 0, 0
	}
	return src[i], 1
}

// decodeRune reads one UTF-8 sequence and returns its code point and width.
//
// Only the two- and three-byte forms are read, because everything in
// bestFitASCII lives below U+10000 and a four-byte sequence cannot be in the
// table. A malformed sequence returns a width of 0 and the caller moves on a
// byte at a time, which is what keeps a truncated value from being skipped past.
func decodeRune(b []byte) (uint16, int) {
	if len(b) >= 3 && b[0]&0xf0 == 0xe0 && b[1]&0xc0 == 0x80 && b[2]&0xc0 == 0x80 {
		return uint16(b[0]&0x0f)<<12 | uint16(b[1]&0x3f)<<6 | uint16(b[2]&0x3f), 3
	}
	if len(b) >= 2 && b[0]&0xe0 == 0xc0 && b[1]&0xc0 == 0x80 {
		return uint16(b[0]&0x1f)<<6 | uint16(b[1]&0x3f), 2
	}
	return 0, 0
}

// foldBestFitInto rewrites the characters that narrow to ASCII punctuation and
// leaves everything else byte for byte.
//
// Leaving the rest alone is the whole safety argument. Fullwidth letters and
// digits are ordinary CJK input, so "価格は１２３４円です" comes out unchanged
// while "＜script＞" comes out as markup, and only the second is something a rule
// should have an opinion about.
func foldBestFitInto(dst, src []byte) []byte {
	for i := 0; i < len(src); {
		// Percent-encoded first: a value that arrived over a query string is
		// still wearing its escapes when readings are built.
		if r, n := percentRuneAt(src, i); n > 0 {
			if b, ok := bestFitASCII[r]; ok {
				dst = append(dst, b)
				i += n
				continue
			}
		}
		if r, n := decodeRune(src[i:]); n > 0 {
			if b, ok := bestFitASCII[r]; ok {
				dst = append(dst, b)
				i += n
				continue
			}
			dst = append(dst, src[i:i+n]...)
			i += n
			continue
		}
		dst = append(dst, src[i])
		i++
	}
	return dst
}

// decodePercentUInto resolves "%uXXXX" the way IIS does.
//
// An ASCII code point becomes its byte. A character Windows best-fit maps to
// ASCII becomes what it maps to, which is the whole point of the reading:
// %u2215 is not a slash to anything that reads Unicode correctly, and is a slash
// by the time it reaches the handler. Anything else contributes its low byte,
// which is what a narrowing conversion without a mapping produces.
func decodePercentUInto(dst, src []byte) []byte {
	for i := 0; i < len(src); {
		if src[i] == '%' && i+5 < len(src) && (src[i+1] == 'u' || src[i+1] == 'U') {
			if v, ok := hex4(src[i+2:]); ok {
				switch {
				case v < 0x80:
					dst = append(dst, byte(v))
				default:
					if b, mapped := bestFitASCII[v]; mapped {
						dst = append(dst, b)
					} else {
						dst = append(dst, byte(v))
					}
				}
				i += 6
				continue
			}
		}
		dst = append(dst, src[i])
		i++
	}
	return dst
}

// backslashToSlashInto reads backslashes as path separators, which Windows,
// .NET, and several Java stacks do.
func backslashToSlashInto(dst, src []byte) []byte {
	for i := 0; i < len(src); {
		// "%5C" as well as a literal backslash: the reading is built before the
		// transform chain, so a value from a query string still wears its
		// escapes. Only the backslash is decoded here — the rest is copied
		// verbatim, so this stays a separator reading rather than turning into a
		// second URL decoder.
		if b, n := percentByteAt(src, i); n == 3 && b == '\\' {
			dst = append(dst, '/')
			i += n
			continue
		}
		c := src[i]
		if c == '\\' {
			c = '/'
		}
		dst = append(dst, c)
		i++
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
	// A shift arrives as "%2B", because a literal '+' in a query string is a
	// space. Undo that layer first so the scan below sees the '+' it looks for;
	// the UTF-7 decoding is then identical for both spellings.
	//
	// Not decoded in place, unlike the entity reading: a long UTF-7 run can
	// *grow*, since n base64 characters carry 3n/8 UTF-16 units and each can
	// reach three bytes of UTF-8. The scratch buffer is only allocated for a
	// value that carries both a percent escape and a shift sequence, and
	// addDecoded keeps it for reuse afterwards.
	if hasPercent(src) {
		return utf7Decode(dst, urlDecodeInto(make([]byte, 0, len(src)), src))
	}
	return utf7Decode(dst, src)
}

func utf7Decode(dst, src []byte) []byte {
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
	// A value that arrived over a query string is percent-encoded, so "&#60;" is
	// "%26%2360%3B" and the scan below would walk past it. Undo that layer first;
	// the entity decoding is then the same for both spellings.
	if hasPercent(src) {
		dst = urlDecodeInto(dst[:0], src)
		return dst[:decodeEntitiesInPlace(dst)]
	}
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

// decodeEntitiesInPlace collapses entity references in b and returns the new
// length.
//
// Safe in place because an entity never grows: the shortest reference is four
// bytes ("&lt;", "&#9;") and the longest rune it can name encodes to four, so
// the write cursor never passes the read cursor.
func decodeEntitiesInPlace(b []byte) int {
	w := 0
	for i := 0; i < len(b); {
		if b[i] != '&' {
			b[w] = b[i]
			w++
			i++
			continue
		}
		if r, size, ok := decodeEntityAt(b[i:]); ok {
			if r < 0x80 {
				b[w] = byte(r)
				w++
			} else {
				var tmp [4]byte
				n := len(appendRune(tmp[:0], r))
				copy(b[w:], tmp[:n])
				w += n
			}
			i += size
			continue
		}
		b[w] = '&'
		w++
		i++
	}
	return w
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

// isHexDigit reports whether c is an ASCII hex digit.
func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// foldStringConcatInto writes the reading a language parser produces: adjacent
// string literals joined into one, and hex escapes inside them resolved.
//
// # What is folded, and what is left alone
//
// Only quoted pieces, and only across "." or "+". Everything outside a quoted
// run is copied verbatim, so "('sys'.'tem')('id')" becomes "(system)(id)" --
// the parentheses stay, because they are what makes the result a call rather
// than a word, and the detectors read that structure.
//
// The quotes themselves are dropped, which is the whole point: "sys" and "tem"
// are two tokens to a byte matcher and one identifier to a parser.
//
// Escapes are resolved inside a quoted run only. "\x73" outside quotes is not a
// PHP escape, it is four characters, and resolving it there would invent bytes.
// \n, \t and \\ are resolved for the same reason a language does; an unknown
// escape keeps its backslash, matching what a lenient parser does with it.
//
// Output is never longer than input: quotes and operators are removed and an
// escape shrinks. So MaxOutputLen is srcLen and the buffer never grows twice.
func foldStringConcatInto(dst, src []byte) []byte {
	for i := 0; i < len(src); {
		c := src[i]
		if c != '\'' && c != '"' && c != '`' {
			dst = append(dst, c)
			i++
			continue
		}

		// Find the extent of this run and whether an operator joins it to
		// another. Only a *joined* run loses its quotes: an isolated literal
		// keeps them, because the quotes are evidence in their own right --
		// rule 4023 reads them as the command being passed to system(, and
		// folding "('id')" into "(id)" would delete the thing it looks for.
		runStart, runEnd, closed := i+1, 0, false
		runEnd, closed = scanQuoted(src, i)
		next := joinedLiteralAt(src, runEnd)
		if next < 0 {
			dst = append(dst, c)
			dst = appendUnescaped(dst, quotedContent(src, runStart, runEnd, closed))
			if closed {
				dst = append(dst, src[runEnd-1])
			}
			i = runEnd
			continue
		}

		// A concatenation: emit the pieces with no quotes and no operators, so
		// the identifier the parser builds appears as one token.
		dst = appendUnescaped(dst, quotedContent(src, runStart, runEnd, closed))
		i = next
		for i < len(src) {
			end, cl := scanQuoted(src, i)
			dst = appendUnescaped(dst, quotedContent(src, i+1, end, cl))
			i = end
			n := joinedLiteralAt(src, i)
			if n < 0 {
				break
			}
			i = n
		}
	}
	return dst
}

// scanQuoted returns the index just past the closing quote of the run opening
// at i, and whether a closing quote was actually there. An unterminated run
// ends at the value's end, which is what a lenient parser does with it.
//
// closed is not a convenience. Without it every caller has to strip a closing
// quote it cannot know exists, and stripping one that does not is how this
// panicked: for input ending in a bare quote, the run starts at i+1 == len(src)
// and ends at len(src), so src[runStart:runEnd-1] slices backwards and the
// runtime kills the request. A trailing quote is not an exotic input -- it is
// what a truncated payload, a split parameter, or a scanner probing quote
// handling looks like, which is to say it is most of the traffic this function
// exists to read.
func scanQuoted(src []byte, i int) (end int, closed bool) {
	q := src[i]
	j := i + 1
	for j < len(src) && src[j] != q {
		if src[j] == '\\' && j+1 < len(src) {
			// Skipping the escaped byte can land exactly on len(src); it can
			// never pass it, because the guard requires a byte to escape.
			j += 2
			continue
		}
		j++
	}
	if j < len(src) {
		return j + 1, true // past the closing quote
	}
	return j, false
}

// quotedContent returns the bytes inside a quoted run: everything from start to
// the close, excluding the closing quote only when there was one.
func quotedContent(src []byte, start, end int, closed bool) []byte {
	if closed {
		return src[start : end-1]
	}
	return src[start:end]
}

// joinedLiteralAt returns the index of a quoted run joined to the position i by
// "." or "+", or -1 when there is none.
func joinedLiteralAt(src []byte, i int) int {
	j := i
	for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
		j++
	}
	if j >= len(src) || (src[j] != '.' && src[j] != '+') {
		return -1
	}
	j++
	for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
		j++
	}
	if j >= len(src) || (src[j] != '\'' && src[j] != '"' && src[j] != '`') {
		return -1
	}
	return j
}

// appendUnescaped copies a quoted run's contents, resolving the escapes a
// language resolves. An escape this does not understand keeps its backslash,
// matching what a lenient parser does.
func appendUnescaped(dst, run []byte) []byte {
	for i := 0; i < len(run); {
		if run[i] == '\\' && i+1 < len(run) {
			if n, adv := unescapeAt(run[i:]); adv > 0 {
				dst = append(dst, n...)
				i += adv
				continue
			}
		}
		dst = append(dst, run[i])
		i++
	}
	return dst
}

// unescapeAt resolves one escape sequence at the start of s, returning the
// bytes it produces and how far to advance. adv is 0 when s does not open an
// escape this understands, so the caller copies the backslash verbatim.
func unescapeAt(s []byte) (out []byte, adv int) {
	if len(s) < 2 || s[0] != '\\' {
		return nil, 0
	}
	switch s[1] {
	case 'x', 'X':
		if len(s) >= 4 && isHexDigit(s[2]) && isHexDigit(s[3]) {
			return []byte{hexVal(s[2])<<4 | hexVal(s[3])}, 4
		}
	case 'n':
		return []byte{'\n'}, 2
	case 't':
		return []byte{'\t'}, 2
	case 'r':
		return []byte{'\r'}, 2
	case '0', '1', '2', '3', '4', '5', '6', '7':
		// Octal, up to three digits, as PHP and C both read it.
		v, n := 0, 0
		for n < 3 && 1+n < len(s) && s[1+n] >= '0' && s[1+n] <= '7' {
			v = v*8 + int(s[1+n]-'0')
			n++
		}
		if n > 0 && v < 256 {
			return []byte{byte(v)}, 1 + n
		}
	}
	return nil, 0
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
