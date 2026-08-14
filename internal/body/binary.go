// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

// Binary content, and why it cannot be inspected as text.
//
// A text detector run over binary data produces matches by chance. The shell
// rule looks for "$(", which is two bytes; in five hundred random bytes it
// appears about one time in a hundred and thirty. Measured against random
// protobuf payloads, 1.2% of gRPC requests were blocked — one in eighty-three —
// with no attacker involved at all.
//
// The same applies to uploads. Every multipart file part has its first 8 KiB
// inspected, and 8 KiB of JPEG is 8 KiB of chances for a two-byte literal to
// appear.
//
// The answer is not to skip binary bodies. A protobuf string field or a
// filename embedded in an upload is attacker-controlled and reaches the
// application. The answer is that a *text* detector should only ever see
// *text*: printable runs are extracted from the binary and inspected
// individually, and the framing bytes between them are never presented as if
// they were a sentence.
//
// This is the same principle as the JSON and multipart parsers. Inspect what
// the origin will actually act on, in the form it will act on it.

// minTextRun is the shortest printable run treated as text.
//
// Below this, a "run" is a coincidence rather than a string. Every payload that
// matters is far longer: the shortest literal in the core ruleset is two bytes,
// but a two-byte run carries no structure for a detector to read and is exactly
// the accident this bound exists to exclude.
const minTextRun = 8

// maxTextRuns bounds how many runs are extracted from one value, so a
// pathological body cannot turn into thousands of values to evaluate.
const maxTextRuns = 256

// IsBinary reports whether data should be treated as binary rather than text.
//
// Two signals, and neither is trusted alone:
//
//   - A NUL byte. Text does not contain them; every common binary format does.
//   - A high proportion of bytes outside the printable range.
//
// The declared Content-Type is deliberately *not* consulted here. It is
// attacker-controlled, and a payload that declares itself binary while
// containing text would then skip inspection. Sniffing the content means the
// decision follows what was actually sent.
func IsBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// A prefix is enough to classify, and bounds the cost for large bodies.
	sample := data
	if len(sample) > 1024 {
		sample = sample[:1024]
	}

	nonText := 0
	for _, c := range sample {
		if c == 0x00 {
			return true
		}
		if !isTextByte(c) {
			nonText++
		}
	}
	// A third of the sample being non-text is well past anything UTF-8 prose
	// produces, and well below the density of any real binary format.
	return nonText*3 > len(sample)
}

// isTextByte reports whether a byte can appear in text.
//
// Bytes above 0x7f count as text: they are UTF-8 continuation bytes, and
// rejecting them would classify every non-English body as binary.
func isTextByte(c byte) bool {
	switch {
	case c >= 0x20 && c < 0x7f:
		return true
	case c == '\t' || c == '\n' || c == '\r':
		return true
	case c >= 0x80:
		return true
	default:
		return false
	}
}

// wideTextMinChars is how many ASCII characters must arrive as NUL-padded code
// units before data is read as UTF-16/UTF-32 text.
//
// It is the same judgement minTextRun makes: below this the pattern is a
// coincidence in binary rather than a sentence in a wide encoding. A payload
// worth carrying this way is far longer -- "<script>" alone is eight.
const wideTextMinChars = 8

// recoverWideText returns the ASCII that a UTF-16 or UTF-32 body decodes to, and
// reports whether data looked like wide text at all.
//
// Both encodings carry an ASCII character in a code unit padded with NULs, so
// dropping the padding recovers what the origin reads -- in either endianness and
// at either width, without having to infer which. Nothing is inferred from the
// declared charset: it is attacker-controlled, and IsBinary already refuses to
// trust it for the same reason.
//
// The test is that most of the data is NUL-padded ASCII, so a body has to look
// like wide text throughout rather than merely contain a run that does. A JPEG,
// a protobuf message, and a zip file all fail it.
func (p *Parser) recoverWideText(data []byte) ([]byte, bool) {
	if len(data) < wideTextMinChars*2 {
		return nil, false
	}

	body := data
	if len(body) >= 2 &&
		((body[0] == 0xFF && body[1] == 0xFE) || (body[0] == 0xFE && body[1] == 0xFF)) {
		body = body[2:]
	}

	// Classify on a prefix, as IsBinary does, so a large body costs a bounded scan.
	sample := body
	if len(sample) > 1024 {
		sample = sample[:1024]
	}

	nuls, printable, other := 0, 0, 0
	for _, c := range sample {
		switch {
		case c == 0x00:
			nuls++
		case c >= 0x20 && c < 0x7f, c == '\t', c == '\n', c == '\r':
			printable++
		default:
			other++
		}
	}
	// Padding and characters in balance, and almost nothing else. UTF-16 ASCII is
	// half NULs; UTF-32 is three quarters, which is why the NUL count is only
	// required to reach the character count rather than to match it.
	if printable < wideTextMinChars || nuls < printable || other*8 > len(sample) {
		return nil, false
	}

	p.scratch = p.scratch[:0]
	for _, c := range body {
		if c != 0x00 {
			p.scratch = append(p.scratch, c)
		}
	}
	return p.scratch, true
}

// ExtractText emits the printable runs found in binary data.
//
// Each run is handed to fn as its own value, under a positional name. A
// protobuf string field, a filename inside an archive, or a comment embedded in
// an image all surface as runs; the framing bytes around them do not.
//
// Runs shorter than minTextRun are dropped. Nothing a rule needs to see is that
// short, and admitting them reintroduces exactly the chance matches this exists
// to prevent.
func (p *Parser) ExtractText(name []byte, data []byte, fn Emit) {
	// UTF-16 and UTF-32 text is binary by every test above -- it is full of NULs --
	// and yields nothing at all to run extraction, because ASCII carried as code
	// units leaves printable runs one byte long and minTextRun drops every one of
	// them. A body declaring "charset=utf-16" therefore passed inspected-and-clean
	// while a Java servlet or ASP.NET request decoder read it straight back to
	// "<script>". That is the CVE-2026-21876 shape: the firewall and the origin
	// disagreeing about a charset.
	//
	// So wide text is recovered to the bytes the origin acts on and extracted from
	// that. Recovery is deliberately narrow -- it fires only on the interleave that
	// real UTF-16/32 text produces -- and a body that is genuinely binary is
	// unaffected and still walks the loop below.
	if wide, ok := p.recoverWideText(data); ok {
		data = wide
	}

	runs := 0
	start := -1

	flush := func(end int) bool {
		if start < 0 {
			return true
		}
		run := data[start:end]
		start = -1
		if len(run) < minTextRun {
			return true
		}

		runs++
		if runs > maxTextRuns {
			return false
		}
		p.fields++
		if p.fields > p.limits.MaxFields {
			return false
		}

		// The run is named by its offset so a decision can say where in the
		// binary the text was found.
		p.path = append(p.path[:0], name...)
		p.path = append(p.path, '@')
		p.path = itoa(p.path, start)
		return fn(p.path, run, KindString)
	}

	for i := 0; i < len(data); i++ {
		if isPrintableRun(data[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if !flush(i) {
			return
		}
	}
	flush(len(data))
}

// isPrintableRun reports whether a byte continues a text run.
//
// Stricter than isTextByte: a run is broken by control bytes and by high bytes,
// because a genuine string inside binary data is normally ASCII, and letting
// high bytes continue a run would splice unrelated fragments into one
// artificial "sentence" — inventing adjacency, which is the same mistake the
// joined-argument view is careful about.
func isPrintableRun(c byte) bool {
	return c >= 0x20 && c < 0x7f
}

// minBase64Run is the shortest run treated as encoded content on length alone.
//
// Long enough that ordinary identifiers, tokens, and words cannot reach it by
// accident: a 64-character unbroken run of base64 alphabet is not a word, and
// real encoded payloads are far longer.
const minBase64Run = 64

// minBase64Text is the floor for a run whose decode is checked instead of
// assumed.
//
// The 64-character floor is a proxy for "is this real content", and a red-team
// pass found what the proxy costs: the shortest useful PHP web shell,
// "<?php system($_GET['c']); ?>", is 28 bytes and encodes to 40 characters.
// Every payload of that size was invisible.
//
// Length is a poor proxy when the decoded bytes can be examined directly. A
// session token or an identifier of this length decodes to effectively random
// bytes, and the chance that 18 random bytes are all printable is about one in
// ten billion — so requiring a fully printable decode separates encoded text
// from encoded nothing far more sharply than counting characters does.
//
// That matters because decoding random bytes is not merely wasted work: the
// printable-run extraction that follows it is where a stray "$(" once produced
// a 1.2% false-positive rate on protobuf. Refusing to decode noise is the
// point, not a side effect.
const minBase64Text = 24

// IsBase64Text reports whether data is a short base64 run that decodes to
// printable text, which is what distinguishes an encoded payload from an
// encoded identifier at lengths below minBase64Run.
//
// dst is scratch; the decoded bytes are returned when the answer is yes.
func IsBase64Text(dst, data []byte) ([]byte, bool) {
	if len(data) < minBase64Text || len(data) >= minBase64Run {
		return nil, false
	}
	// Encoding n bytes yields a length that is 0, 2 or 3 modulo four and never
	// 1, so a quarter of candidates are rejected here for one instruction
	// rather than by scanning them. This path runs on every field short enough
	// to qualify, so the order of the checks is the cost.
	if len(data)%4 == 1 {
		return nil, false
	}
	if !isBase64Alphabet(data) {
		return nil, false
	}
	decoded, ok := DecodeBase64(dst, data)
	if !ok || len(decoded) == 0 {
		return nil, false
	}
	for _, c := range decoded {
		// Tab, CR and LF are text; everything else outside printable ASCII says
		// this was not text to begin with.
		if isPrintableRun(c) || c == '\t' || c == '\r' || c == '\n' {
			continue
		}
		return nil, false
	}
	return decoded, true
}

// IsBase64 reports whether data is a single run of base64-encoded content.
//
// Base64 is encoded binary that happens to be printable. Running a SQL
// tokenizer and a markup scanner over a megabyte of it costs real time and
// finds nothing, because there is no grammar in it to read — measured at 20
// million fuel and 20ms for a 700 KiB field, 62% of the default budget for one
// upload.
//
// Skipping it would be a coverage hole, because the origin decodes it: a
// base64-encoded web shell is a real upload technique. So it is decoded instead,
// and the decoded content is inspected in the form the application will act on.
// That is the same principle as everywhere else here — inspect what the origin
// will actually process.
func IsBase64(data []byte) bool {
	if len(data) < minBase64Run {
		return false
	}
	return isBase64Alphabet(data)
}

// minBase64Body is the shortest *whole body* treated as encoded content.
//
// Much lower than minBase64Run because the context is different. The
// 64-character floor exists so that an identifier or a token inside a field is
// not mistaken for encoded content; a whole request body that is nothing but
// base64 alphabet is not an identifier.
//
// grpc-web-text is exactly this case — a browser that cannot send binary
// framing base64-encodes the entire body — and a short gRPC message encodes to
// well under sixty-four characters, which is why the payload was invisible.
//
// Not zero either: eight characters is the smallest gRPC frame, a five-byte
// header and nothing else, once encoded.
const minBase64Body = 8

// IsBase64Body reports whether an entire body is one base64 run.
//
// Separate from IsBase64 only in its length floor; the alphabet and padding
// rules are identical, and both accept the URL-safe alphabet because an origin
// decoding either will produce content.
func IsBase64Body(data []byte) bool {
	if len(data) < minBase64Body {
		return false
	}
	return isBase64Alphabet(data)
}

// isBase64Alphabet reports whether data is entirely base64, padding aside.
func isBase64Alphabet(data []byte) bool {
	body := data
	// Padding only ever appears at the end, and only ever one or two bytes.
	for len(body) > 0 && body[len(body)-1] == '=' {
		body = body[:len(body)-1]
		if len(data)-len(body) > 2 {
			return false
		}
	}
	if len(body) == 0 {
		return false
	}

	for _, c := range body {
		if !isBase64Byte(c) {
			return false
		}
	}
	return true
}

// isBase64Byte accepts both the standard and URL-safe alphabets, since both
// appear in real traffic and an origin decoding either will produce content.
func isBase64Byte(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '+', c == '/', c == '-', c == '_':
		return true
	default:
		return false
	}
}

// DecodeBase64 decodes a base64 run into dst.
//
// Both alphabets are accepted and padding is optional, because an origin's
// decoder is typically permissive and a firewall stricter than the origin
// inspects something the application never sees. A run that fails to decode is
// reported so the caller can fall back to inspecting it verbatim.
func DecodeBase64(dst, src []byte) ([]byte, bool) {
	dst = dst[:0]

	var acc uint32
	var bits uint
	for _, c := range src {
		if c == '=' {
			break
		}
		v, ok := base64Value(c)
		if !ok {
			return nil, false
		}
		acc = acc<<6 | uint32(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			dst = append(dst, byte(acc>>bits))
		}
	}
	return dst, true
}

func base64Value(c byte) (byte, bool) {
	switch {
	case c >= 'A' && c <= 'Z':
		return c - 'A', true
	case c >= 'a' && c <= 'z':
		return c - 'a' + 26, true
	case c >= '0' && c <= '9':
		return c - '0' + 52, true
	case c == '+', c == '-':
		return 62, true
	case c == '/', c == '_':
		return 63, true
	default:
		return 0, false
	}
}

// DecodedBuffer exposes the parser's scratch space for base64 decoding, so a
// caller can decode without allocating per value.
func (p *Parser) DecodedBuffer() []byte { return p.scratch }

// SetDecodedBuffer returns the scratch space after use.
func (p *Parser) SetDecodedBuffer(b []byte) { p.scratch = b }
