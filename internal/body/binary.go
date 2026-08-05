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
