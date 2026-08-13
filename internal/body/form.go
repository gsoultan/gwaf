// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

import "bytes"

// ParseForm extracts fields from an application/x-www-form-urlencoded body.
//
// Names and values are percent-decoded, with '+' read as space, because that is
// what the origin's form parser does. As with JSON escapes, the decoding is not
// an ambiguity to enumerate — it is a transformation the origin will certainly
// perform, so inspecting the raw bytes would be inspecting something no
// application ever sees.
//
// A parameter with no '=' is emitted with an empty value rather than dropped:
// origins differ on whether "?debug" sets a flag, and a name an attacker chose
// is worth inspecting either way.
func (p *Parser) ParseForm(src []byte, fn Emit) error {
	if len(src) > p.limits.MaxTotalSize {
		return ErrTooLarge
	}

	for len(src) > 0 {
		var pair []byte
		if i := bytes.IndexByte(src, '&'); i >= 0 {
			pair, src = src[:i], src[i+1:]
		} else {
			pair, src = src, nil
		}
		if len(pair) == 0 {
			continue
		}

		// Both separator readings, for the reason Transaction.addQueryArguments
		// gives at length: some origins honour ';' as a pair separator and most
		// do not, and committing to either discards the other. The query side
		// was fixed when "?cmd=;whoami" turned out to be a live command
		// injection; the body kept the '&'-only reading, which is the majority
		// one and therefore hides the *name*-anchored half -- a payload after
		// ';' arrives as part of a value here and as an argument name there.
		//
		// The whole pair is emitted first because it is the reading most
		// origins use, which matters when MaxFields is reached. A pair with no
		// ';' costs one IndexByte and produces nothing extra.
		if err := p.emitPair(pair, fn); err != nil {
			return err
		}
		if bytes.IndexByte(pair, ';') < 0 {
			continue
		}
		for len(pair) > 0 {
			var sub []byte
			if i := bytes.IndexByte(pair, ';'); i >= 0 {
				sub, pair = pair[:i], pair[i+1:]
			} else {
				sub, pair = pair, nil
			}
			if len(sub) == 0 {
				continue
			}
			if err := p.emitPair(sub, fn); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitPair splits one "name=value" pair, decodes both halves and emits them.
func (p *Parser) emitPair(pair []byte, fn Emit) error {
	{

		var rawName, rawValue []byte
		if i := bytes.IndexByte(pair, '='); i >= 0 {
			rawName, rawValue = pair[:i], pair[i+1:]
		} else {
			// No '=' at all: the token is emitted as both the name and the
			// value, because which of the two it is depends on a parser gwaf
			// does not run.
			//
			// The comment above already said such a token is "worth inspecting
			// either way" and the code then handed it over with an empty value,
			// so only rules targeting ARGS_NAMES ever saw it. That is most of a
			// body when the body has no '=' in it at all: POST / with
			// "<script>alert(1)</script>" became one nameless parameter, and the
			// XSS rules — which read values — were shown an empty string. The
			// same bytes with no Content-Type were caught, because that path
			// falls back to inspecting the raw body.
			rawName, rawValue = pair, pair
		}

		if len(rawName) > p.limits.MaxKeyLen {
			return ErrTooLarge
		}

		// The name is decoded into the path buffer and the value into scratch,
		// so a pair costs no allocation once both have warmed up.
		p.path = formDecode(p.path[:0], rawName)
		p.scratch = formDecode(p.scratch[:0], rawValue)

		if len(p.scratch) > p.limits.MaxValueLen {
			return ErrTooLarge
		}

		// The parameter *name* is attacker-controlled and is emitted in its own
		// right, exactly as ParseJSON emits an object key and ParseMultipart
		// emits a field name.
		//
		// It was not, and the asymmetry is the one readsArgs already warns
		// about from the other direction: a rule reading names "would catch
		// ?password[$ne]=1 and miss {"password":{"$ne":null}}". JSON keys were
		// fixed; form names were left, so the *same* payload was caught in a
		// query string and missed in a urlencoded body. NoSQL operators and
		// prototype pollution both live in the name.
		p.fields++
		if p.fields > p.limits.MaxFields {
			return ErrTooManyFields
		}
		if !fn(p.path, p.path, KindKey) {
			return nil
		}

		p.fields++
		if p.fields > p.limits.MaxFields {
			return ErrTooManyFields
		}
		if !fn(p.path, p.scratch, KindString) {
			return nil
		}
	}
	return nil
}

// formDecode percent-decodes into dst, reading '+' as space.
//
// Malformed escapes are preserved verbatim, matching rules/transform.URLDecode.
// The two have to agree: if this package decoded a sequence the transform
// leaves alone, a rule's literals would be stated against bytes that never
// reach it.
func formDecode(dst, src []byte) []byte {
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

// ContentKind classifies a Content-Type header into a body format.
type ContentKind uint8

// Content kinds.
const (
	// ContentUnknown is anything gwaf cannot structure. Such a body is
	// inspected whole, which is slower and less precise but never less safe.
	ContentUnknown ContentKind = iota
	ContentJSON
	ContentForm
	ContentXML
)

// DetectContent maps a Content-Type header onto a body format.
//
// Matching is on the media type only, ignoring parameters, and the "+json"
// structured-suffix convention is honoured so that application/vnd.api+json and
// friends are parsed rather than treated as opaque.
func DetectContent(contentType string) ContentKind {
	ct := contentType
	if i := indexByteStr(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = trimSpaceStr(lowerStr(ct))

	switch {
	case ct == "application/json", ct == "text/json":
		return ContentJSON
	case hasSuffixStr(ct, "+json"):
		return ContentJSON
	case ct == "application/x-www-form-urlencoded":
		return ContentForm
	case ct == "application/xml", ct == "text/xml",
		ct == "application/soap+xml", ct == "application/xhtml+xml":
		return ContentXML
	case hasSuffixStr(ct, "+xml"):
		return ContentXML
	default:
		return ContentUnknown
	}
}

// SniffJSON reports whether data looks like a JSON document.
//
// Content-Type is attacker-controlled, and several widely used decoders never
// consult it: json.NewDecoder(r.Body).Decode(&v) is the ordinary Go idiom and
// ignores the header entirely, as do Express with type:'*/*' and Flask with
// force=True. Trusting the declared type against any of them leaves a JSON body
// labelled text/plain completely unparsed.
//
// Used as an *additional* reading rather than a replacement, exactly like
// SniffGzip. The check is deliberately shallow — a leading '{' or '[' — because
// its job is to decide whether the JSON parser is worth running, and that
// parser is strict enough to reject what is not JSON. A document the parser
// refuses falls back to whole-body inspection, so a wrong guess here costs a
// parse attempt and never coverage.
func SniffJSON(data []byte) bool {
	for _, c := range data {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

func indexByteStr(s string, c byte) int {
	for i := range len(s) {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func trimSpaceStr(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func lowerStr(s string) string {
	hasUpper := false
	for i := range len(s) {
		if s[i] >= 'A' && s[i] <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func hasSuffixStr(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
