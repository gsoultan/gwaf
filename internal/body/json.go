// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

// ParseJSON walks a JSON document and emits every leaf value.
//
// It does not build a tree. encoding/json would allocate a map per object and a
// slice per array, which on the request path is exactly the cost this package
// exists to remove; instead the document is scanned once with an explicit
// stack and leaves are handed to the caller as they are found.
//
// Strings are **unescaped**. This is the correctness half of the package:
// `{"c":"<script>"}` contains no angle bracket on the wire, and the
// origin's parser hands the application `<script>`. A firewall reading raw
// bytes sees inert text and passes it.
//
// Object member names are emitted too, as KindKey. A key is as
// attacker-controlled as a value, and a payload placed there would otherwise be
// invisible.
//
// A malformed document is an error, not a partial result. Half a parse says
// nothing about the half that was not read.
func (p *Parser) ParseJSON(src []byte, fn Emit) error {
	if len(src) > p.limits.MaxTotalSize {
		return ErrTooLarge
	}

	i := skipSpace(src, 0)
	if i >= len(src) {
		return ErrMalformed
	}

	stop, i, err := p.parseValue(src, i, 0, fn)
	if err != nil || stop {
		return err
	}

	if i = skipSpace(src, i); i != len(src) {
		// Trailing content means the document was not what it claimed to be,
		// and a second document may be what the origin actually reads.
		return ErrMalformed
	}
	return nil
}

// parseValue parses one value, returning whether the caller asked to stop and
// the index just past it.
func (p *Parser) parseValue(src []byte, i, depth int, fn Emit) (bool, int, error) {
	if depth > p.limits.MaxDepth {
		return false, i, ErrTooDeep
	}
	if i >= len(src) {
		return false, i, ErrMalformed
	}

	switch src[i] {
	case '{':
		return p.parseObject(src, i, depth, fn)
	case '[':
		return p.parseArray(src, i, depth, fn)
	case '"':
		val, next, err := p.parseString(src, i)
		if err != nil {
			return false, i, err
		}
		cont, err := p.emit(fn, val, KindString)
		return !cont, next, err
	case 't', 'f':
		lit, next, err := parseLiteral(src, i)
		if err != nil {
			return false, i, err
		}
		cont, err := p.emit(fn, lit, KindBool)
		return !cont, next, err
	case 'n':
		lit, next, err := parseLiteral(src, i)
		if err != nil {
			return false, i, err
		}
		cont, err := p.emit(fn, lit, KindNull)
		return !cont, next, err
	default:
		num, next, err := parseNumber(src, i)
		if err != nil {
			return false, i, err
		}
		cont, err := p.emit(fn, num, KindNumber)
		return !cont, next, err
	}
}

func (p *Parser) parseObject(src []byte, i, depth int, fn Emit) (bool, int, error) {
	i++ // '{'
	i = skipSpace(src, i)
	if i < len(src) && src[i] == '}' {
		return false, i + 1, nil
	}

	for {
		i = skipSpace(src, i)
		if i >= len(src) || src[i] != '"' {
			return false, i, ErrMalformed
		}

		key, next, err := p.parseString(src, i)
		if err != nil {
			return false, i, err
		}
		i = next

		// The key is attacker-controlled, so it is inspected in its own right.
		// It is emitted before the path is extended, so it reports against the
		// enclosing object rather than against itself.
		cont, err := p.emit(fn, key, KindKey)
		if err != nil {
			return false, i, err
		}
		if !cont {
			return true, i, nil
		}

		if !p.pushPath(key, false) {
			return false, i, ErrTooLarge
		}

		i = skipSpace(src, i)
		if i >= len(src) || src[i] != ':' {
			p.popPath()
			return false, i, ErrMalformed
		}
		i = skipSpace(src, i+1)

		stop, next, err := p.parseValue(src, i, depth+1, fn)
		p.popPath()
		if err != nil || stop {
			return stop, next, err
		}
		i = skipSpace(src, next)

		if i >= len(src) {
			return false, i, ErrMalformed
		}
		switch src[i] {
		case ',':
			i++
		case '}':
			return false, i + 1, nil
		default:
			return false, i, ErrMalformed
		}
	}
}

func (p *Parser) parseArray(src []byte, i, depth int, fn Emit) (bool, int, error) {
	i++ // '['
	i = skipSpace(src, i)
	if i < len(src) && src[i] == ']' {
		return false, i + 1, nil
	}

	for idx := 0; ; idx++ {
		var idxBuf [20]byte
		if !p.pushPath(itoa(idxBuf[:0], idx), true) {
			return false, i, ErrTooLarge
		}

		stop, next, err := p.parseValue(src, skipSpace(src, i), depth+1, fn)
		p.popPath()
		if err != nil || stop {
			return stop, next, err
		}
		i = skipSpace(src, next)

		if i >= len(src) {
			return false, i, ErrMalformed
		}
		switch src[i] {
		case ',':
			i++
		case ']':
			return false, i + 1, nil
		default:
			return false, i, ErrMalformed
		}
	}
}

// parseString reads a JSON string and returns its **unescaped** bytes.
//
// The result aliases p.scratch when any escape was present and the source
// otherwise, so an unescaped string costs no copy at all — the common case for
// ordinary API traffic.
func (p *Parser) parseString(src []byte, i int) ([]byte, int, error) {
	if i >= len(src) || src[i] != '"' {
		return nil, i, ErrMalformed
	}
	start := i + 1

	// Fast path: scan for the closing quote, and only fall back to unescaping
	// if a backslash was seen.
	j := start
	escaped := false
	for j < len(src) {
		c := src[j]
		if c == '"' {
			if !escaped {
				return src[start:j], j + 1, nil
			}
			break
		}
		// RFC 8259 forbids raw control characters inside a string; they must be
		// escaped. Accepting them would make gwaf's grammar looser than the
		// origin's, so gwaf would inspect documents the application rejects --
		// and would give an attacker a shape the two sides read differently.
		if c < 0x20 {
			return nil, j, ErrMalformed
		}
		if c == '\\' {
			escaped = true
			j++
			if j >= len(src) {
				return nil, j, ErrMalformed
			}
		}
		j++
	}
	if j >= len(src) {
		return nil, j, ErrMalformed
	}

	p.scratch = p.scratch[:0]
	j = start
	for j < len(src) {
		c := src[j]
		switch {
		case c == '"':
			return p.scratch, j + 1, nil

		case c == '\\':
			j++
			if j >= len(src) {
				return nil, j, ErrMalformed
			}
			switch src[j] {
			case '"', '\\', '/':
				p.scratch = append(p.scratch, src[j])
				j++
			case 'b':
				p.scratch = append(p.scratch, '\b')
				j++
			case 'f':
				p.scratch = append(p.scratch, '\f')
				j++
			case 'n':
				p.scratch = append(p.scratch, '\n')
				j++
			case 'r':
				p.scratch = append(p.scratch, '\r')
				j++
			case 't':
				p.scratch = append(p.scratch, '\t')
				j++
			case 'u':
				r, next, err := parseUnicodeEscape(src, j+1)
				if err != nil {
					return nil, j, err
				}
				p.scratch = appendRune(p.scratch, r)
				j = next
			default:
				return nil, j, ErrMalformed
			}

		case c < 0x20:
			// See the fast path: raw control characters are not legal JSON.
			return nil, j, ErrMalformed

		default:
			p.scratch = append(p.scratch, c)
			j++
		}

		if len(p.scratch) > p.limits.MaxValueLen {
			return nil, j, ErrTooLarge
		}
	}
	return nil, j, ErrMalformed
}

// parseUnicodeEscape decodes \uXXXX, including a surrogate pair.
//
// Surrogates are joined rather than emitted separately, because that is what
// the origin's parser does: `😀` is one emoji to the application, and
// a firewall that produced two replacement characters would be inspecting
// something the application never sees.
func parseUnicodeEscape(src []byte, i int) (rune, int, error) {
	hi, next, err := hex4(src, i)
	if err != nil {
		return 0, i, err
	}

	if hi >= 0xD800 && hi <= 0xDBFF {
		// A high surrogate must be followed by a low one.
		if next+1 < len(src) && src[next] == '\\' && src[next+1] == 'u' {
			lo, after, err := hex4(src, next+2)
			if err == nil && lo >= 0xDC00 && lo <= 0xDFFF {
				r := 0x10000 + (rune(hi)-0xD800)<<10 + (rune(lo) - 0xDC00)
				return r, after, nil
			}
		}
		// An unpaired surrogate is not a character. Emitting the replacement
		// keeps the byte stream well formed without inventing content.
		return 0xFFFD, next, nil
	}
	if hi >= 0xDC00 && hi <= 0xDFFF {
		return 0xFFFD, next, nil
	}
	return rune(hi), next, nil
}

func hex4(src []byte, i int) (uint32, int, error) {
	if i+4 > len(src) {
		return 0, i, ErrMalformed
	}
	var v uint32
	for k := range 4 {
		c := src[i+k]
		var d uint32
		switch {
		case c >= '0' && c <= '9':
			d = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint32(c-'A') + 10
		default:
			return 0, i, ErrMalformed
		}
		v = v<<4 | d
	}
	return v, i + 4, nil
}

// parseNumber reads a JSON number under the strict grammar.
//
// Strict matters: leading zeros ("01") and a bare fraction (".5") are not JSON,
// and accepting them would make gwaf's grammar looser than the origin's. A
// looser parser inspects documents the origin will reject — and, worse, gives
// an attacker a shape the two sides read differently, which is the same
// disagreement class the interpret package exists to close.
func parseNumber(src []byte, i int) ([]byte, int, error) {
	start := i

	// JSON permits a leading minus only; a plus is not a number.
	if i < len(src) && src[i] == '-' {
		i++
	}

	// Integer part: a single zero, or a non-zero digit followed by any digits.
	if i >= len(src) {
		return nil, start, ErrMalformed
	}
	switch {
	case src[i] == '0':
		i++
	case src[i] >= '1' && src[i] <= '9':
		for i < len(src) && src[i] >= '0' && src[i] <= '9' {
			i++
		}
	default:
		return nil, start, ErrMalformed
	}

	// Fraction, if present, needs at least one digit.
	if i < len(src) && src[i] == '.' {
		i++
		digits := 0
		for i < len(src) && src[i] >= '0' && src[i] <= '9' {
			i++
			digits++
		}
		if digits == 0 {
			return nil, start, ErrMalformed
		}
	}

	// Exponent, if present, needs at least one digit.
	if i < len(src) && (src[i] == 'e' || src[i] == 'E') {
		i++
		if i < len(src) && (src[i] == '+' || src[i] == '-') {
			i++
		}
		digits := 0
		for i < len(src) && src[i] >= '0' && src[i] <= '9' {
			i++
			digits++
		}
		if digits == 0 {
			return nil, start, ErrMalformed
		}
	}

	return src[start:i], i, nil
}

func parseLiteral(src []byte, i int) ([]byte, int, error) {
	for _, lit := range []string{"true", "false", "null"} {
		if i+len(lit) <= len(src) && string(src[i:i+len(lit)]) == lit {
			return src[i : i+len(lit)], i + len(lit), nil
		}
	}
	return nil, i, ErrMalformed
}

func skipSpace(src []byte, i int) int {
	for i < len(src) {
		switch src[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}

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
