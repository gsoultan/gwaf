// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

// ParseXML extracts element text and attribute values from an XML document.
//
// # Why this exists
//
// It was the one body format with no structural parser. XXE was covered by a
// rule scanning the raw bytes for an entity declaration or an external DTD,
// which finds the declaration and says nothing about the document: a payload in
// an element or an attribute was inspected only as part of one undifferentiated
// blob, with no path to name it and no per-field ceiling on it. SOAP endpoints
// in the corpus went through exactly that hole.
//
// # It never expands an entity
//
// Not "expands them safely" — never at all. `&lt;`, `&foo;` and a
// megabyte-deep `&lol9;` chain are all copied through as the bytes they are.
//
// That is what makes the billion-laughs class structurally impossible here
// rather than bounded: there is no expansion step to bound. A parser that
// expands and then caps the result has to be right about the cap; this has
// nothing to be right about. The cost is that a rule wanting the decoded form
// asks for it — `internal/interpret` already produces the HTML-entity reading,
// and transform chains already spell it — which is the same bargain the rest of
// the engine makes: decode where it is requested, never once and eagerly.
//
// A DOCTYPE is skipped rather than read, and deliberately not reported from
// here: rule 4005 already scans the raw body for it, and detection belongs to a
// rule rather than to a parser that would then have to carry a verdict.
//
// # What it emits
//
//	<order id="7"><note>hi</note></order>
//
//	order@id     "7"    KindString
//	note         "hi"   KindString
//	order, note, id     KindKey
//
// Element and attribute names are emitted as keys because they are
// attacker-controlled: a tag name is as much a place to hide a payload as the
// text inside it, and the ARGS_NAMES target exists for exactly that.
func (p *Parser) ParseXML(src []byte, fn Emit) error {
	if len(src) > p.limits.MaxTotalSize {
		return ErrTooLarge
	}

	depth := 0
	i := 0

	for i < len(src) {
		// Text between tags belongs to the element currently open.
		if src[i] != '<' {
			start := i
			for i < len(src) && src[i] != '<' {
				i++
			}
			if depth > 0 {
				if text := trimXMLSpace(src[start:i]); len(text) > 0 {
					ok, err := p.emit(fn, text, KindString)
					if err != nil {
						return err
					}
					if !ok {
						return nil
					}
				}
			}
			continue
		}

		// A '<' that opens nothing is text. Emitting it keeps a truncated
		// document from silently losing its tail.
		if i+1 >= len(src) {
			break
		}

		switch {
		case hasPrefixAt(src, i, "<!--"):
			i = skipUntil(src, i+4, "-->", 3)

		case hasPrefixAt(src, i, "<![CDATA["):
			end := indexFrom(src, i+9, "]]>")
			if end < 0 {
				end = len(src)
			}
			if depth > 0 {
				if text := src[i+9 : end]; len(text) > 0 {
					ok, err := p.emit(fn, text, KindString)
					if err != nil {
						return err
					}
					if !ok {
						return nil
					}
				}
			}
			i = min(end+3, len(src))

		case hasPrefixAt(src, i, "<!"):
			// DOCTYPE and any other declaration. Skipped, not parsed: internal
			// subsets nest brackets, and following them would mean implementing
			// the one part of XML that exists to expand things.
			i = skipDeclaration(src, i)

		case hasPrefixAt(src, i, "<?"):
			i = skipUntil(src, i+2, "?>", 2)

		case hasPrefixAt(src, i, "</"):
			j := i + 2
			for j < len(src) && src[j] != '>' {
				j++
			}
			if depth > 0 {
				depth--
				p.popPath()
			}
			i = min(j+1, len(src))

		default:
			var err error
			i, depth, err = p.parseElement(src, i, depth, fn)
			if err != nil {
				return err
			}
			if i < 0 {
				return nil // caller asked to stop
			}
		}
	}
	return nil
}

// parseElement handles a start tag and its attributes.
//
// It returns the index just past the tag, the new depth, and any error. An
// index of -1 means the Emit callback asked to stop.
func (p *Parser) parseElement(src []byte, i, depth int, fn Emit) (int, int, error) {
	nameStart := i + 1
	j := nameStart
	for j < len(src) && !isXMLNameEnd(src[j]) {
		j++
	}
	name := src[nameStart:j]
	if len(name) == 0 {
		// "< " is not a tag. Skip the bracket and carry on rather than treating
		// the rest of the document as one element.
		return i + 1, depth, nil
	}
	if len(name) > p.limits.MaxKeyLen {
		return 0, 0, ErrTooLarge
	}

	if depth >= p.limits.MaxDepth {
		return 0, 0, ErrTooDeep
	}
	if !p.pushPath(name, false) {
		return 0, 0, ErrTooLarge
	}
	depth++

	// The tag name itself.
	if ok, err := p.emit(fn, name, KindKey); err != nil {
		return 0, 0, err
	} else if !ok {
		return -1, depth, nil
	}

	// Attributes, until '>' or '/>'.
	selfClosing := false
	for j < len(src) {
		for j < len(src) && isXMLSpace(src[j]) {
			j++
		}
		if j >= len(src) {
			break
		}
		if src[j] == '>' {
			j++
			break
		}
		if src[j] == '/' {
			selfClosing = true
			j++
			continue
		}

		attrStart := j
		for j < len(src) && !isXMLNameEnd(src[j]) && src[j] != '=' {
			j++
		}
		attr := src[attrStart:j]
		if len(attr) == 0 {
			j++ // never stall on a byte we cannot classify
			continue
		}
		if len(attr) > p.limits.MaxKeyLen {
			return 0, 0, ErrTooLarge
		}

		if ok, err := p.emit(fn, attr, KindKey); err != nil {
			return 0, 0, err
		} else if !ok {
			return -1, depth, nil
		}

		for j < len(src) && isXMLSpace(src[j]) {
			j++
		}
		if j >= len(src) || src[j] != '=' {
			continue // a bare attribute, which is HTML rather than XML
		}
		j++
		for j < len(src) && isXMLSpace(src[j]) {
			j++
		}

		var value []byte
		if j < len(src) && (src[j] == '"' || src[j] == '\'') {
			q := src[j]
			j++
			vs := j
			for j < len(src) && src[j] != q {
				j++
			}
			value = src[vs:j]
			if j < len(src) {
				j++ // closing quote
			}
		} else {
			vs := j
			for j < len(src) && !isXMLSpace(src[j]) && src[j] != '>' {
				j++
			}
			value = src[vs:j]
		}

		// The attribute is reported under "element@attr" so a decision can name
		// the place rather than the document.
		//
		// Appended directly rather than through pushPath, which inserts the '.'
		// that separates elements: an attribute is not a child, and "order.@id"
		// names a path that does not exist.
		mark := len(p.path)
		p.path = append(p.path, '@')
		p.path = append(p.path, attr...)
		if len(p.path) > p.limits.MaxKeyLen {
			p.path = p.path[:mark]
			return 0, 0, ErrTooLarge
		}
		ok, err := p.emit(fn, value, KindString)
		p.path = p.path[:mark]
		if err != nil {
			return 0, 0, err
		}
		if !ok {
			return -1, depth, nil
		}
	}

	if selfClosing {
		depth--
		p.popPath()
	}
	return j, depth, nil
}

// skipDeclaration steps over "<!...>", tracking an internal subset so that a
// DOCTYPE carrying one does not end the scan at the first '>' inside it.
func skipDeclaration(src []byte, i int) int {
	j := i + 2
	bracket := 0
	for j < len(src) {
		switch src[j] {
		case '[':
			bracket++
		case ']':
			if bracket > 0 {
				bracket--
			}
		case '>':
			if bracket == 0 {
				return j + 1
			}
		}
		j++
	}
	return len(src)
}

// skipUntil returns the index past the next occurrence of pat, or the end.
func skipUntil(src []byte, i int, pat string, n int) int {
	if k := indexFrom(src, i, pat); k >= 0 {
		return k + n
	}
	return len(src)
}

// indexFrom finds pat in src at or after i.
func indexFrom(src []byte, i int, pat string) int {
	if i < 0 {
		i = 0
	}
	for ; i+len(pat) <= len(src); i++ {
		if string(src[i:i+len(pat)]) == pat {
			return i
		}
	}
	return -1
}

// hasPrefixAt reports whether src has pat at i.
func hasPrefixAt(src []byte, i int, pat string) bool {
	return i+len(pat) <= len(src) && string(src[i:i+len(pat)]) == pat
}

func isXMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// isXMLNameEnd reports whether c ends a name. A namespace prefix stays part of
// the name: "soap:Envelope" is one name, because that is what an operator reads
// in a finding and what a rule keys on.
func isXMLNameEnd(c byte) bool {
	return isXMLSpace(c) || c == '>' || c == '/' || c == '=' || c == '<'
}

// trimXMLSpace drops surrounding whitespace from a text run.
func trimXMLSpace(b []byte) []byte {
	i := 0
	for i < len(b) && isXMLSpace(b[i]) {
		i++
	}
	j := len(b)
	for j > i && isXMLSpace(b[j-1]) {
		j--
	}
	return b[i:j]
}

// SniffXML reports whether data looks like an XML document.
//
// Shallow on purpose, for the reason SniffJSON is: its job is to decide whether
// running the parser is worthwhile, and a wrong guess costs a parse attempt
// rather than coverage. Content-Type is attacker-controlled and several SOAP
// stacks never consult it.
func SniffXML(data []byte) bool {
	i := 0
	for i < len(data) && isXMLSpace(data[i]) {
		i++
	}
	if i >= len(data) || data[i] != '<' {
		return false
	}
	// "<?xml" and "<!DOCTYPE" are unambiguous.
	if hasPrefixAt(data, i, "<?xml") || hasPrefixAt(data, i, "<!DOCTYPE") {
		return true
	}

	// Otherwise require a plausible start tag: a name character, then only name
	// characters, then something that can actually end a tag name.
	//
	// "starts with '<' and a letter" was the first version and it was too loose
	// by exactly the margin that matters. Random binary begins that way often
	// enough that 2 of 2,000 random bodies were parsed as XML, and the fields
	// that fell out of the garbage matched a text detector -- a chance match
	// rate of 0.1%, which is a false-positive source rather than coverage.
	j := i + 1
	if j >= len(data) || !isXMLNameStart(data[j]) {
		return false
	}
	for j < len(data) && j-i <= 64 {
		c := data[j]
		switch {
		case isXMLNameChar(c):
			j++
		case c == '>' || c == '/' || isXMLSpace(c):
			return true
		default:
			return false
		}
	}
	return false
}

// isXMLNameChar reports whether c may appear inside a name. Deliberately ASCII:
// a sniff that accepts arbitrary high bytes accepts arbitrary binary.
func isXMLNameChar(c byte) bool {
	return isXMLNameStart(c) || (c >= '0' && c <= '9') || c == '-' || c == '.'
}

func isXMLNameStart(c byte) bool {
	return c == '_' || c == ':' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
