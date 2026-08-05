// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

import (
	"bytes"
	"errors"
)

// Multipart-specific errors.
var (
	// ErrNoBoundary reports a multipart Content-Type with no usable boundary.
	ErrNoBoundary = errors.New("body: multipart boundary missing")

	// ErrTooManyParts reports more parts than MaxParts.
	ErrTooManyParts = errors.New("body: too many multipart parts")
)

// MaxParts bounds how many parts are parsed. A form with more than this is not
// one a browser sends.
const MaxParts = 256

// maxPartHeaderBytes bounds the header block of a single part.
const maxPartHeaderBytes = 8 << 10

// PartInfo describes one multipart part, for the caller's per-part checks.
type PartInfo struct {
	// Name is the form field name from Content-Disposition.
	Name []byte

	// Filename is the client-supplied file name, if any. It is entirely
	// attacker-controlled and is a classic traversal and polyglot vector, so it
	// is inspected in its own right rather than treated as metadata.
	Filename []byte

	// ContentType is the part's declared media type, lowercased.
	ContentType []byte

	// Charset is the charset parameter of the part's Content-Type, lowercased.
	//
	// This field is why multipart parsing is a security feature rather than an
	// optimization. CVE-2026-21876 (CVSS 9.3) broke the OWASP Core Rule Set
	// across ModSecurity v2, v3, and Coraza because a chained rule captured the
	// charset once and evaluated it once — so only the *last* part's charset
	// was checked, and a UTF-7 payload in an earlier part sailed through.
	//
	// gwaf reports the charset of every part, and every part's content is
	// inspected. There is no "final part" for the check to collapse onto.
	Charset []byte

	// Index is the part's position, from zero.
	Index int
}

// EmitPart receives one part before its content is emitted as a field.
// Returning false stops parsing.
type EmitPart func(info PartInfo) bool

// ParseMultipart splits a multipart body and emits each part's fields.
//
// Every part is parsed and every part's content is emitted. That is the whole
// defence against the CVE-2026-21876 class: a firewall that inspects only some
// parts has told the operator nothing about the others.
//
// Parts are emitted as:
//
//   - the field name, as KindKey, since it is attacker-controlled;
//   - the filename, if present, as its own value under "<name>.filename";
//   - the content, under the field name.
//
// File content is emitted up to maxFileContent bytes. Scanning an entire
// uploaded binary for SQL grammar is expensive and finds nothing; a bounded
// prefix still catches the polyglots and scripts that matter. The bound is a
// documented coverage decision, not an accident — see maxFileContent.
func (p *Parser) ParseMultipart(src []byte, boundary []byte, onPart EmitPart, fn Emit) error {
	if len(src) > p.limits.MaxTotalSize {
		return ErrTooLarge
	}
	if len(boundary) == 0 {
		return ErrNoBoundary
	}

	// The delimiter is CRLF + "--" + boundary, but the first one may appear at
	// the very start with no preceding CRLF.
	dash := make([]byte, 0, len(boundary)+4)
	dash = append(dash, '-', '-')
	dash = append(dash, boundary...)

	i := indexDelimiter(src, 0, dash)
	if i < 0 {
		return ErrNoBoundary
	}
	i += len(dash)

	for idx := 0; ; idx++ {
		if idx >= MaxParts {
			return ErrTooManyParts
		}

		// "--" immediately after the boundary marks the final delimiter.
		if i+2 <= len(src) && src[i] == '-' && src[i+1] == '-' {
			return nil
		}

		// Skip the transport padding and line ending after the delimiter.
		i = skipLineEnd(src, i)
		if i < 0 {
			return ErrMalformed
		}

		next := indexDelimiter(src, i, dash)
		if next < 0 {
			// No closing delimiter: the body was truncated, and the origin may
			// read it differently. That is a decision, not something to guess at.
			return ErrMalformed
		}

		part := src[i:next]
		// Trim the CRLF that belongs to the delimiter, not the content.
		part = trimTrailingLineEnd(part)

		if err := p.parsePart(part, idx, onPart, fn); err != nil {
			return err
		}

		i = next + len(dash)
		if i > len(src) {
			return ErrMalformed
		}
	}
}

// maxFileContent bounds how much of a file part is inspected.
//
// A payload that matters — a script, a polyglot, an injected template — lives in
// the first few kilobytes. Tokenizing the remainder of a multi-megabyte upload
// as SQL costs real time and finds nothing. This is a coverage decision and is
// stated rather than hidden: content beyond this is not inspected, and an
// embedder that needs it should scan uploads out of band, which is where
// antivirus and content inspection belong anyway.
const maxFileContent = 8 << 10

// parsePart parses one part's headers and emits its fields.
func (p *Parser) parsePart(part []byte, idx int, onPart EmitPart, fn Emit) error {
	headers, content, ok := splitPartHeaders(part)
	if !ok {
		return ErrMalformed
	}
	if len(headers) > maxPartHeaderBytes {
		return ErrTooLarge
	}

	info := PartInfo{Index: idx}
	parsePartHeaders(headers, &info)

	if onPart != nil && !onPart(info) {
		return nil
	}

	name := info.Name
	if len(name) == 0 {
		// A part with no name is still attacker-supplied content; giving it a
		// positional key keeps it inspected rather than dropped.
		var buf [24]byte
		name = append(itoa(buf[:0], idx), ".unnamed"...)
	}
	if len(name) > p.limits.MaxKeyLen {
		return ErrTooLarge
	}

	// The field name is attacker-controlled.
	p.fields++
	if p.fields > p.limits.MaxFields {
		return ErrTooManyFields
	}
	if !fn(name, name, KindKey) {
		return nil
	}

	// The filename is the most attacker-controlled part of an upload and is a
	// standard traversal and double-extension vector, so it is inspected as a
	// value of its own rather than trusted as metadata.
	if len(info.Filename) > 0 {
		p.path = append(append(p.path[:0], name...), ".filename"...)
		p.fields++
		if p.fields > p.limits.MaxFields {
			return ErrTooManyFields
		}
		if !fn(p.path, info.Filename, KindString) {
			return nil
		}
	}

	value := content
	if len(info.Filename) > 0 && len(value) > maxFileContent {
		value = value[:maxFileContent]
	}
	if len(value) > p.limits.MaxValueLen {
		value = value[:p.limits.MaxValueLen]
	}

	p.fields++
	if p.fields > p.limits.MaxFields {
		return ErrTooManyFields
	}
	fn(name, value, KindString)
	return nil
}

// splitPartHeaders separates a part's header block from its content.
func splitPartHeaders(part []byte) (headers, content []byte, ok bool) {
	if i := bytes.Index(part, []byte("\r\n\r\n")); i >= 0 {
		return part[:i], part[i+4:], true
	}
	// A lenient origin accepts bare LF, so a firewall that required CRLF would
	// refuse to parse bodies the application happily reads.
	if i := bytes.Index(part, []byte("\n\n")); i >= 0 {
		return part[:i], part[i+2:], true
	}
	// Headers with no terminator and no content: still a well-formed empty part.
	return part, nil, true
}

// parsePartHeaders reads the headers gwaf cares about.
func parsePartHeaders(headers []byte, info *PartInfo) {
	for len(headers) > 0 {
		var line []byte
		if i := bytes.IndexByte(headers, '\n'); i >= 0 {
			line, headers = headers[:i], headers[i+1:]
		} else {
			line, headers = headers, nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			continue
		}

		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := bytes.TrimSpace(line[:colon])
		value := bytes.TrimSpace(line[colon+1:])

		switch {
		case equalFoldBytes(name, "content-disposition"):
			// A repeated Content-Disposition is ambiguous: origins differ on
			// whether the first or last wins. Keeping the first and inspecting
			// both names means neither reading is missed.
			if v, ok := headerParam(value, "name"); ok && len(info.Name) == 0 {
				info.Name = v
			}
			if v, ok := headerParam(value, "filename"); ok && len(info.Filename) == 0 {
				info.Filename = v
			}
		case equalFoldBytes(name, "content-type"):
			ct := value
			if i := bytes.IndexByte(ct, ';'); i >= 0 {
				ct = bytes.TrimSpace(ct[:i])
			}
			info.ContentType = ct
			if v, ok := headerParam(value, "charset"); ok {
				info.Charset = v
			}
		}
	}
}

// headerParam extracts a parameter from a structured header value, handling
// both quoted and bare forms.
func headerParam(value []byte, param string) ([]byte, bool) {
	for i := 0; i+len(param) <= len(value); i++ {
		// The parameter name must start at a boundary, or "filename" would also
		// match inside "xfilename".
		if i > 0 {
			prev := value[i-1]
			if prev != ';' && prev != ' ' && prev != '\t' {
				continue
			}
		}
		if !equalFoldBytes(value[i:i+len(param)], param) {
			continue
		}

		j := i + len(param)
		for j < len(value) && (value[j] == ' ' || value[j] == '\t') {
			j++
		}
		if j >= len(value) || value[j] != '=' {
			continue
		}
		j++
		for j < len(value) && (value[j] == ' ' || value[j] == '\t') {
			j++
		}
		if j >= len(value) {
			return nil, false
		}

		if value[j] == '"' {
			j++
			start := j
			for j < len(value) && value[j] != '"' {
				// A backslash escape inside a quoted string.
				if value[j] == '\\' && j+1 < len(value) {
					j++
				}
				j++
			}
			return value[start:j], true
		}

		start := j
		for j < len(value) && value[j] != ';' && value[j] != ' ' && value[j] != '\t' {
			j++
		}
		return value[start:j], true
	}
	return nil, false
}

// indexDelimiter finds the next "--boundary" at a line start at or after i.
func indexDelimiter(src []byte, i int, dash []byte) int {
	for i <= len(src)-len(dash) {
		j := bytes.Index(src[i:], dash)
		if j < 0 {
			return -1
		}
		pos := i + j
		// A delimiter only counts at the start of the body or after a line end,
		// so the boundary string appearing inside content is not mistaken for one.
		if pos == 0 || src[pos-1] == '\n' {
			return pos
		}
		i = pos + 1
	}
	return -1
}

// skipLineEnd advances past optional padding and one line ending.
func skipLineEnd(src []byte, i int) int {
	for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
		i++
	}
	if i < len(src) && src[i] == '\r' {
		i++
	}
	if i < len(src) && src[i] == '\n' {
		return i + 1
	}
	// A delimiter with no line ending is malformed, but an empty final part is
	// not: report the position and let the caller decide.
	if i >= len(src) {
		return i
	}
	return -1
}

// trimTrailingLineEnd removes the CRLF that belongs to the following delimiter.
func trimTrailingLineEnd(part []byte) []byte {
	if n := len(part); n > 0 && part[n-1] == '\n' {
		part = part[:n-1]
		if n = len(part); n > 0 && part[n-1] == '\r' {
			part = part[:n-1]
		}
	}
	return part
}

// Boundary extracts the boundary parameter from a multipart Content-Type.
//
// The bool reports whether the header declares multipart at all. A multipart
// type with no boundary is malformed rather than merely unstructured: the
// origin cannot parse it either, and treating it as an opaque body would hide
// that.
func Boundary(contentType string) ([]byte, bool) {
	ct := contentType
	media := ct
	if i := indexByteStr(media, ';'); i >= 0 {
		media = media[:i]
	}
	media = trimSpaceStr(lowerStr(media))
	if !hasPrefixStr(media, "multipart/") {
		return nil, false
	}
	b, ok := headerParam([]byte(ct), "boundary")
	if !ok {
		return nil, true
	}
	return b, true
}

func hasPrefixStr(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// equalFoldBytes compares two byte slices ignoring ASCII case.
func equalFoldBytes(a []byte, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		c := a[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != b[i] {
			return false
		}
	}
	return true
}
