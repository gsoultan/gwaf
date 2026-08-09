// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package transform

import "github.com/gsoultan/gwaf/rules"

// HexEscapeDecode resolves only the numeric backslash escapes — \xHH and
// \uHHHH — and leaves every other backslash sequence byte-for-byte intact.
//
// # Why this exists next to EscapeDecode
//
// EscapeDecode is the full JavaScript reading, and part of that reading is that
// an escaped ordinary character is that character: "\q" is "q", and the
// backslash is dropped. That is correct for a JS string literal and wrong for a
// path, because "..\..\windows\win.ini" would decode to "....windowswin.ini" and
// lose the separators the traversal rules match on. So the path chain could not
// use it, and "..\u002f..\u002fetc\u002fpasswd" walked straight through every
// traversal rule -- there is no '/' anywhere in those bytes.
//
// The split is not a compromise, it is the ambiguity boundary. "\x2f" is '/' to
// every consumer that reads escapes at all, so decoding it resolves nothing that
// was in doubt. "\." is read one way by a JS string and another by a Windows
// path, and that is a genuine fork -- the kind gwaf answers with a reading
// rather than a rewrite (CLAUDE.md invariant 1). This transform decodes the
// unambiguous half and refuses to guess at the other.
var HexEscapeDecode rules.Transform = hexEscapeDecode{}

type hexEscapeDecode struct{}

func (hexEscapeDecode) Name() string { return "hex_escape_decode" }

// MaxOutputLen: decoding only ever shortens. "\x41" is four bytes in and one
// out; "\uFFFF" is six in and at most three out as UTF-8.
func (hexEscapeDecode) MaxOutputLen(n int) int { return n }

func (hexEscapeDecode) Apply(dst, src []byte) ([]byte, bool) {
	if indexByteIn(src, '\\') < 0 {
		return src, false
	}

	dst = dst[:0]
	changed := false
	for i := 0; i < len(src); {
		if src[i] != '\\' || i+1 >= len(src) {
			dst = append(dst, src[i])
			i++
			continue
		}
		c := src[i+1]
		if c != 'x' && c != 'u' {
			// Not a numeric escape. Copy the backslash verbatim and carry on;
			// the character after it is examined on its own next pass, so
			// "\\x41" -- an escaped backslash followed by text -- is not
			// mistaken for an escape.
			dst = append(dst, src[i])
			i++
			continue
		}
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
			// A truncated or malformed escape is not an escape. Keeping it
			// verbatim matters: pretending "\xZZ" decodes would rewrite the
			// value into something the origin never sees.
			dst = append(dst, src[i])
			i++
			continue
		}
		dst = appendRuneTo(dst, v)
		i += 2 + width
		changed = true
	}
	if !changed {
		return src, false
	}
	return dst, true
}
