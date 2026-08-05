// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package transform provides the built-in value normalizations.
//
// Each transform returns false from Apply when it changed nothing, which lets
// the engine keep using the original bytes instead of copying. Already-normal
// traffic is the common case, so this is a large part of why benign requests
// allocate nothing.
//
// These are the materialised implementations. They are deliberately simple and
// obviously correct: docs/CONCEPT.md §3 plans to fold streamable transforms
// into the matcher itself, and when that lands these become the differential
// fuzz oracle it is validated against. Keeping them straightforward is what
// makes them usable as an oracle.
package transform

import "github.com/gsoultan/gwaf/rules"

// Lowercase folds ASCII upper case to lower case.
//
// Only ASCII is folded. Unicode case folding can change byte length, which
// would invalidate the offsets that match spans are reported in, and it opens a
// normalization-mismatch surface of its own.
var Lowercase rules.Transform = lowercase{}

type lowercase struct{}

func (lowercase) Name() string { return "lowercase" }

func (lowercase) MaxOutputLen(n int) int { return n }

func (lowercase) Apply(dst, src []byte) ([]byte, bool) {
	changed := false
	for i := range len(src) {
		if src[i] >= 'A' && src[i] <= 'Z' {
			changed = true
			break
		}
	}
	if !changed {
		return src, false
	}
	dst = dst[:0]
	for _, c := range src {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst, true
}

// RemoveWhitespace strips ASCII whitespace.
//
// Attackers insert whitespace to break up keywords ("UNI ON SELECT"); origins
// often ignore it. Stripping it before matching removes that gap.
var RemoveWhitespace rules.Transform = removeWhitespace{}

type removeWhitespace struct{}

func (removeWhitespace) Name() string { return "remove_whitespace" }

func (removeWhitespace) MaxOutputLen(n int) int { return n }

func (removeWhitespace) Apply(dst, src []byte) ([]byte, bool) {
	changed := false
	for _, c := range src {
		if isSpace(c) {
			changed = true
			break
		}
	}
	if !changed {
		return src, false
	}
	dst = dst[:0]
	for _, c := range src {
		if !isSpace(c) {
			dst = append(dst, c)
		}
	}
	return dst, true
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	default:
		return false
	}
}

// URLDecode decodes percent-encoding and, per the form-encoding convention,
// '+' as space.
//
// Malformed escapes are left verbatim rather than dropped or guessed. Guessing
// is precisely how a WAF and an origin come to disagree about what a request
// says, and that disagreement is the CVE-2026-21876 bug class. When gwaf cannot
// determine the decoding, it must not invent one — docs/CONCEPT.md §4 handles
// genuine ambiguity by evaluating every plausible reading rather than picking.
var URLDecode rules.Transform = urlDecode{}

type urlDecode struct{}

func (urlDecode) Name() string { return "url_decode" }

func (urlDecode) MaxOutputLen(n int) int { return n }

func (urlDecode) Apply(dst, src []byte) ([]byte, bool) {
	changed := false
	for _, c := range src {
		if c == '%' || c == '+' {
			changed = true
			break
		}
	}
	if !changed {
		return src, false
	}

	dst = dst[:0]
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
			// Malformed escape: keep it verbatim.
			dst = append(dst, c)
			i++
		default:
			dst = append(dst, c)
			i++
		}
	}
	return dst, true
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

// CompressWhitespace collapses runs of ASCII whitespace to a single space.
//
// Unlike RemoveWhitespace this preserves token boundaries, which matters for
// operators that care about word structure.
var CompressWhitespace rules.Transform = compressWhitespace{}

type compressWhitespace struct{}

func (compressWhitespace) Name() string { return "compress_whitespace" }

func (compressWhitespace) MaxOutputLen(n int) int { return n }

func (compressWhitespace) Apply(dst, src []byte) ([]byte, bool) {
	changed := false
	for i, c := range src {
		if isSpace(c) && (c != ' ' || (i > 0 && isSpace(src[i-1]))) {
			changed = true
			break
		}
	}
	if !changed {
		return src, false
	}
	dst = dst[:0]
	prevSpace := false
	for _, c := range src {
		if isSpace(c) {
			if !prevSpace {
				dst = append(dst, ' ')
			}
			prevSpace = true
			continue
		}
		dst = append(dst, c)
		prevSpace = false
	}
	return dst, true
}

// NormalizePath resolves "." and ".." segments and collapses duplicate
// separators, so that traversal attempts are compared in canonical form.
//
// Backslashes are treated as separators: Windows origins accept them, and a WAF
// that did not would miss "..\..\" traversal against those origins.
var NormalizePath rules.Transform = normalizePath{}

type normalizePath struct{}

func (normalizePath) Name() string { return "normalize_path" }

// MaxOutputLen reserves one byte beyond the input length.
//
// Every emitted segment is followed by a separator and the trailing one is
// removed at the end, so the buffer transiently holds one byte more than the
// final result: "/a/b" becomes "/a/b/" before the trim. The bound has to cover
// that peak, not just the final length — otherwise append grows the engine's
// scratch buffer and the transform allocates on every request.
func (normalizePath) MaxOutputLen(n int) int { return n + 1 }

func (normalizePath) Apply(dst, src []byte) ([]byte, bool) {
	needs := false
	for i, c := range src {
		if c == '\\' || c == '.' || (c == '/' && i > 0 && src[i-1] == '/') {
			needs = true
			break
		}
	}
	if !needs {
		return src, false
	}

	// Split on either separator, resolving segments as we go.
	//
	// ".." pops the previous segment by scanning backwards through the output
	// rather than keeping a stack of segment offsets. A stack would be an
	// auxiliary allocation on the hot path — escape analysis cannot keep it on
	// the stack once it is appended to — and the backwards scan is amortised
	// linear over the whole path, since each byte is passed at most twice.
	dst = dst[:0]
	absolute := len(src) > 0 && (src[0] == '/' || src[0] == '\\')

	// base marks the end of the prefix that ".." can never pop past: the root
	// separator of an absolute path, or the leading "../" run of a relative
	// one. One ".." cannot cancel another, so leading ones extend base instead
	// of becoming poppable segments — otherwise "../../x" would collapse to "x".
	base := 0
	if absolute {
		dst = append(dst, '/')
		base = 1
	}

	start := 0
	for i := 0; i <= len(src); i++ {
		if i < len(src) && src[i] != '/' && src[i] != '\\' {
			continue
		}
		seg := src[start:i]
		start = i + 1

		switch {
		case len(seg) == 0 || (len(seg) == 1 && seg[0] == '.'):
			// An empty segment or "." contributes nothing.
		case len(seg) == 2 && seg[0] == '.' && seg[1] == '.':
			if len(dst) > base {
				// dst ends with "<segment>/"; drop it.
				d := len(dst) - 1
				for d > base && dst[d-1] != '/' {
					d--
				}
				dst = dst[:d]
			} else if !absolute {
				// Traversal above the start of a relative path is meaningful
				// and must be preserved, not silently dropped.
				dst = append(dst, ".."...)
				dst = append(dst, '/')
				base = len(dst)
			}
			// An absolute path cannot escape its root, so ".." at base is a
			// no-op rather than an error.
		default:
			dst = append(dst, seg...)
			dst = append(dst, '/')
		}
	}

	// Drop the trailing separator unless the input had one or the result is the
	// bare root.
	if n := len(dst); n > 1 && dst[n-1] == '/' {
		last := src[len(src)-1]
		if last != '/' && last != '\\' {
			dst = dst[:n-1]
		}
	}
	return dst, true
}
