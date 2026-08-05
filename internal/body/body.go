// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package body extracts individual fields from a request body.
//
// # Why this is not just an optimization
//
// Analysing a body as one opaque blob is both slow and wrong.
//
// Slow, because every detector runs over the whole document. A 1 KiB JSON
// payload is tokenized as SQL and scanned as markup in its entirety, when the
// only attacker-controlled parts are the leaf values.
//
// Wrong, because a JSON string is not its bytes. `{"c":"<script>"}`
// contains no '<' anywhere on the wire, and the origin's parser hands the
// application `<script>`. A firewall reading the raw body sees inert text. This
// is the same disagreement class as internal/interpret, arriving through a
// different door: the escape is not an ambiguity to enumerate, it is a decoding
// the origin will definitely perform.
//
// Parsing also makes the schema layer meaningful for bodies. A field declared
// an integer can only be checked, and skipped, once it is a field.
//
// # Bounds
//
// Every parser here is bounded before it starts: depth, field count, key
// length, and value length all have ceilings. Exceeding one is reported rather
// than truncated, because a body that was only partly parsed has not been shown
// to be clean. Nothing recurses; nesting is tracked on an explicit stack.
package body

import "errors"

// Errors returned when a body cannot be fully parsed. Each is a decision for
// the caller to apply its fail mode to, never a reason to continue with partial
// data.
var (
	// ErrMalformed reports input that is not valid for its declared type.
	ErrMalformed = errors.New("body: malformed")

	// ErrTooDeep reports nesting beyond MaxDepth.
	ErrTooDeep = errors.New("body: nesting too deep")

	// ErrTooManyFields reports more leaf values than MaxFields.
	ErrTooManyFields = errors.New("body: too many fields")

	// ErrTooLarge reports a key or value beyond its ceiling.
	ErrTooLarge = errors.New("body: field too large")
)

// Limits bound parsing work. Zero fields fall back to the defaults.
type Limits struct {
	MaxDepth     int
	MaxFields    int
	MaxKeyLen    int
	MaxValueLen  int
	MaxTotalSize int
}

// DefaultLimits are sized for realistic API traffic. They are deliberately
// tight: a body that needs deeper nesting or more fields than these is not one
// an ordinary client sends, and the ceiling is what makes worst-case work
// bounded regardless of input.
func DefaultLimits() Limits {
	return Limits{
		MaxDepth:     32,
		MaxFields:    1024,
		MaxKeyLen:    256,
		MaxValueLen:  64 << 10,
		MaxTotalSize: 1 << 20,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxFields <= 0 {
		l.MaxFields = d.MaxFields
	}
	if l.MaxKeyLen <= 0 {
		l.MaxKeyLen = d.MaxKeyLen
	}
	if l.MaxValueLen <= 0 {
		l.MaxValueLen = d.MaxValueLen
	}
	if l.MaxTotalSize <= 0 {
		l.MaxTotalSize = d.MaxTotalSize
	}
	return l
}

// Kind classifies a parsed leaf, so the caller can tell a string an attacker
// wrote from a number the format itself constrains.
type Kind uint8

// Kinds.
const (
	KindString Kind = iota
	KindNumber
	KindBool
	KindNull
	KindKey // an object member name, which is also attacker-controlled
)

// Emit receives one leaf. Returning false stops parsing early.
//
// name and value alias the parser's buffers and are only valid for the duration
// of the call. A caller that needs to retain them must copy — in gwaf that copy
// goes into the transaction arena.
type Emit func(name, value []byte, kind Kind) bool

// Parser extracts fields from a body.
//
// A Parser owns reusable buffers and is reset per body, so parsing costs no
// allocation after warm-up. It is owned by one goroutine, like the transaction
// driving it.
type Parser struct {
	// path accumulates the dotted key of the current position, so a decision
	// can say "items[3].note" rather than "somewhere in the body".
	path []byte
	// pathStack records where each path component started, so a component can
	// be popped without rescanning.
	pathStack []int
	// scratch holds the unescaped form of the current string value.
	scratch []byte

	fields int
	limits Limits
}

// Reset prepares p for a new body.
func (p *Parser) Reset(limits Limits) {
	p.limits = limits.withDefaults()
	p.path = p.path[:0]
	p.pathStack = p.pathStack[:0]
	p.scratch = p.scratch[:0]
	p.fields = 0
}

// Fields returns how many leaves were emitted.
func (p *Parser) Fields() int { return p.fields }

// pushPath appends a component to the dotted path.
func (p *Parser) pushPath(name []byte, index bool) bool {
	p.pathStack = append(p.pathStack, len(p.path))
	if index {
		p.path = append(p.path, '[')
		p.path = appendInt(p.path, name)
		p.path = append(p.path, ']')
	} else {
		if len(p.path) > 0 {
			p.path = append(p.path, '.')
		}
		p.path = append(p.path, name...)
	}
	return len(p.path) <= p.limits.MaxKeyLen
}

// popPath removes the last component.
func (p *Parser) popPath() {
	if n := len(p.pathStack); n > 0 {
		p.path = p.path[:p.pathStack[n-1]]
		p.pathStack = p.pathStack[:n-1]
	}
}

// emit reports one leaf, enforcing the field-count ceiling.
func (p *Parser) emit(fn Emit, value []byte, kind Kind) (bool, error) {
	p.fields++
	if p.fields > p.limits.MaxFields {
		return false, ErrTooManyFields
	}
	if len(value) > p.limits.MaxValueLen {
		return false, ErrTooLarge
	}
	return fn(p.path, value, kind), nil
}

// appendInt appends a small non-negative integer given as digits.
func appendInt(dst []byte, digits []byte) []byte {
	return append(dst, digits...)
}

// itoa writes a non-negative int into a small buffer without allocating.
func itoa(dst []byte, n int) []byte {
	if n == 0 {
		return append(dst, '0')
	}
	var tmp [20]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
	}
	return append(dst, tmp[i:]...)
}
