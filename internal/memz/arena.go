// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package memz owns all allocation on the request hot path.
//
// Every transaction holds one Arena. Intermediate values — decoded arguments,
// materialised transform output, joined views — bump-allocate from it and the
// whole thing is reset when the transaction is recycled. Steady-state GC
// pressure from serving traffic therefore approaches zero, which matters more
// under Go's Green Tea collector where marking locality drives cost.
//
// Values are addressed as types.Span offsets rather than byte slices, so
// transaction state stays pointer-free and the collector never traces it. See
// docs/CONCEPT.md §5.
package memz

import "github.com/gsoultan/gwaf/types"

// DefaultArenaSize is the initial per-transaction arena capacity. It is sized
// so that a typical API request — headers plus a small JSON body plus decoded
// arguments — never grows the arena, while keeping per-in-flight-transaction
// memory within the SLO in CLAUDE.md §2.
const DefaultArenaSize = 8 << 10 // 8 KiB

// maxRetainedSize bounds the capacity an Arena keeps when recycled. A single
// large request must not permanently inflate every pooled arena; beyond this
// the backing array is dropped and reallocated at DefaultArenaSize.
const maxRetainedSize = 256 << 10 // 256 KiB

// Arena is a bump allocator with a single reset point.
//
// The zero value is usable and allocates its backing array on first use. An
// Arena is owned by exactly one goroutine.
type Arena struct {
	buf []byte
	// limit caps total growth. Zero means unlimited, which is intended for
	// offline tooling; serving traffic always sets one.
	limit int
}

// NewArena returns an Arena with the given initial capacity and growth limit.
// A non-positive limit means unlimited.
func NewArena(size, limit int) *Arena {
	if size <= 0 {
		size = DefaultArenaSize
	}
	return &Arena{
		buf:   make([]byte, 0, size),
		limit: limit,
	}
}

// SetLimit sets the maximum total capacity the arena may grow to.
func (a *Arena) SetLimit(limit int) { a.limit = limit }

// Len returns the bytes currently allocated.
func (a *Arena) Len() int { return len(a.buf) }

// Cap returns the arena's current capacity.
func (a *Arena) Cap() int { return cap(a.buf) }

// Bytes returns the arena's backing buffer.
//
// The result is only valid until the next allocation, which may reallocate, and
// until Reset. Resolve a Span against the slice returned here, do not retain it.
func (a *Arena) Bytes() []byte { return a.buf }

// Alloc reserves n bytes and returns the Span covering them along with a slice
// for writing into. The contents are not zeroed: callers overwrite the full
// span, and zeroing 8 KiB per transaction is exactly the cost this package
// exists to avoid.
//
// The bool reports success. Allocation fails when the arena would exceed its
// limit; callers must treat that as a decision (reject the request under the
// configured fail mode) rather than continuing with truncated data, since a
// partially inspected value is indistinguishable from a bypass.
func (a *Arena) Alloc(n int) (types.Span, []byte, bool) {
	if n < 0 {
		return types.Span{}, nil, false
	}
	off := len(a.buf)
	if !a.reserve(n) {
		return types.Span{}, nil, false
	}
	a.buf = a.buf[:off+n]
	return types.SpanOf(off, n), a.buf[off : off+n], true
}

// Append copies src into the arena and returns the Span covering the copy.
func (a *Arena) Append(src []byte) (types.Span, bool) {
	span, dst, ok := a.Alloc(len(src))
	if !ok {
		return types.Span{}, false
	}
	copy(dst, src)
	return span, true
}

// AppendString copies s into the arena and returns the Span covering the copy.
func (a *Arena) AppendString(s string) (types.Span, bool) {
	span, dst, ok := a.Alloc(len(s))
	if !ok {
		return types.Span{}, false
	}
	copy(dst, s)
	return span, true
}

// Resolve returns the bytes covered by span.
func (a *Arena) Resolve(span types.Span) []byte { return span.Bytes(a.buf) }

// reserve ensures capacity for n more bytes, growing if needed.
func (a *Arena) reserve(n int) bool {
	need := len(a.buf) + n
	if a.limit > 0 && need > a.limit {
		return false
	}
	if need <= cap(a.buf) {
		return true
	}
	newCap := max(cap(a.buf)*2, DefaultArenaSize)
	for newCap < need {
		newCap *= 2
	}
	if a.limit > 0 && newCap > a.limit {
		newCap = a.limit
	}
	grown := make([]byte, len(a.buf), newCap)
	copy(grown, a.buf)
	a.buf = grown
	return true
}

// Reset returns the arena to empty, retaining its capacity for reuse.
//
// Capacity above maxRetainedSize is released so that one oversized request does
// not permanently inflate a pooled arena.
func (a *Arena) Reset() {
	if cap(a.buf) > maxRetainedSize {
		a.buf = make([]byte, 0, DefaultArenaSize)
		return
	}
	a.buf = a.buf[:0]
}
