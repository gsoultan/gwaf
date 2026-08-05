// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package types

// Span identifies a byte range inside a buffer owned by a transaction.
//
// Span is deliberately pointer-free: the garbage collector never traces it, so
// transaction state built from Spans is invisible to GC marking. This is the
// endpoint of the allocation strategy described in docs/CONCEPT.md §5.
//
// A Span is only meaningful together with the buffer it was cut from. It cannot
// keep that buffer alive, which is intentional — it makes accidental use after
// the owning arena is recycled a logic error rather than a silent data race on
// reused memory. Resolve a Span to bytes only at an API boundary, via Bytes.
type Span struct {
	Off uint32
	Len uint32
}

// SpanOf returns the Span covering buf[off:off+length].
func SpanOf(off, length int) Span {
	return Span{Off: uint32(off), Len: uint32(length)}
}

// End returns the exclusive end offset of s.
func (s Span) End() uint32 { return s.Off + s.Len }

// Empty reports whether s covers no bytes.
func (s Span) Empty() bool { return s.Len == 0 }

// Bytes resolves s against buf.
//
// It returns nil when s does not lie entirely within buf, so a stale or
// corrupted Span degrades to an empty value instead of panicking or exposing
// unrelated memory. Callers on the hot path that have already validated bounds
// may slice directly.
func (s Span) Bytes(buf []byte) []byte {
	end := uint64(s.Off) + uint64(s.Len)
	if end > uint64(len(buf)) {
		return nil
	}
	return buf[s.Off:end]
}
