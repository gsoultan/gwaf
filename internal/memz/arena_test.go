// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package memz

import (
	"bytes"
	"testing"

	"github.com/gsoultan/gwaf/types"
)

// spanAt builds a Span for tests that need one the arena did not produce.
func spanAt(off, length int) types.Span { return types.SpanOf(off, length) }

func TestZeroValueIsUsable(t *testing.T) {
	var a Arena

	span, ok := a.AppendString("hello")
	if !ok {
		t.Fatal("AppendString failed on the zero value")
	}
	if got := string(a.Resolve(span)); got != "hello" {
		t.Errorf("Resolve = %q, want %q", got, "hello")
	}
}

func TestAppendAndResolve(t *testing.T) {
	a := NewArena(64, 0)

	values := []string{"first", "second", "third"}
	spans := make([]types.Span, 0, len(values))

	for _, v := range values {
		s, ok := a.AppendString(v)
		if !ok {
			t.Fatalf("AppendString(%q) failed", v)
		}
		spans = append(spans, s)
	}

	for i, want := range values {
		if got := string(a.Resolve(spans[i])); got != want {
			t.Errorf("value %d = %q, want %q", i, got, want)
		}
	}
}

// TestSpansSurviveGrowth is the invariant that makes Span the right
// representation: offsets stay valid across a reallocation, where byte slices
// cut from the old backing array would not.
func TestSpansSurviveGrowth(t *testing.T) {
	a := NewArena(8, 0)

	first, ok := a.AppendString("abc")
	if !ok {
		t.Fatal("first append failed")
	}

	// Force several growths.
	for range 100 {
		if _, ok := a.AppendString("padding-padding-padding"); !ok {
			t.Fatal("padding append failed")
		}
	}

	if got := string(a.Resolve(first)); got != "abc" {
		t.Errorf("after growth Resolve = %q, want %q", got, "abc")
	}
}

func TestLimitRejectsOversizeAllocation(t *testing.T) {
	a := NewArena(16, 64)

	if _, ok := a.Append(bytes.Repeat([]byte("x"), 32)); !ok {
		t.Fatal("allocation within the limit failed")
	}
	// Exceeding the limit must fail rather than grow. The caller turns that
	// into a decision under its fail mode; silently truncating would be
	// indistinguishable from a bypass.
	if _, ok := a.Append(bytes.Repeat([]byte("x"), 64)); ok {
		t.Error("allocation beyond the limit succeeded")
	}
}

func TestResetRetainsCapacity(t *testing.T) {
	a := NewArena(1024, 0)
	a.AppendString("some data")

	before := a.Cap()
	a.Reset()

	if a.Len() != 0 {
		t.Errorf("Len() = %d after Reset, want 0", a.Len())
	}
	if a.Cap() != before {
		t.Errorf("Cap() = %d after Reset, want %d retained", a.Cap(), before)
	}
}

// TestResetReleasesOversizedBuffer stops one large request from permanently
// inflating every pooled arena.
func TestResetReleasesOversizedBuffer(t *testing.T) {
	a := NewArena(1024, 0)
	if _, ok := a.Append(bytes.Repeat([]byte("x"), maxRetainedSize*2)); !ok {
		t.Fatal("large append failed")
	}
	if a.Cap() <= maxRetainedSize {
		t.Fatalf("Cap() = %d, expected growth beyond %d", a.Cap(), maxRetainedSize)
	}

	a.Reset()
	if a.Cap() > maxRetainedSize {
		t.Errorf("Cap() = %d after Reset, want the oversized buffer released", a.Cap())
	}
}

func TestAllocRejectsNegative(t *testing.T) {
	a := NewArena(64, 0)
	if _, _, ok := a.Alloc(-1); ok {
		t.Error("Alloc(-1) succeeded")
	}
}

func TestResolveOutOfRangeIsSafe(t *testing.T) {
	a := NewArena(64, 0)
	a.AppendString("abc")

	// A stale span must resolve to nil rather than panic or expose unrelated
	// memory: this is the failure mode Span's offset representation is chosen
	// to make safe.
	stale := spanAt(1000, 100)
	if got := a.Resolve(stale); got != nil {
		t.Errorf("Resolve(stale) = %q, want nil", got)
	}
}

func TestEmptyAppend(t *testing.T) {
	a := NewArena(64, 0)
	span, ok := a.Append(nil)
	if !ok {
		t.Fatal("empty append failed")
	}
	if !span.Empty() {
		t.Error("empty append produced a non-empty span")
	}
	if got := a.Resolve(span); len(got) != 0 {
		t.Errorf("Resolve = %q, want empty", got)
	}
}

func BenchmarkAppendReset(b *testing.B) {
	a := NewArena(DefaultArenaSize, 1<<20)
	data := []byte("a typical header value of moderate length")

	b.ReportAllocs()
	for b.Loop() {
		for range 20 {
			a.Append(data)
		}
		a.Reset()
	}
}
