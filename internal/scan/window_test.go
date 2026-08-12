// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package scan

import (
	"bytes"
	"testing"
)

// TestWindowsCoverEveryByte is the property the detectors depend on: a needle
// anywhere in the value lands intact inside at least one window.
func TestWindowsCoverEveryByte(t *testing.T) {
	const needle = "NEEDLE"
	for _, window := range []int{1 << 10, 8 << 10, 64 << 10} {
		for _, size := range []int{0, 1, window - 1, window, window + 1, 3*window + 7, 17 * window} {
			for _, at := range []int{0, size / 3, size / 2, size - len(needle)} {
				if size < len(needle) || at < 0 || at+len(needle) > size {
					continue
				}
				src := bytes.Repeat([]byte("x"), size)
				copy(src[at:], needle)

				found := false
				Windows(src, window, func(off int, w []byte) bool {
					if i := bytes.Index(w, []byte(needle)); i >= 0 {
						found = true
						if off+i != at {
							t.Errorf("window=%d size=%d at=%d: reported offset %d",
								window, size, at, off+i)
						}
						return false
					}
					return true
				})
				if !found {
					t.Errorf("window=%d size=%d: needle at %d was never in a window "+
						"— this is the padding bypass", window, size, at)
				}
			}
		}
	}
}

// TestWindowsTerminate guards the loop itself. A step of zero would hang the
// request path, which is a denial of service delivered by the defence.
func TestWindowsTerminate(t *testing.T) {
	for _, window := range []int{-1, 0, 1, 2, minOverlap - 1, minOverlap, maxOverlap, maxOverlap + 1, 1 << 20} {
		src := bytes.Repeat([]byte("x"), 1<<16)
		calls := 0
		Windows(src, window, func(int, []byte) bool {
			calls++
			return calls < 1_000_000
		})
		if calls == 0 {
			t.Errorf("window=%d: never called", window)
		}
		if calls >= 1_000_000 {
			t.Errorf("window=%d: did not terminate", window)
		}
	}
}

// TestSingleWindowIsThePassthrough keeps the common case free.
func TestSingleWindowIsThePassthrough(t *testing.T) {
	src := []byte("short value")
	calls := 0
	Windows(src, 64<<10, func(off int, w []byte) bool {
		calls++
		if off != 0 || !bytes.Equal(w, src) {
			t.Errorf("off=%d w=%q, want the whole value at 0", off, w)
		}
		return true
	})
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

// TestEarlyStop lets a detector stop at its first finding rather than paying
// for the rest of a large value.
func TestEarlyStop(t *testing.T) {
	src := bytes.Repeat([]byte("x"), 1<<20)
	calls := 0
	Windows(src, 8<<10, func(int, []byte) bool { calls++; return false })
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}
