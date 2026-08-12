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

// FuzzWindowsCovers is the property the whole package exists for.
//
// Windows now runs over every value in every detector, so its two failure modes
// are both severe and neither is visible from a call site:
//
//   - a step that does not advance hangs the request path, which is a denial of
//     service delivered by the defence itself;
//   - a gap between windows silently restores the padding bypass this package
//     was written to remove, and restores it invisibly, because the detector
//     reports "clean" exactly as it did before.
//
// So the fuzzer drives both: a bounded call count catches the first, and a
// needle placed at an arbitrary offset catches the second. The needle is
// checked for being *intact* rather than merely present, because a signal split
// across a boundary is precisely what overlap exists to prevent.
func FuzzWindowsCovers(f *testing.F) {
	f.Add(0, 0, 0)
	f.Add(100, 10, 5)
	f.Add(1<<16, 8<<10, 1<<15)
	f.Add(5, 1, 0)
	f.Add(1<<20, 64<<10, (1<<20)-8)

	f.Fuzz(func(t *testing.T, size, window, at int) {
		// Bound the inputs rather than the behaviour: a negative or enormous
		// size says nothing about the algorithm.
		if size < 0 || size > 1<<20 || window < -8 || window > 1<<20 {
			t.Skip()
		}
		const needle = "NEEDLE"
		src := bytes.Repeat([]byte("x"), size)

		place := -1
		if size >= len(needle) {
			at = ((at % (size - len(needle) + 1)) + (size - len(needle) + 1)) % (size - len(needle) + 1)
			copy(src[at:], needle)
			place = at
		}

		calls := 0
		found := false
		var maxEnd int
		Windows(src, window, func(off int, w []byte) bool {
			calls++
			if calls > 1<<20 {
				t.Fatalf("did not terminate: size=%d window=%d", size, window)
			}
			if off < 0 || off > len(src) {
				t.Fatalf("offset %d outside src of %d", off, len(src))
			}
			if off+len(w) > len(src) {
				t.Fatalf("window [%d,%d) overruns src of %d", off, off+len(w), len(src))
			}
			// Windows must alias src, never copy it: the detectors receive these
			// slices on the hot path and a copy per window would be an
			// allocation per window.
			if len(w) > 0 && &w[0] != &src[off] {
				t.Fatal("window does not alias src")
			}
			if off+len(w) > maxEnd {
				maxEnd = off + len(w)
			}
			if i := bytes.Index(w, []byte(needle)); i >= 0 && off+i == place {
				found = true
			}
			return true
		})

		if calls == 0 {
			t.Fatal("fn was never called")
		}
		if maxEnd != len(src) {
			t.Fatalf("windows reached %d of %d bytes: the tail is a blind spot",
				maxEnd, len(src))
		}
		// The guarantee is exact: a run of at most overlapFor(window) bytes is
		// never split. A needle longer than that is outside what Windows
		// promises, and asserting it anyway would be testing a claim the
		// package does not make.
		if place >= 0 && len(needle) <= overlapFor(window) && !found {
			t.Fatalf("needle at %d never appeared intact in any window "+
				"(size=%d window=%d overlap=%d): this is the padding bypass",
				place, size, window, overlapFor(window))
		}
	})
}
