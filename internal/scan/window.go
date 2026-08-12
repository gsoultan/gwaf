// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package scan covers a whole value with bounded work.
//
// # The bug this exists to remove
//
// Every semantic detector bounded its analysis with a constant named maxScan and
// implemented it as `src = src[:maxScan]`. The reasoning written beside each one
// was sound and is still true — "every signal is local to one command", "a
// payload declares itself early" — but it justifies a bounded *window*, not a
// bounded *prefix*. A payload does not need to be longer than the bound. It only
// needs to sit past it.
//
// Measured, with the payload placed after N bytes of ordinary text:
//
//	phpi     8 KiB   missed at 16 KiB of padding
//	javaser  8 KiB   missed at 16 KiB
//	ldapi    8 KiB   missed at 16 KiB
//	shelli  64 KiB   missed at 128 KiB
//	xss     64 KiB   missed at 128 KiB
//	ssti    64 KiB   missed at 128 KiB
//
// Six of seven classes, each at exactly its own constant. This is the technique
// the 2026 literature calls the WAF blind spot, and gwaf's answer to it —
// refusing to truncate an oversize body — was correct at the transaction layer
// and absent one level down. transaction.go's noteOversize states the rule
// plainly: "Inspecting the first 64 KiB of a value and reporting the request as
// clean is a bypass with a padding step." The detectors were doing exactly that.
//
// # Why windows rather than no bound at all
//
// Unbounded analysis is the other failure: an attacker sends a large value and
// chooses how much work the firewall does. Bounded everything is not negotiable
// (CLAUDE.md §2). Windowing keeps the per-window bound that made the detectors
// affordable and pays a linear cost in the value's length, which is a cost the
// fuel meter already prices per byte — so a value large enough to matter exhausts
// the budget and the configured FailMode decides, rather than the value being
// silently reported clean.
//
// # Why locality makes this lossless
//
// Overlap is what turns "scan each window" into "scan the value". A signal
// spanning a window boundary would be split and missed, so consecutive windows
// overlap by more than the longest signal any detector can produce. The
// detectors' own comments are the argument that such a bound exists: a command
// name is bounded by maxTokenLen, a serialization header declares itself in a
// few dozen bytes, a tag is shorter than the overlap by orders of magnitude.
package scan

// Overlap bounds are how much consecutive windows share.
//
// Overlap is pure duplicated work — every shared byte is scanned twice — so it
// is sized against what it has to protect and no larger. What it protects is a
// signal straddling a window boundary, and every detector bounds its own
// signals far below these numbers: shelli caps a command token at 32 bytes, its
// sensitive paths are around 30, javaser reads a header of a few dozen, and the
// longest template expression or script tag any of them scores is measured in
// hundreds.
//
// minOverlap is therefore already an order of magnitude of headroom, and
// maxOverlap keeps a large window from paying for headroom it cannot use.
//
// The first version used a flat 4 KiB, which on the 8 KiB windows that phpi,
// javaser and ldapi use meant a step of 4 KiB — every byte scanned twice, for a
// guarantee those detectors needed a few dozen bytes to obtain. Proportional
// sizing costs 14% on those and under 2% at 64 KiB.
const (
	minOverlap = 1 << 10
	maxOverlap = 4 << 10
)

// overlapFor sizes the shared region for a given window, and with it the
// guarantee Windows offers:
//
//	a run of at most overlapFor(window) bytes always appears intact in
//	some window.
//
// That is exactly right rather than approximately right. A run of length L
// survives iff the step is at most window-L; the step is window-overlap; so the
// guarantee is L <= overlap and nothing more. Every detector's signals sit
// orders of magnitude under minOverlap, which is why this is a comfortable
// bound in practice and a precise one on paper.
//
// The final clamp is the part a fuzzer had to find. Without it a window smaller
// than minOverlap produced an overlap larger than the window itself — an
// incoherent claim, since no window can hold a run longer than it is — and the
// step then fell through to a fallback that still advanced but guaranteed
// nothing. Capping at half the window keeps overlap meaningful at every size and
// keeps the step strictly positive without a fallback.
func overlapFor(window int) int {
	if window <= 1 {
		return 0
	}
	o := window / 8
	if o < minOverlap {
		o = minOverlap
	}
	if o > maxOverlap {
		o = maxOverlap
	}
	if half := window / 2; o > half {
		o = half
	}
	return o
}

// Windows calls fn with successive overlapping views of src, stopping early if
// fn returns false.
//
// The int passed to fn is the window's offset within src, so a span reported
// against the window can be translated back to the value the caller was given.
// Reporting a span relative to a window would put the highlight in the wrong
// place in an audit log, which is the kind of detail that makes an operator stop
// trusting the tool.
//
// A value that fits in one window is passed through unchanged and uncopied, so
// the overwhelmingly common case costs one comparison.
func Windows(src []byte, window int, fn func(off int, w []byte) bool) {
	if window <= 0 || len(src) <= window {
		fn(0, src)
		return
	}

	// Step must make progress. A window at or below the overlap would advance by
	// zero or less and loop forever, so the step is floored at half the window —
	// still generous overlap, and always forward.
	step := window - overlapFor(window)
	if step <= 0 {
		step = window / 2
	}
	if step <= 0 {
		step = 1
	}

	for off := 0; off < len(src); off += step {
		end := off + window
		if end > len(src) {
			end = len(src)
		}
		if !fn(off, src[off:end]) {
			return
		}
		if end == len(src) {
			return
		}
	}
}
