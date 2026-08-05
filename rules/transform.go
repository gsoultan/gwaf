// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package rules

// Transform normalizes a value before an operator sees it.
//
// Transforms exist because attackers encode payloads and origins decode them.
// A WAF that inspects only the raw bytes is trivially bypassed, and one that
// decodes differently from the origin is bypassed in a subtler way — that
// mismatch is the CVE-2026-21876 failure class.
//
// Transform is one of the five public extension points (docs/RULES.md §4) and
// is frozen under semver at v1.0.
//
// Implementations must be:
//
//   - Pure. The same input always produces the same output. Transform results
//     are memoised per transaction, so an impure transform produces a decision
//     that depends on evaluation order.
//   - Concurrent-safe. One instance is shared across all transactions.
//   - Non-expanding, or explicitly bounded. Output longer than input is allowed
//     but must be bounded by a constant factor, since output length feeds the
//     arena and therefore the memory budget.
type Transform interface {
	// Name returns a stable identifier used in compile reports, explain output,
	// and declarative rule formats.
	Name() string

	// Apply writes the normalized form of src into dst and returns the result.
	//
	// dst is a scratch buffer owned by the caller with capacity for at least
	// MaxOutputLen(len(src)) bytes; implementations should append to dst[:0] and
	// return the result rather than allocating.
	//
	// The bool reports whether anything actually changed. Returning false lets
	// the engine skip the copy and keep using src, which is the common case for
	// already-normalized traffic and a large part of why benign requests
	// allocate nothing.
	Apply(dst, src []byte) ([]byte, bool)

	// MaxOutputLen returns an upper bound on the output length for an input of
	// the given length. The engine uses it to size scratch space up front, so
	// an implementation that exceeds its own bound will have its output
	// truncated by the arena limit — which the engine treats as a failed
	// transform rather than silently inspecting partial data.
	MaxOutputLen(srcLen int) int
}
