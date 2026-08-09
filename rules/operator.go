// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package rules

import (
	"github.com/gsoultan/gwaf/types"
)

// Match describes where inside an evaluated value an operator matched.
//
// The span makes every decision explainable: a block carries the exact bytes
// that caused it, which is what turns false-positive triage from archaeology
// into a diff. An operator that cannot report a span should report the whole
// value rather than a zero span.
type Match struct {
	// Span locates the match within the value passed to Eval, not within the
	// original request buffer. The engine translates it for reporting.
	Span types.Span
}

// WholeValue returns a Match covering all of value.
func WholeValue(value []byte) Match {
	return Match{Span: types.SpanOf(0, len(value))}
}

// EvalContext carries the context an operator may need beyond the value itself.
//
// # What may be trusted
//
// The fields come from two places that look identical in Go and are not:
//
//   - Target, Key and Origins are trustworthy. The first two are how gwaf
//     parsed the request rather than what the request said; Origins is
//     embedder configuration, set with gwaf.WithOrigins.
//   - Method, RequestURI, Host and Siblings are attacker-controlled. All four
//     are bytes the client chose.
//
// Attacker-controlled context is evidence, never ground truth. It may raise
// suspicion; it may not be the thing that clears a value. The direction is what
// matters: Siblings used to convict -- "path=/etc/ together with target=passwd"
// -- is sound, because supplying it gains an attacker nothing. Host used to
// acquit -- "this destination matches Host, so it is same-origin" -- is a
// bypass, because the attacker supplies both sides and sets them equal.
//
// That was a real bypass in v0.4.0's OffOriginURLRule, fixed in v0.4.1 by
// comparing against Origins. docs/RULES.md §4 has the table and the reasoning.
//
// It is passed by pointer and is owned by the engine; operators must not retain
// it or any slice reachable from it beyond the Eval call, because the backing
// arena is recycled when the transaction ends.
type EvalContext struct {
	// Target is the collection the value came from.
	Target types.Target

	// Key is the specific key within a keyed collection — a header name, an
	// argument name — or empty for unkeyed targets.
	Key string

	// Method, RequestURI and Host describe the request the value arrived in.
	// They are the same for every value in a transaction and are populated once
	// per phase, so reading them costs nothing.
	//
	// They exist because some questions are not answerable from a value alone.
	// "Is this URL a destination the attacker chose?" needs the request's own
	// origin to compare against — without it, a rule cannot tell
	// "redirect_to=https://app.example.com/cb" arriving at app.example.com from
	// the same bytes arriving anywhere else, and has to choose between missing
	// open redirects and blocking OAuth. Route also carries real evidence:
	// "file=functions.php" is the WordPress theme editor working on
	// /wp-admin/theme-editor.php and local file inclusion on /download.
	//
	// These are bytes, not strings, because they are read on the request path
	// and materialising three strings per transaction would cost the
	// zero-allocation benign case. They point into the transaction's arena and
	// follow the same rule as everything else here: read them, do not retain
	// them.
	//
	// Any of them may be empty — a request need not carry a Host header, and a
	// value can be evaluated in a phase before the request line was set. An
	// operator that requires one must handle its absence rather than assume it.
	Method     []byte
	RequestURI []byte
	Host       []byte

	// Origins are the hostnames the embedder declared as its own, via
	// gwaf.WithOrigins. Empty when none were declared.
	//
	// This exists because Host does not. A rule that asks "is this destination
	// somewhere else?" cannot answer it from the request, because the request
	// supplies both sides: set Host to match the destination and any comparison
	// against it concludes same-origin. That was a real bypass in v0.4.0's
	// off-origin rule, and the lesson generalises -- a verdict that depends on
	// attacker-supplied data is not a verdict.
	//
	// Who the application is, is configuration. It is the embedder's to state
	// and gwaf's to trust.
	Origins []string

	// Siblings are the other arguments of the same request, when the engine has
	// them. It is nil outside the argument collections.
	//
	// It exists for the payload that is not in any single value. An application
	// that joins "path" and "target" reads "/etc/" and "passwd" and opens
	// /etc/passwd; a rule looking at one argument at a time sees a directory and
	// a word, and neither is an attack. Splitting a payload across parameters is
	// a documented technique and per-argument inspection is structurally blind
	// to it.
	//
	// Reading it is deliberately awkward, and that is the point: an operator
	// that walks every sibling on every value turns per-request work quadratic
	// in the argument count. Use SiblingValue to ask for one name.
	Siblings Args
}

// Args is a read-only view of a request's arguments.
//
// It is a slice of pairs rather than a map because building a map per request
// would allocate, and the argument count is small enough that a scan is
// cheaper. The engine owns the backing memory; do not retain it.
type Args struct {
	Names  [][]byte
	Values [][]byte
}

// SiblingValue returns the value of another argument of the same request.
//
// The comparison is case-sensitive, because argument names are.
func (c *EvalContext) SiblingValue(name string) ([]byte, bool) {
	for i, n := range c.Siblings.Names {
		if len(n) != len(name) {
			continue
		}
		if string(n) == name && i < len(c.Siblings.Values) {
			return c.Siblings.Values[i], true
		}
	}
	return nil, false
}

// Operator decides whether a transformed value matches.
//
// Operator is one of the five public extension points (docs/RULES.md §4). It is
// frozen under semver at v1.0 because third parties implement it, so changes to
// this signature are a major design decision rather than a refactor.
//
// Implementations must be safe for concurrent use: one Operator instance is
// shared by every transaction evaluating the rule that holds it.
type Operator interface {
	// Name returns a stable identifier, used in compile reports, explain
	// output, and to reference the operator from declarative rule formats.
	Name() string

	// Eval reports whether value matches.
	Eval(ctx *EvalContext, value []byte) (Match, bool)

	// Literals returns the byte sequences that must be present for this
	// operator to have any chance of matching, and whether that requirement is
	// exact.
	//
	// When the bool is true the engine may skip evaluation entirely if none of
	// the literals appear in the input, which is what keeps benign traffic off
	// the evaluation path. When it is false the rule is unconditional and runs
	// on every request; the compiler reports those and `gwaf lint` budgets
	// them, so the cost is visible at build time rather than in a latency
	// graph. See docs/RULES.md §5.
	//
	// Returning true with literals that are not genuinely required is the one
	// way to make the engine silently miss matches. It is an assertion, and it
	// is the caller's to justify.
	Literals() ([]string, bool)

	// Cost returns the fuel charged per evaluation, excluding any per-byte
	// component the engine adds. It must not depend on the input.
	Cost() types.Fuel
}
