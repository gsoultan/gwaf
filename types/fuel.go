// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package types

// Fuel is an abstract unit of work.
//
// Work is metered in fuel rather than wall-clock time. Consulting the clock per
// rule costs more than many rules do, and a wall-clock budget is
// nondeterministic: the same request can pass on an idle machine and fail on a
// loaded one, which makes a budget violation impossible to reproduce in a test.
//
// Fuel is a static per-operation cost decremented from a counter, which gives
// three properties a security control needs:
//
//   - Deterministic. The same input always consumes the same fuel.
//   - Reproducible. A budget violation reproduces in a unit test.
//   - Provably bounded. Maximum fuel per request bounds the work an attacker can
//     induce, independent of input.
//
// See docs/CONCEPT.md §2.
//
// # Why this lives in types rather than internal
//
// Because `Operator.Cost() Fuel` is part of a public extension point, and an
// interface method returning an unexported type is an interface nobody outside
// the module can implement. That was true and unnoticed until somebody tried:
//
//	myOp does not implement rules.Operator (missing method Cost)
//	use of internal package .../internal/budget not allowed
//
// The first-party detectors never hit it, because they sit under the same import
// path as internal/. A vendor at their own module path cannot, and vendors
// implementing these five interfaces is the whole reason they exist
// (docs/RULES.md §4). test/extension is a module at a foreign path that
// implements all five, so this cannot regress quietly.
//
// The metering machinery — Meter, and the ceiling arithmetic — stays in
// internal/budget. A third party needs to *declare* a cost, never to run the
// accounting.
type Fuel int64

// Operation costs, calibrated against the benchmark suite rather than guessed:
// bench/ asserts that measured wall-clock stays correlated with fuel spent, so a
// drift between the two fails CI rather than silently making the budget
// meaningless.
//
// They are exported so a third-party Operator can price itself in the same units
// the engine uses. A custom operator returning a number picked out of the air
// would make the DoS bound arithmetic wrong in a way nothing would catch.
const (
	// CostPerByteScanned is charged for each input byte the prefilter reads.
	// One unit is roughly one byte scanned, which is what anchors the scale.
	CostPerByteScanned Fuel = 1

	// CostPerByteTransformed is charged per byte of materialised transform
	// output. Transforms allocate and copy, so they cost more than a scan.
	CostPerByteTransformed Fuel = 2

	// CostRuleDispatch is the fixed overhead of evaluating one candidate rule,
	// before its operator runs.
	CostRuleDispatch Fuel = 8

	// CostTargetResolve is the fixed overhead of resolving one target
	// collection for a transaction.
	CostTargetResolve Fuel = 16

	// CostLiteralMatch is a literal comparison against an already-scanned
	// value. A reasonable unit for a third-party operator to multiply.
	CostLiteralMatch Fuel = 4

	// CostRegexPerByte is charged per input byte for a regex evaluation. Regex
	// is the fallback tier and is priced to reflect that.
	CostRegexPerByte Fuel = 10

	// CostCustomOperator is the floor charged for a third-party operator, which
	// the engine cannot cost statically.
	CostCustomOperator Fuel = 64
)

// DefaultFuelLimit is the per-transaction ceiling applied when an embedder does
// not choose one.
//
// It is derived from the default input limits rather than picked, because the
// two have to be coherent: a request the input limits admit must not then be
// rejected for running out of fuel, or the deployment would reject traffic it
// was configured to accept.
//
// The derivation, with the defaults in gwaf.DefaultLimits:
//
//	inspected bytes   ≈ MaxBodySize (1 MiB) + arguments + headers ≈ 1.5 MiB
//	transform chains  ≈ 6 distinct chains across a realistic ruleset
//	cost per byte     = 1 (scan) + 2 (transform) = 3
//
//	1.5 MiB × 6 × 3 ≈ 28 M
//
// 32,000,000 leaves headroom above that while still bounding the work an
// attacker can induce to a fixed multiple of a legitimate maximum-size request.
// Deployments with tighter input limits should lower this in proportion; the
// bound is only as useful as it is tight.
const DefaultFuelLimit Fuel = 32_000_000
