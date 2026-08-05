// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

//go:build race

package gwaf_test

// raceEnabled reports whether the race detector is active.
//
// Race instrumentation allocates shadow state per memory access, so the
// zero-allocation SLO is not measurable under -race. The concurrency tests
// still run there; only the allocation assertion is skipped.
const raceEnabled = true
