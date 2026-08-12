// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"io"
	"log/slog"
	"os"
	"testing"
)

// TestMain silences the default logger for the whole package.
//
// gwaf.New reports an inert rule once at construction, through slog.Default,
// which is exactly right in production and wrong in a benchmark: `go test`
// echoes it to stdout, and a benchmark run constructs thousands of WAFs. The
// recorded baseline came back with 193 log lines interleaved among 319
// benchmark results, against zero in the previous one — enough to make
// benchstat's job harder and the file unreadable.
//
// Silencing the *default* rather than passing a logger everywhere is what keeps
// this to one place. The two tests that assert on the diagnostic message supply
// their own logger and a buffer to read it back, so they are unaffected — and a
// test that cared about default-logger output would still be able to set one.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}
