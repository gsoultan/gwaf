// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package openapi_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gwaf/schema/openapi"
)

// TestYAMLExpansionBomb is a control rather than a finding.
//
// "Billion laughs" was a YAML attack before it was an XML one, and this package
// parses YAML supplied by whoever wrote the spec. gopkg.in/yaml.v3 refuses the
// expansion outright — a 396-byte document that would expand to roughly 387
// million nodes returns an error in no measurable time and no measurable
// memory.
//
// It is pinned because that protection lives in a dependency. A version bump, a
// swap to a different YAML library, or a switch to a hand-rolled parser could
// remove it silently, and nothing else in this repository would notice.
func TestYAMLExpansionBomb(t *testing.T) {
	// Nine levels of nine-fold aliasing: 9^9 ≈ 387 million nodes if expanded.
	var b strings.Builder
	b.WriteString("a0: &a0 [x,x,x,x,x,x,x,x,x]\n")
	for i := 1; i < 9; i++ {
		fmt.Fprintf(&b, "a%d: &a%d [", i, i)
		for j := 0; j < 9; j++ {
			if j > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, "*a%d", i-1)
		}
		b.WriteString("]\n")
	}
	doc := b.String()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	_, _, err := openapi.Parse([]byte(doc), openapi.Options{})
	el := time.Since(start)
	runtime.ReadMemStats(&after)

	mb := int64(after.TotalAlloc-before.TotalAlloc) >> 20
	t.Logf("%d byte bomb -> %s, alloc=%d MB, err=%v", len(doc), el.Round(time.Millisecond), mb, err != nil)
	if mb > 128 {
		t.Errorf("a %d byte document allocated %d MB: the alias expansion is unbounded", len(doc), mb)
	}
}
