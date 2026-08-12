// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package seclang_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf/seclang"
)

// The bounds on one parse, and the amplification that makes them necessary.
//
// This package had none, and no stated trust boundary either — which are the
// same gap. A test comment called it "a build-time tool", but Parse is exported
// from a module anyone may import, and the first adopter stores user-authored
// SecLang in a rule database. That is a parse of somebody else's bytes at
// runtime, in a shared process.
//
// The measurement is what decided the shape of the fix. A ceiling on total
// source would not have helped: the cost is driven by a single operator
// argument, so a megabyte of input is nothing and a megabyte in one @rx is a
// quarter of a gigabyte of compiled program.
//
//	real CRS, 27 files    711 KB   →  250 rules,  55 MB
//	one 1 MB @rx pattern    1 MB   →    0 rules,  12 MB   (was 264 MB)
//	one 10 MB @pm line     10 MB   →    0 rules, 118 MB   (was 423 MB)
//
// RE2 already refuses the classic program-size bombs, which is why they are
// here as controls rather than as findings: `(a{1000}){1000}` and a
// two-thousand-deep alternation are both rejected during compilation. What was
// left was bulk, and bulk needs a ceiling rather than a cleverer engine.
func TestParseIsBounded(t *testing.T) {
	parse := func(t *testing.T, src string) (int, int64) {
		t.Helper()
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		set, _, _ := seclang.Parse("x.conf", []byte(src),
			seclang.Options{DefaultConfidence: seclang.Medium})
		runtime.ReadMemStats(&after)
		return len(set), int64(after.TotalAlloc-before.TotalAlloc) >> 20
	}

	t.Run("oversize pattern is refused, not compiled", func(t *testing.T) {
		n, mb := parse(t, `SecRule ARGS "@rx `+strings.Repeat("a", 1<<20)+`" "id:1,phase:2,deny"`)
		if n != 0 {
			t.Errorf("compiled %d rules from a 1 MiB pattern", n)
		}
		if mb > 64 {
			t.Errorf("allocated %d MB for a pattern that is refused; the bound is "+
				"supposed to apply before compilation", mb)
		}
	})

	t.Run("oversize phrase list is refused", func(t *testing.T) {
		n, mb := parse(t, `SecRule ARGS "@pm `+strings.Repeat("x y ", 2500000)+`" "id:1,phase:2,deny"`)
		if n != 0 {
			t.Errorf("compiled %d rules from a 10 MiB phrase list", n)
		}
		if mb > 256 {
			t.Errorf("allocated %d MB for a phrase list that is refused", mb)
		}
	})

	// RE2 handles these; they are controls, so a change of engine cannot quietly
	// reintroduce a class this package is supposed to be immune to.
	t.Run("RE2 refuses program-size bombs", func(t *testing.T) {
		for _, pat := range []string{
			`(a{1000}){1000}`,
			strings.Repeat("(a|b", 2000) + strings.Repeat(")", 2000),
		} {
			if n, _ := parse(t, `SecRule ARGS "@rx `+pat+`" "id:1,phase:2,deny"`); n != 0 {
				t.Errorf("compiled a rule from a program-size bomb: %.40s", pat)
			}
		}
	})

	// The bound must never touch an honest ruleset. CRS's longest operator
	// argument is 8,504 bytes against a 64 KiB default.
	t.Run("a realistic pattern still compiles", func(t *testing.T) {
		pat := strings.Repeat("(?:union|select|insert)|", 300) + "drop"
		n, _ := parse(t, `SecRule ARGS "@rx `+pat+`" "id:1,phase:2,deny"`)
		if n != 1 {
			t.Errorf("a %d byte pattern compiled to %d rules, want 1: the bound is "+
				"too tight for real rulesets", len(pat), n)
		}
	})

	t.Run("a negative limit means none", func(t *testing.T) {
		set, _, _ := seclang.Parse("x.conf",
			[]byte(`SecRule ARGS "@rx `+strings.Repeat("a", 1<<20)+`" "id:1,phase:2,deny"`),
			seclang.Options{DefaultConfidence: seclang.Medium, MaxPatternBytes: -1})
		if len(set) != 1 {
			t.Errorf("MaxPatternBytes=-1 compiled %d rules, want 1: a build step "+
				"compiling its own rules must be able to opt out", len(set))
		}
	})

	t.Run("rule count is bounded", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < 200; i++ {
			b.WriteString("SecRule ARGS \"@rx a\" \"id:100000,phase:2,deny\"\n")
		}
		_, _, err := seclang.Parse("x.conf", []byte(b.String()),
			seclang.Options{DefaultConfidence: seclang.Medium, MaxRules: 10})
		if err == nil {
			t.Error("200 rules against a limit of 10 did not error")
		}
	})

	t.Run("source size is bounded", func(t *testing.T) {
		_, _, err := seclang.Parse("x.conf",
			[]byte(`SecRule ARGS "@rx a" "id:1,phase:2,deny"`),
			seclang.Options{DefaultConfidence: seclang.Medium, MaxSourceBytes: 8})
		if err == nil {
			t.Error("a source over MaxSourceBytes did not error")
		}
	})
}
