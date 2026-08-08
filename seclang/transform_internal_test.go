// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package seclang

import (
	"fmt"
	"strings"
	"testing"
)

// TestEveryEmittableTransformCanBeRendered is the invariant the two tables used
// to break: if the compiler will put a transform in a rule, Generate must have a
// name to write it with.
//
// Before this, t:jsDecode compiled to transform.EscapeDecode and generate.go had
// no case for "escape_decode", so `report` counted CRS rule 932210 as translated
// and `convert` failed on it — the whole Core Rule Set converted to an error.
// The failure was invisible to every test in the tree because they all fed
// Generate a rule set that happened not to use it.
func TestEveryEmittableTransformCanBeRendered(t *testing.T) {
	for _, e := range secTransforms {
		name, ok := transformConst(e.tf.Name())
		if !ok {
			t.Errorf("transform %q (t:%s) has no exported name for Generate",
				e.tf.Name(), e.tokens[0])
			continue
		}
		if name != e.goName {
			t.Errorf("transform %q renders as %q, table says %q", e.tf.Name(), name, e.goName)
		}
	}
}

// TestEverySpellingSurvivesConversion walks the table through the real path:
// parse a rule using each SecLang spelling, then render it. A spelling the
// parser accepts and the generator cannot write is a conversion that reports
// success and produces nothing.
func TestEverySpellingSurvivesConversion(t *testing.T) {
	for _, e := range secTransforms {
		for _, tok := range e.tokens {
			t.Run(tok, func(t *testing.T) {
				src := fmt.Sprintf(
					"SecRule ARGS \"@rx attack\" \"id:1,phase:2,deny,t:%s\"\n", tok)

				set, rep, err := Parse("t.conf", []byte(src), Options{DefaultConfidence: High})
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				if len(set) != 1 {
					t.Fatalf("t:%s did not translate: %s", tok, rep)
				}

				out, err := Generate("x", set, rep)
				if err != nil {
					t.Fatalf("generate: %v", err)
				}
				if want := "transform." + e.goName; !strings.Contains(string(out), want) {
					t.Errorf("generated source for t:%s is missing %q", tok, want)
				}
			})
		}
	}
}

// TestTransformSpellingsAreUnambiguous guards the table itself: one spelling
// selecting two transforms would make the conversion depend on table order.
func TestTransformSpellingsAreUnambiguous(t *testing.T) {
	seen := map[string]string{}
	for _, e := range secTransforms {
		for _, tok := range e.tokens {
			if prev, dup := seen[tok]; dup {
				t.Errorf("t:%s maps to both %s and %s", tok, prev, e.goName)
			}
			seen[tok] = e.goName
		}
		if isDroppedTransform(e.tokens[0]) {
			t.Errorf("t:%s is both emitted and dropped", e.tokens[0])
		}
	}
}
