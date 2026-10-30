// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package core

import (
	"testing"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// lastKeySegment must keep '/' as part of a marker name. Splitting on it reduced
// "py/object" and "rb/object" to "object", which is in no marker table, so a
// jsonpickle or Ruby gadget was never matched at all. The nesting separators are
// '.', '[' and ']'.
func TestLastKeySegmentKeepsMarkerSlash(t *testing.T) {
	cases := map[string]string{
		"py/object":          "py/object",
		"rb/object":          "rb/object",
		"payload.py/object":  "py/object",
		"items[0].rb/object": "rb/object",
		"__class":            "__class",
		"a.b.c.@class":       "@class",
		"PY/OBJECT":          "py/object", // lowercased
	}
	for in, want := range cases {
		if got := lastKeySegment(in); got != want {
			t.Errorf("lastKeySegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsDottedClassName(t *testing.T) {
	dotted := []string{
		"subprocess.Popen", "os.system", "builtins.exec",
		"Gem::Requirement", "ActiveSupport::Deprecation",
		`guzzlehttp\psr7\fnstream`,
		"System.Diagnostics.Process, System", // comma-stripped to a dotted name
	}
	for _, v := range dotted {
		if !isDottedClassName([]byte(v)) {
			t.Errorf("isDottedClassName(%q) = false, want true", v)
		}
	}
	plain := []string{
		"true", "42", "invoice", "primary", "highlight",
		"v1.2.3",    // version: a segment starts with a digit
		"photo",     // single segment
		"image/png", // '/' is not a class separator
		"a:b",       // a lone ':' is not '::'
		"", "ab",    // too short
	}
	for _, v := range plain {
		if isDottedClassName([]byte(v)) {
			t.Errorf("isDottedClassName(%q) = true, want false", v)
		}
	}
}

// The companion operator reads the class from the sibling value, so with no
// siblings it cannot convict, and it covers only the two dotted markers.
func TestTypeMarkerDottedOpScopedToMarkers(t *testing.T) {
	o := typeMarkerDottedOp{}
	ctx := &rules.EvalContext{Target: types.Target{Kind: types.TargetArgNames}}
	if _, ok := o.Eval(ctx, []byte("py/object")); ok {
		t.Error("matched py/object with no sibling value")
	}
	// With the sibling value present, it fires.
	ctx.Siblings = rules.Args{
		Names:  [][]byte{[]byte("py/object")},
		Values: [][]byte{[]byte("subprocess.Popen")},
	}
	if _, ok := o.Eval(ctx, []byte("py/object")); !ok {
		t.Error("did not match py/object whose sibling value is a dotted class")
	}
	// A non-marker name is ignored even with a class-looking sibling.
	if _, ok := o.Eval(ctx, []byte("widget")); ok {
		t.Error("matched a non-marker argument name")
	}
	lits, required := o.Literals()
	if !required || len(lits) != 2 {
		t.Errorf("Literals() = %v, %v; want the two marker names, required", lits, required)
	}
}
