// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package seclang

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op/rx"
)

// @rx is implemented by rules/op/rx, in the root module.
//
// It used to live here, on the reasoning that an embedder writing gwaf.New()
// should not link a regex engine because somebody else is migrating from CRS.
// That reasoning was right about the cost and wrong about where to put it: Go
// links per package, so a package of its own gives the same guarantee without
// making an embedder who wants one regex rule take a SecLang parser as well.
// gateon was the case that showed it — a first-party adopter with a corpus of
// @rx rules and no use for the parser.
//
// The type alias keeps compile.go and generate.go, which switch on the operator
// type to regenerate a pattern, working against the moved implementation.

type regexOperator = rx.Operator

func newRegexOperator(pattern string, negated bool) (rules.Operator, error) {
	if negated {
		return rx.NewNegated(pattern)
	}
	return rx.New(pattern)
}

// Regex returns an @rx operator for a pattern, for code the converter emits.
//
// Exported so a generated ruleset can reconstruct the operator it was compiled
// from. That dependency is honest rather than incidental: running a Core Rule
// Set means running its regexes, and a regex needs an engine.
//
// RE2, so the imported patterns are linear-time and ReDoS-impossible. A pattern
// using backreferences or lookaround does not compile, which is the property
// that makes importing a stranger's regexes defensible at all.
func Regex(pattern string) (rules.Operator, error) { return rx.New(pattern) }

// MustRegex is Regex for generated code, where the pattern was already
// validated by the converter that emitted it.
func MustRegex(pattern string) rules.Operator {
	o, err := Regex(pattern)
	if err != nil {
		panic("seclang: generated pattern does not compile: " + err.Error())
	}
	return o
}
