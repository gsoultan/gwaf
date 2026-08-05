// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package seclang parses ModSecurity rule files and compiles them to gwaf rules.
//
// # This is a bridge, not the core
//
// SecLang is how a decade of operational knowledge is written down, and the
// Core Rule Set is the largest body of it. An embedder migrating from
// ModSecurity or Coraza has rules, exceptions, and tuning they cannot simply
// abandon, and telling them to rewrite it by hand is telling them not to
// migrate.
//
// So this package exists to get that work across, and then to be left behind.
// It compiles to `rules.Rule` — the same IR the Go frontend produces — and adds
// nothing the typed API cannot express. If something here needs IR the others
// cannot produce, that is an IR gap rather than a frontend feature
// (docs/RULES.md §1).
//
// It is a separate module for the fifth ownership test: a regex engine, and the
// literal extraction that keeps regex rules prefilterable, are cost an embedder
// should not inherit for writing "gwaf.New()".
//
// # SecLang is not a language gwaf wants to be good at
//
// CVE-2026-21876 broke the Core Rule Set across ModSecurity v2, v3, and Coraza
// simultaneously — a canonicalization mismatch in chained multipart rules, and
// a bug class endemic to a language where matching is a list of regexes over
// transformed strings. gwaf does not inherit that design, and this package is
// deliberately not a route back to it.
//
// What that means in practice: **a rule that cannot be translated faithfully is
// reported, never approximated.** A silently weakened rule is worse than an
// absent one, because the operator believes they still have it. Report names
// every directive, operator, transformation, and action that did not come
// across, with the file and line.
//
// # What comes across
//
// The directives that carry detection: SecRule, SecAction, SecMarker,
// SecDefaultAction, SecRuleRemoveById and its relatives. Chained rules become
// one gwaf rule per chain, since gwaf evaluates a rule against one value and a
// SecLang chain is a conjunction across values.
//
// Operators map where the semantics are identical: @rx, @contains,
// @containsWord, @streq, @beginsWith, @endsWith, @pm, @pmf, @within, @eq, @gt,
// @lt, @ge, @le, and the two ModSecurity shipped as native code — @detectSQLi
// and @detectXSS — which map onto gwaf's structural detectors and are the one
// place the translation is an *upgrade* rather than a port.
//
// What does not come across is as important, and is listed by Report: anything
// depending on cross-request state (@ipMatchFromFile against a live feed,
// SecAction with setvar on a persistent collection), on the filesystem at
// request time, or on Lua.
package seclang

import (
	"fmt"
	"strings"

	"github.com/gsoultan/gwaf/rules"
)

// Options control translation.
type Options struct {
	// Prefix is added to every imported rule ID, so imported rules cannot
	// collide with rules authored in Go or with gwaf's own core ruleset.
	//
	// Zero means no offset, which is what a caller replacing the core ruleset
	// wants. A caller running both should set it.
	Prefix uint32

	// DefaultConfidence is the tier assigned to imported rules.
	//
	// Deliberately required rather than defaulted to Certain. A SecLang rule
	// arrives with a paranoia level and a severity but with no measured
	// false-positive rate, and confidence in gwaf is a *measured* property
	// (docs/CONCEPT.md §8). Importing rules as Certain would assert something
	// nobody has checked; `gwaf calibrate` is how they earn a tier.
	DefaultConfidence Confidence

	// SkipUntranslatable keeps parsing when a rule cannot be translated.
	//
	// On by default in Parse, because a CRS release contains directives no
	// third-party engine implements and stopping at the first one imports
	// nothing. Everything skipped is in Report.
	SkipUntranslatable bool
}

// Confidence mirrors types.Confidence without importing it into the option
// surface, so a caller can write seclang.Medium without a second import.
type Confidence uint8

// Confidence tiers, matching types.Confidence.
const (
	Heuristic Confidence = iota + 1
	Low
	Medium
	High
	Certain
)

// Report describes what a ruleset contributed and what it could not.
//
// Returned even on success. The interesting case is a file that parsed cleanly
// and translated a third of its rules, and an operator who is not told that
// believes they migrated everything.
type Report struct {
	// Directives is how many directives were read.
	Directives int

	// Rules is how many gwaf rules were produced.
	Rules int

	// Chains is how many of those came from chained SecRules.
	Chains int

	// Prefiltered is how many produced a literal the automaton can key on.
	// The rest run against every value in their phase, which is a latency cost
	// the caller should see before deploying.
	Prefiltered int

	// Skipped lists what did not come across, with file and line.
	Skipped []Skip
}

// Skip is one thing that could not be translated.
type Skip struct {
	File   string
	Line   int
	RuleID uint32
	What   string
	Why    string
}

func (s Skip) String() string {
	loc := s.File
	if loc == "" {
		loc = "<input>"
	}
	if s.RuleID != 0 {
		return fmt.Sprintf("%s:%d: rule %d: %s — %s", loc, s.Line, s.RuleID, s.What, s.Why)
	}
	return fmt.Sprintf("%s:%d: %s — %s", loc, s.Line, s.What, s.Why)
}

// String renders the report for a build log.
func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d directives → %d rules (%d chained, %d prefiltered)",
		r.Directives, r.Rules, r.Chains, r.Prefiltered)
	if unconditional := r.Rules - r.Prefiltered; unconditional > 0 {
		fmt.Fprintf(&b, "\n%d rule(s) have no literal to key on and will run "+
			"against every value in their phase", unconditional)
	}
	if len(r.Skipped) > 0 {
		fmt.Fprintf(&b, "\n%d not translated:", len(r.Skipped))
		for _, s := range r.Skipped {
			fmt.Fprintf(&b, "\n  %s", s)
		}
	}
	return b.String()
}

// Parse reads SecLang source and compiles it to gwaf rules.
//
// The name is used in Report locations; pass the file path when there is one.
func Parse(name string, src []byte, opts Options) (rules.Set, Report, error) {
	if opts.DefaultConfidence == 0 {
		return nil, Report{}, ErrNoConfidence
	}
	opts.SkipUntranslatable = true

	directives, err := parse(name, src)
	if err != nil {
		return nil, Report{}, err
	}
	c := &compiler{opts: opts, file: name}
	set := c.run(directives)
	return set, c.report, nil
}

// ParseStrict is Parse without skipping: the first directive that cannot be
// translated faithfully is an error.
//
// For a caller who would rather fail a build than deploy a ruleset that is
// quietly smaller than the one they wrote.
func ParseStrict(name string, src []byte, opts Options) (rules.Set, Report, error) {
	if opts.DefaultConfidence == 0 {
		return nil, Report{}, ErrNoConfidence
	}
	opts.SkipUntranslatable = false

	directives, err := parse(name, src)
	if err != nil {
		return nil, Report{}, err
	}
	c := &compiler{opts: opts, file: name}
	set := c.run(directives)
	if len(c.report.Skipped) > 0 {
		return nil, c.report, fmt.Errorf("%w: %s", ErrUntranslatable, c.report.Skipped[0])
	}
	return set, c.report, nil
}
