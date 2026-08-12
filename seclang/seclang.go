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
	"errors"
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

	// MaxSourceBytes and MaxRules bound what one parse may cost.
	//
	// # Why a parser needs these at all
	//
	// This package had no bounds and no stated trust boundary, and those two
	// gaps are the same gap. A test comment called it "a build-time tool", but
	// Parse is exported from a module anyone may import, and the first adopter
	// stores user-authored SecLang in a rule database — which is a parse of
	// somebody else's bytes at runtime, in a shared process.
	//
	// Measured, the amplification is what makes that matter:
	//
	//	real CRS, 27 files      711 KB source   →  250 rules,  55 MB,  37 ms
	//	one 1 MB @rx pattern      1 MB source   →    1 rule,  264 MB,  59 ms
	//	one 10 MB @pm line       10 MB source   →    1 rule,  423 MB, 109 ms
	//
	// A megabyte of hostile SecLang costs a quarter-gigabyte. RE2 already
	// refuses the classic program-size bombs — `(a{1000}){1000}` and a
	// two-thousand-deep alternation are both rejected during compilation — so
	// what is left is bulk, and bulk is what a ceiling is for.
	//
	// # Why these numbers
	//
	// The Core Rule Set is the largest body of SecLang in existence and it is
	// 711 KB producing 250 rules. The defaults are 32 MiB and 100,000 rules:
	// roughly 45× and 400× the largest real ruleset, so no honest input has
	// ever come near them, and a pathological one stops before it costs a
	// gigabyte.
	//
	// Set either to a negative value for no limit, which is the right choice
	// for a build step compiling rules you wrote yourself. Zero means the
	// default, so a caller who never heard of these still gets them — safe by
	// construction rather than safe if you read the docs (CLAUDE.md §2b.8).
	MaxSourceBytes int
	MaxRules       int

	// MaxPatternBytes bounds one operator argument, which is the thing that
	// actually amplifies. A limit on total source does not catch it: a megabyte
	// of input is nothing, and a megabyte in a single @rx is a quarter of a
	// gigabyte of compiled program.
	//
	// The largest operator argument in the Core Rule Set is 8,504 bytes. The
	// default is 64 KiB — about seven times that — and a pattern over it is
	// reported as untranslatable rather than compiled, so the ruleset still
	// loads and the operator is told which rule was dropped and why.
	//
	// Negative for no limit; zero means the default.
	MaxPatternBytes int

	// DataFiles resolves the phrase lists @pmFromFile and @pmf refer to, so
	// their rules can be imported with the phrases inlined.
	//
	// The converter never opens a file itself. Reading from disk is an
	// environment capability, and a library that helps itself to one the caller
	// did not grant is a library that cannot be embedded anywhere strict
	// (CLAUDE.md §1, the environment test). The caller decides what "lfi-os-
	// files.data" resolves to — a directory, an embed.FS, or nothing.
	//
	// Nil means @pmFromFile stays untranslatable and is reported as such. That
	// is the safe default: eighteen CRS rules depend on it, including the LFI
	// and RCE phrase lists, and importing them empty would be worse than not
	// importing them.
	DataFiles func(name string) ([]byte, error)
}

// Source is one named SecLang input.
//
// Files are parsed separately and compiled together, because SecLang is stateful
// across them — SecDefaultAction set in one applies to the next, and
// SecRuleRemoveById routinely appears after the include that defined its target
// — while a skip has to name the file it actually came from. Concatenating the
// bytes first gets the statefulness right and the attribution wrong.
type Source struct {
	// Name is used in Report locations; pass the file path when there is one.
	Name string
	// Data is the SecLang source.
	Data []byte
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
	return ParseSources([]Source{{Name: name, Data: src}}, opts)
}

// ParseSources compiles several SecLang files as one ruleset.
//
// Use this rather than concatenating the files yourself: the directives are
// compiled in the order given, so state carries across them exactly as
// ModSecurity would, and every skip still reports the file and line it came
// from. A migration is read by whoever has to tune it, and "rule 942100 in one
// of these twenty-seven files" is not a location.
func ParseSources(srcs []Source, opts Options) (rules.Set, Report, error) {
	if opts.DefaultConfidence == 0 {
		return nil, Report{}, ErrNoConfidence
	}
	opts.SkipUntranslatable = true

	if err := checkSize(srcs, opts); err != nil {
		return nil, Report{}, err
	}
	directives, err := parseAll(srcs)
	if err != nil {
		return nil, Report{}, err
	}
	c := &compiler{opts: opts}
	set := c.run(directives)
	if err := checkRules(len(set), opts); err != nil {
		return nil, Report{}, err
	}
	return set, c.report, nil
}

// Default bounds for one parse. See Options.MaxSourceBytes for why these
// numbers: the largest real ruleset in existence is 711 KB and 250 rules.
const (
	defaultMaxSourceBytes = 32 << 20
	defaultMaxRules       = 100_000
	defaultMaxPattern     = 64 << 10
)

// patternLimit resolves MaxPatternBytes, where zero means the default and a
// negative value means none.
func (o Options) patternLimit() int {
	if o.MaxPatternBytes == 0 {
		return defaultMaxPattern
	}
	return o.MaxPatternBytes
}

// ErrTooLarge reports a parse that exceeded Options.MaxSourceBytes or MaxRules.
//
// A refusal rather than a truncation, for the same reason the engine refuses an
// oversize body: half a ruleset is not a ruleset, and importing a prefix of
// somebody's rules silently drops the ones at the end.
var ErrTooLarge = errors.New("seclang: input exceeds the configured bounds")

// checkSize enforces MaxSourceBytes across every source in one parse.
func checkSize(srcs []Source, opts Options) error {
	limit := opts.MaxSourceBytes
	if limit == 0 {
		limit = defaultMaxSourceBytes
	}
	if limit < 0 {
		return nil
	}
	total := 0
	for _, s := range srcs {
		total += len(s.Data)
		if total > limit {
			return fmt.Errorf("%w: %d bytes of source against a %d byte limit; "+
				"set Options.MaxSourceBytes to raise it, or a negative value for none",
				ErrTooLarge, total, limit)
		}
	}
	return nil
}

// checkRules enforces MaxRules on the compiled set.
func checkRules(n int, opts Options) error {
	limit := opts.MaxRules
	if limit == 0 {
		limit = defaultMaxRules
	}
	if limit < 0 {
		return nil
	}
	if n > limit {
		return fmt.Errorf("%w: %d rules against a %d rule limit; "+
			"set Options.MaxRules to raise it, or a negative value for none",
			ErrTooLarge, n, limit)
	}
	return nil
}

func parseAll(srcs []Source) ([]directive, error) {
	var out []directive
	for _, s := range srcs {
		ds, err := parse(s.Name, s.Data)
		if err != nil {
			return nil, err
		}
		out = append(out, ds...)
	}
	return out, nil
}

// ParseStrict is Parse without skipping: the first directive that cannot be
// translated faithfully is an error.
//
// For a caller who would rather fail a build than deploy a ruleset that is
// quietly smaller than the one they wrote.
func ParseStrict(name string, src []byte, opts Options) (rules.Set, Report, error) {
	return ParseSourcesStrict([]Source{{Name: name, Data: src}}, opts)
}

// ParseSourcesStrict is ParseSources without skipping.
func ParseSourcesStrict(srcs []Source, opts Options) (rules.Set, Report, error) {
	if opts.DefaultConfidence == 0 {
		return nil, Report{}, ErrNoConfidence
	}
	opts.SkipUntranslatable = false

	if err := checkSize(srcs, opts); err != nil {
		return nil, Report{}, err
	}
	directives, err := parseAll(srcs)
	if err != nil {
		return nil, Report{}, err
	}
	c := &compiler{opts: opts}
	set := c.run(directives)
	if err := checkRules(len(set), opts); err != nil {
		return nil, Report{}, err
	}
	if len(c.report.Skipped) > 0 {
		return nil, c.report, fmt.Errorf("%w: %s", ErrUntranslatable, c.report.Skipped[0])
	}
	return set, c.report, nil
}
