// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package conformance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/seclang"
	"gopkg.in/yaml.v3"
)

// LoadTests reads every .yaml under dir, recursively.
//
// The CRS test corpus is a tree of directories named after rule families, and a
// runner that only read one level would silently cover a fraction of it while
// reporting a percentage — so this walks.
func LoadTests(dir string) (map[string]File, error) {
	out := map[string]File{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := strings.ToLower(filepath.Ext(path)); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var f File
		if err := yaml.Unmarshal(b, &f); err != nil {
			// A malformed file is an error rather than a skip: silently dropping
			// it would shrink the suite while the pass rate stayed flattering.
			return fmt.Errorf("parse %s: %w", path, err)
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			rel = path
		}
		out[rel] = f
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LoadCRS parses every .conf under dir into a ruleset, preserving CRS rule IDs.
//
// This is what makes ModeRuleID meaningful: the IDs in the ruleset are the same
// IDs the tests name, because seclang carries them across rather than
// renumbering. It also returns the parse report, because what did *not*
// translate is as much a result as what did — a bridge that quietly dropped a
// third of the corpus would otherwise post an excellent pass rate.
func LoadCRS(dir string) (rules.Set, []seclang.Report, error) {
	var set rules.Set
	var reports []seclang.Report

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	// Sorted by name, which is how CRS orders its files and therefore how rule
	// IDs are expected to appear.
	var srcs []seclang.Source
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", path, err)
		}
		srcs = append(srcs, seclang.Source{Name: e.Name(), Data: b})
	}

	// One ParseSources over every file, not Parse per file.
	//
	// SecLang is stateful across files: SecDefaultAction set in one applies to
	// the next, and SecRuleRemoveById routinely appears after the include that
	// defined the rule it disables. Parsing each alone silently loses both, so
	// the ruleset under test was not the ruleset CRS describes.
	//
	// DataFiles matters just as much. Without it every @pmFromFile rule is
	// skipped, and this loader was dropping seventeen of them -- including 930120,
	// which carries the LFI filename list. The suite was measuring a conversion
	// materially smaller than the one gwaf-seclang produces, and reporting the
	// difference as gwaf failing CRS's tests.
	//
	// DefaultConfidence is required rather than defaulted, because a SecLang rule
	// arrives with a paranoia level and no measured false-positive rate. High is
	// the honest import tier: "believed precise, not yet calibrated against this
	// deployment's traffic".
	set, rep, err := seclang.ParseSources(srcs, seclang.Options{
		DefaultConfidence: seclang.High,
		DataFiles: func(name string) ([]byte, error) {
			return os.ReadFile(filepath.Join(dir, name))
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", dir, err)
	}
	reports = append(reports, rep)
	return set, reports, nil
}

// Coverage summarises what a set of seclang reports translated.
//
// Printed beside a pass rate so the two are read together: "98% of the tests
// pass" means something different when the bridge only translated half the
// rules, and that difference is exactly what an adopter needs to know.
type Coverage struct {
	Directives  int
	Rules       int
	Prefiltered int
	Skipped     int
}

// Summarise folds the per-file reports into one.
func Summarise(reports []seclang.Report) Coverage {
	var c Coverage
	for _, r := range reports {
		c.Directives += r.Directives
		c.Rules += r.Rules
		c.Prefiltered += r.Prefiltered
		c.Skipped += len(r.Skipped)
	}
	return c
}

// String renders the coverage line.
func (c Coverage) String() string {
	return fmt.Sprintf("seclang bridge: %d directives -> %d rules (%d prefiltered, %d not translated)",
		c.Directives, c.Rules, c.Prefiltered, c.Skipped)
}

// Exceptions gathers the tuning the reports translated.
//
// Returned separately rather than applied by LoadCRS, because an exception is a
// hole in a firewall and the caller decides which holes their deployment has.
// The suite applies them because it is measuring conformance with the ruleset
// CRS actually runs, tuning included.
func Exceptions(reports []seclang.Report) []rules.Exception {
	var out []rules.Exception
	for _, r := range reports {
		out = append(out, r.Exceptions...)
	}
	return out
}
