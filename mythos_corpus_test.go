// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"fmt"
	"sort"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/core"
)

// The Mythos corpus: adversarial traffic gwaf had never seen.
//
// The shipped evasion corpus reports 334/334 and 0/176, and it is honest — but
// every payload in it is one gwaf was fixed against, so it measures regression
// and not resistance. This corpus is the other measurement: payloads produced by
// adversarial rounds against the *shipped* engine, kept whether or not they were
// ever closed.
//
// That is what makes it a statistic rather than a scoreboard. A case marked open
// is a bypass that still works, and it is recorded here with the reason it was
// left rather than deleted, because a corpus that only holds fixed payloads
// always reports 100% and tells you nothing.
//
// Recall alone is never a passing metric (CLAUDE.md §Testing), so the benign
// half runs beside it and the false-positive rate is reported next to detection
// on every run.

// placement says where a payload is carried, because the same bytes are a
// different test in a query argument and in a body.
type placement int

const (
	inArg       placement = iota // a query/body argument value
	inCmdArg                     // an argument named "cmd" -- a declared shell sink
	inBody                       // a raw body, with a content type
	inRawArg                     // an argument whose *name* carries the payload
	inPathArg                    // an argument named "filepath" -- a declared path sink
	inURLArg                     // an argument named "url" -- a declared fetch sink
	inUserAgent                  // a request header
)

// mythCase is one payload and what gwaf is expected to make of it.
type mythCase struct {
	class string
	name  string
	arg   string
	body  []byte
	ct    string
	where placement

	// attack says a real backend would execute this. false marks the benign
	// half: traffic that must pass, and whose blocking is a false positive.
	attack bool

	// open records a bypass that is known and not closed, with the reason. It
	// does not change the arithmetic -- an open case still counts as a miss --
	// it documents that the miss is a decision rather than a surprise.
	open string
}

func mythWAF(t *testing.T) *gwaf.WAF {
	t.Helper()
	return newWAF(t,
		gwaf.WithOrigins("target.local"),
		gwaf.WithRuleset(core.WithBodyPhase(rules.Set{
			core.CRLFHeaderRule(1007), core.LoopbackSSRFRule(11003),
			core.WordPressHardeningRule(1011), core.SSRFParamRule(1016),
			core.SQLSinkRule(2011), core.PathSinkRule(1017),
		})),
		gwaf.WithRuleset(rules.Set{core.CommandSinkRule(4022)}))
}

func mythUTF16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, b := range []byte(s) {
		out = append(out, b, 0x00)
	}
	return out
}

func mythUTF16BE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, b := range []byte(s) {
		out = append(out, 0x00, b)
	}
	return out
}

// runMyth drives one case and reports whether gwaf blocked it.
func runMyth(t *testing.T, w *gwaf.WAF, c mythCase) bool {
	t.Helper()
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("POST", "/x", "HTTP/1.1")
	tx.SetRemoteAddr("192.0.2.1")

	switch c.where {
	case inBody:
		tx.AddRequestHeader("Content-Type", c.ct)
		tx.SetRequestBody(c.body)
		return tx.ProcessRequestHeaders().Blocked() || tx.ProcessRequestBody().Blocked()
	case inUserAgent:
		tx.AddRequestHeader("User-Agent", c.arg)
		return tx.ProcessRequestHeaders().Blocked()
	case inCmdArg:
		tx.AddArgument("cmd", c.arg)
	case inPathArg:
		tx.AddArgument("filepath", c.arg)
	case inURLArg:
		tx.AddArgument("url", c.arg)
	case inRawArg:
		tx.AddArgument(c.arg, "1")
	default:
		tx.AddArgument("p", c.arg)
	}
	return tx.ProcessRequestHeaders().Blocked()
}

// TestMythosCorpus reports detection and false-positive rates per attack class.
//
// It never fails on an open case: those are counted, named, and printed, because
// the number this test exists to produce is the honest one. It fails when a case
// that is *not* marked open regresses, which is what keeps a closed bypass shut.
func TestMythosCorpus(t *testing.T) {
	w := mythWAF(t)

	type stat struct{ tp, fn, tn, fp int }
	byClass := map[string]*stat{}
	get := func(c string) *stat {
		s, ok := byClass[c]
		if !ok {
			s = &stat{}
			byClass[c] = s
		}
		return s
	}

	var regressions, openMisses []string

	for _, c := range mythosCorpus {
		blocked := runMyth(t, w, c)
		s := get(c.class)
		switch {
		case c.attack && blocked:
			s.tp++
		case c.attack && !blocked:
			s.fn++
			if c.open == "" {
				regressions = append(regressions,
					fmt.Sprintf("REGRESSION [%s] %s: %s", c.class, c.name, c.arg))
			} else {
				openMisses = append(openMisses,
					fmt.Sprintf("open [%s] %s -- %s", c.class, c.name, c.open))
			}
		case !c.attack && blocked:
			s.fp++
			if c.open == "" {
				regressions = append(regressions,
					fmt.Sprintf("FALSE POSITIVE [%s] %s: %s", c.class, c.name, c.arg))
			} else {
				openMisses = append(openMisses,
					fmt.Sprintf("open-fp [%s] %s -- %s", c.class, c.name, c.open))
			}
		default:
			s.tn++
		}
	}

	classes := make([]string, 0, len(byClass))
	for k := range byClass {
		classes = append(classes, k)
	}
	sort.Strings(classes)

	var tp, fn, tn, fp int
	t.Logf("%-22s %8s %8s %8s", "class", "detect", "caught", "fp")
	for _, c := range classes {
		s := byClass[c]
		tp, fn, tn, fp = tp+s.tp, fn+s.fn, tn+s.tn, fp+s.fp
		det := "n/a"
		if s.tp+s.fn > 0 {
			det = fmt.Sprintf("%.1f%%", 100*float64(s.tp)/float64(s.tp+s.fn))
		}
		fprate := "n/a"
		if s.tn+s.fp > 0 {
			fprate = fmt.Sprintf("%.1f%%", 100*float64(s.fp)/float64(s.tn+s.fp))
		}
		t.Logf("%-22s %8s %5d/%-3d %8s", c, det, s.tp, s.tp+s.fn, fprate)
	}

	t.Logf("")
	t.Logf("MYTHOS detection: %d/%d (%.1f%%)  false positives: %d/%d (%.2f%%)",
		tp, tp+fn, 100*float64(tp)/float64(tp+fn),
		fp, fp+tn, 100*float64(fp)/float64(fp+tn))

	for _, m := range openMisses {
		t.Logf("  %s", m)
	}
	for _, r := range regressions {
		t.Error(r)
	}
}
