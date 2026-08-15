// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package attackgen replays a large real-attack corpus through gwaf.
//
// The corpus is built by generate.py from nuclei-templates (real CVE exploit
// requests), the OWASP CRS regression tests, and a curated seed set, then
// expanded across the placements and encodings a WAF has to survive. This runner
// replays it and reports detection per category, dumps the misses so they can be
// triaged and fixed, and asserts that the benign half never blocks -- because a
// detection number without a false-positive number is the one that gets a WAF
// switched off.
//
// Run:
//
//	python3 generate.py --n 50000 --out attacks.jsonl --benign benign.jsonl
//	ATTACK_CORPUS=attacks.jsonl BENIGN_CORPUS=benign.jsonl \
//	    go test -run TestAttackCorpus -v ./test/attackgen/
//
// It skips without the corpus files rather than failing, because they are
// generated, not committed.
package attackgen

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/core"
	"github.com/gsoultan/gwaf/types"
)

type acase struct {
	Cat     string         `json:"cat"`
	Place   string         `json:"place"`
	Enc     string         `json:"enc"`
	Src     string         `json:"src"`
	Method  string         `json:"method"`
	Path    string         `json:"path"`
	Arg     string         `json:"arg"`
	Body    string         `json:"body"`
	CT      string         `json:"ct"`
	Headers map[string]any `json:"headers"`
}

// headerString renders a header value that JSON may have decoded as a number or
// bool, because nuclei and CRS both carry non-string header values verbatim.
func headerString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%g", t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

// buildWAF returns gwaf's strongest shipped configuration: the default ruleset
// plus every opt-in rule, all reaching the body phase. This is what an embedder
// who wants maximum coverage turns on, so it is what the corpus measures.
func buildWAF(t testing.TB) *gwaf.WAF {
	t.Helper()
	w, err := gwaf.New(
		gwaf.WithOrigins("target.local"),
		gwaf.WithMinConfidence(types.Medium),
		gwaf.WithRuleset(core.WithBodyPhase(rules.Set{
			core.CRLFHeaderRule(1007), core.LoopbackSSRFRule(11003),
			core.WordPressHardeningRule(1011), core.SSRFParamRule(1016),
			core.SQLSinkRule(2011), core.PathSinkRule(1017),
		})),
		gwaf.WithRuleset(rules.Set{core.CommandSinkRule(4022)}),
	)
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	return w
}

func loadCorpus(path string) ([]acase, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []acase
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var c acase
		if err := json.Unmarshal(line, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, sc.Err()
}

// blocks drives one case through a fresh transaction and reports the verdict.
func blocks(w *gwaf.WAF, c acase) bool {
	tx := w.NewTransaction()
	defer tx.Close()
	method := c.Method
	if method == "" {
		method = "GET"
	}
	tx.SetRequestLine(method, c.Path, "HTTP/1.1")
	tx.SetRemoteAddr("192.0.2.1")
	for k, v := range c.Headers {
		tx.AddRequestHeader(k, headerString(v))
	}
	if c.CT != "" {
		tx.AddRequestHeader("Content-Type", c.CT)
	}
	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		return true
	}
	if c.Body != "" {
		tx.SetRequestBody([]byte(c.Body))
		if d := tx.ProcessRequestBody(); d.Blocked() {
			return true
		}
	}
	return false
}

func TestAttackCorpus(t *testing.T) {
	path := os.Getenv("ATTACK_CORPUS")
	if path == "" {
		t.Skip("ATTACK_CORPUS not set; run generate.py first")
	}
	cases, err := loadCorpus(path)
	if err != nil {
		t.Fatalf("load attacks: %v", err)
	}
	w := buildWAF(t)

	type stat struct{ hit, miss int }
	byCat := map[string]*stat{}
	bySrc := map[string]*stat{}
	getCat := func(k string) *stat {
		s := byCat[k]
		if s == nil {
			s = &stat{}
			byCat[k] = s
		}
		return s
	}
	getSrc := func(k string) *stat {
		s := bySrc[k]
		if s == nil {
			s = &stat{}
			bySrc[k] = s
		}
		return s
	}

	// Misses are written out for triage, grouped by (cat, place, enc) so a
	// family of misses is one line rather than thousands.
	missKey := map[string]int{}
	var missDump *bufio.Writer
	if out := os.Getenv("MISS_OUT"); out != "" {
		f, err := os.Create(out)
		if err == nil {
			defer f.Close()
			missDump = bufio.NewWriter(f)
			defer missDump.Flush()
		}
	}

	total, hit := 0, 0
	for _, c := range cases {
		total++
		b := blocks(w, c)
		cs, ss := getCat(c.Cat), getSrc(c.Src)
		if b {
			hit++
			cs.hit++
			ss.hit++
			continue
		}
		cs.miss++
		ss.miss++
		missKey[c.Cat+"|"+c.Place+"|"+c.Enc]++
		if missDump != nil {
			b, _ := json.Marshal(c)
			missDump.Write(b)
			missDump.WriteByte('\n')
		}
	}

	cats := make([]string, 0, len(byCat))
	for k := range byCat {
		cats = append(cats, k)
	}
	sort.Slice(cats, func(i, j int) bool { return byCat[cats[i]].miss > byCat[cats[j]].miss })

	t.Logf("=== detection by category (%d attacks) ===", total)
	t.Logf("%-16s %8s %8s %8s", "category", "hit", "miss", "rate")
	for _, k := range cats {
		s := byCat[k]
		t.Logf("%-16s %8d %8d %7.1f%%", k, s.hit, s.miss,
			100*float64(s.hit)/float64(s.hit+s.miss))
	}

	t.Logf("=== detection by source ===")
	srcs := make([]string, 0, len(bySrc))
	for k := range bySrc {
		srcs = append(srcs, k)
	}
	sort.Strings(srcs)
	for _, k := range srcs {
		s := bySrc[k]
		t.Logf("%-10s %8d/%-8d %6.1f%%", k, s.hit, s.hit+s.miss,
			100*float64(s.hit)/float64(s.hit+s.miss))
	}

	t.Logf("=== TOTAL detection: %d/%d (%.2f%%) ===", hit, total,
		100*float64(hit)/float64(total))

	// The biggest miss families, the actionable output.
	type mf struct {
		k string
		n int
	}
	var mfs []mf
	for k, n := range missKey {
		mfs = append(mfs, mf{k, n})
	}
	sort.Slice(mfs, func(i, j int) bool { return mfs[i].n > mfs[j].n })
	t.Logf("=== top miss families (cat|place|enc) ===")
	for i, m := range mfs {
		if i >= 25 {
			break
		}
		t.Logf("  %6d  %s", m.n, m.k)
	}
}

func TestBenignNoFalsePositives(t *testing.T) {
	path := os.Getenv("BENIGN_CORPUS")
	if path == "" {
		t.Skip("BENIGN_CORPUS not set")
	}
	cases, err := loadCorpus(path)
	if err != nil {
		t.Fatalf("load benign: %v", err)
	}
	w := buildWAF(t)
	var fps []string
	for _, c := range cases {
		if blocks(w, c) {
			fps = append(fps, fmt.Sprintf("[%s/%s] %s", c.Cat, c.Place,
				strings.TrimSpace(c.Path+c.Body)))
		}
	}
	t.Logf("benign corpus: %d requests, %d false positives", len(cases), len(fps))
	for _, f := range fps {
		t.Errorf("FALSE POSITIVE %s", f)
	}
}
