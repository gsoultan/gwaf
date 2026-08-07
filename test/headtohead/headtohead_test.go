// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package headtohead measures gwaf and Coraza + CRS against the same corpus, on
// the same machine, in the same process.
//
// docs/COMPARISON.md §6 has promised this and admitted it was missing. Until it
// existed, every claim gwaf made about itself was self-reported, and the honest
// framing in that document was "a map of the design space rather than a
// scoreboard". This is the scoreboard.
//
// # What makes it a fair test
//
// Both engines see byte-identical requests from the same CRS test corpus, built
// once and replayed. Neither is given anything the other is not: gwaf runs its
// default ruleset, Coraza runs CRS, and both are asked the same question —
// did you block this?
//
// Detection is reported *with* the false-positive rate, always. A WAF that
// blocks everything scores 100% detection and is useless, so a detection number
// alone is not a result. That rule is why the benign corpus is replayed through
// both engines as well.
//
// # What it does not measure
//
// Not latency. Coraza and gwaf have different startup, parsing, and body
// handling, and a throughput number from a test harness that drives neither the
// way production would is a number nobody should quote. Latency belongs in
// docs/BENCHMARKS.md against gwaf alone, where the methodology is stated.
//
// # Running it
//
//	git clone --depth 1 https://github.com/coreruleset/coreruleset /tmp/crs
//	CRS_TESTS=/tmp/crs/tests/regression/tests \
//	CRS_RULES=/tmp/crs/rules make headtohead
package headtohead

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/test/conformance"
)

// engine is whatever can answer "did you block this request?".
type engine interface {
	Name() string
	Blocks(stage conformance.Stage) bool
}

// ---- gwaf ------------------------------------------------------------------

type gwafEngine struct{ waf *gwaf.WAF }

func (gwafEngine) Name() string { return "gwaf" }

func (e gwafEngine) Blocks(st conformance.Stage) bool {
	tx := e.waf.NewTransaction()
	defer tx.Close()

	in := st.Input
	method, uri, version := in.Method, in.URI, in.Version
	if method == "" {
		method = "GET"
	}
	if uri == "" {
		uri = "/"
	}
	if version == "" {
		version = "HTTP/1.1"
	}

	tx.SetRequestLine(method, uri, version)
	for k, v := range in.Headers {
		tx.AddRequestHeader(k, v)
	}
	d := tx.ProcessRequestHeaders()
	body := in.Data
	if body == "" {
		body = in.EncodedData
	}
	if !d.Blocked() && body != "" {
		tx.SetRequestBody([]byte(body))
		d = tx.ProcessRequestBody()
	}
	if !d.Blocked() {
		d = tx.Decision()
	}
	return d.Blocked()
}

// gwafCRSEngine is gwaf running CRS's rules through the seclang bridge.
type gwafCRSEngine struct{ gwafEngine }

func (gwafCRSEngine) Name() string { return "gwaf+crs" }

// newGwafWithCRS builds a gwaf loaded with CRS rules instead of its own.
//
// WithRuleset accumulates onto the default set, so this is gwaf's rules *plus*
// whatever the bridge translated — which is the configuration an adopter
// migrating from CRS would actually run, rather than a synthetic CRS-only one.
func newGwafWithCRS(dir string) (*gwaf.WAF, conformance.Coverage, error) {
	set, reports, err := conformance.LoadCRS(dir)
	if err != nil {
		return nil, conformance.Coverage{}, err
	}
	w, err := gwaf.New(gwaf.WithRuleset(set))
	if err != nil {
		return nil, conformance.Coverage{}, err
	}
	return w, conformance.Summarise(reports), nil
}

// ---- Coraza + CRS ----------------------------------------------------------

type corazaEngine struct{ waf coraza.WAF }

func (corazaEngine) Name() string { return "coraza+crs" }

func (e corazaEngine) Blocks(st conformance.Stage) bool {
	tx := e.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	in := st.Input
	method, uri, version := in.Method, in.URI, in.Version
	if method == "" {
		method = "GET"
	}
	if uri == "" {
		uri = "/"
	}
	if version == "" {
		version = "HTTP/1.1"
	}

	tx.ProcessURI(uri, method, version)
	for k, v := range in.Headers {
		tx.AddRequestHeader(k, v)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return true
	}
	body := in.Data
	if body == "" {
		body = in.EncodedData
	}
	if body != "" {
		if _, _, err := tx.WriteRequestBody([]byte(body)); err != nil {
			return false
		}
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		return false
	}
	return it != nil
}

// newCoraza builds a Coraza WAF with the CRS rules at dir.
//
// The setup directive is included because CRS will not load without it, and the
// anomaly thresholds are left at their defaults: tuning one engine and not the
// other would be the easiest way to produce a flattering number.
func newCoraza(dir string) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecRequestBodyAccess On",
		"SecResponseBodyAccess Off",
	}, "\n"))

	// CRS's own setup file, not a hand-written substitute.
	//
	// An earlier version of this harness set the anomaly thresholds with a few
	// SecAction directives and measured a 36% false-positive rate on ordinary
	// traffic. That number was the harness, not Coraza: without crs-setup the
	// paranoia and scoring variables are not initialised the way CRS expects,
	// and publishing it would have been exactly the dishonest comparison this
	// file exists to avoid. If the setup file is missing, the run fails rather
	// than falling back to something approximate.
	setup := filepath.Join(filepath.Dir(dir), "crs-setup.conf.example")
	if _, err := os.Stat(setup); err != nil {
		return nil, fmt.Errorf("crs-setup.conf.example not found next to %s: %w", dir, err)
	}
	cfg = cfg.WithDirectivesFromFile(setup)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no .conf files in %s", dir)
	}
	// Sorted, because CRS rule files depend on load order.
	sort.Strings(names)
	for _, n := range names {
		cfg = cfg.WithDirectivesFromFile(filepath.Join(dir, n))
	}
	return coraza.NewWAF(cfg)
}

// ---- the comparison --------------------------------------------------------

type score struct {
	detected, attacks int
	blocked, benign   int // blocked benign = false positives
}

func (s score) detectionRate() float64 {
	if s.attacks == 0 {
		return 0
	}
	return 100 * float64(s.detected) / float64(s.attacks)
}

func (s score) fpRate() float64 {
	if s.benign == 0 {
		return 0
	}
	return 100 * float64(s.blocked) / float64(s.benign)
}

// TestHeadToHead replays the CRS corpus through both engines and reports both
// numbers for each.
func TestHeadToHead(t *testing.T) {
	testDir := os.Getenv("CRS_TESTS")
	rulesDir := os.Getenv("CRS_RULES")
	if testDir == "" || rulesDir == "" {
		t.Skip("CRS_TESTS and CRS_RULES must both be set; see the package doc")
	}

	files, err := conformance.LoadTests(testDir)
	if err != nil {
		t.Fatalf("load tests: %v", err)
	}

	g, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	cz, err := newCoraza(rulesDir)
	if err != nil {
		t.Fatalf("coraza: %v", err)
	}

	// The third engine answers the obvious question: does gwaf running *CRS's
	// own rules* close the gap? It is built from the same .conf files Coraza
	// loads, through the seclang bridge.
	gc, bridgeCov, err := newGwafWithCRS(rulesDir)
	if err != nil {
		t.Fatalf("gwaf+crs: %v", err)
	}
	t.Logf("gwaf+crs %s", bridgeCov)

	engines := []engine{gwafEngine{waf: g}, gwafCRSEngine{gwafEngine{waf: gc}}, corazaEngine{waf: cz}}
	scores := make([]score, len(engines))

	// One pass over the corpus, both engines per stage, so neither sees a
	// different machine state than the other.
	for _, f := range files {
		if f.Meta.Enabled != nil && !*f.Meta.Enabled {
			continue
		}
		for _, tc := range f.Tests {
			for _, st := range tc.Stages {
				// Only stages this harness can send faithfully. Raw requests
				// need a socket, and counting them would measure the harness.
				if st.Input.RawRequest != "" || st.Input.EncodedRequest != "" {
					continue
				}
				attack := len(st.Output.Log.ExpectIDs) > 0 || st.Output.Status == 403
				benign := !attack && st.Output.Status == 200
				if !attack && !benign {
					continue // asserts neither; not a scoreable stage
				}

				for i, e := range engines {
					blocked := e.Blocks(st)
					if attack {
						scores[i].attacks++
						if blocked {
							scores[i].detected++
						}
					} else {
						scores[i].benign++
						if blocked {
							scores[i].blocked++
						}
					}
				}
			}
		}
	}

	t.Log("head-to-head on the OWASP CRS regression corpus, same process, same machine")
	t.Logf("%-12s %-22s %s", "engine", "detection", "false positives")
	for i, e := range engines {
		s := scores[i]
		t.Logf("%-12s %4d/%-4d (%5.1f%%)   %4d/%-4d (%5.1f%%)",
			e.Name(), s.detected, s.attacks, s.detectionRate(),
			s.blocked, s.benign, s.fpRate())
	}
	t.Log("detection is never reported without the false-positive rate beside it: " +
		"a WAF that blocks everything scores 100% and is useless")

	if scores[0].attacks == 0 {
		t.Error("no attack stages were scored; the corpus did not load")
	}
}

// ---- the second half: false positives on ordinary traffic -------------------

// benignRequest is one line of gwaf's calibration corpus.
type benignRequest struct {
	Name    string            `json:"name"`
	Method  string            `json:"method"`
	Target  string            `json:"target"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// TestFalsePositivesOnOrdinaryTraffic replays gwaf's 10,000-request benign
// corpus through both engines.
//
// This is the half the CRS corpus cannot measure: it carries about five stages
// that assert a clean pass, and a false-positive rate computed from five samples
// is not a rate. It is also the half that decides deployability — a WAF is
// removed for blocking customers, not for missing an attack nobody attempted.
//
// # Whose home turf this is
//
// gwaf's, and that is stated rather than hidden. Every rule gwaf ships was
// calibrated against this corpus and fails the build if it exceeds its tier's
// ceiling, so gwaf scoring well here is close to tautological. Coraza has never
// seen it.
//
// The symmetry is the point. The CRS corpus is CRS's home turf — its tests were
// written for its rules, one per rule — and Coraza wins there decisively. This
// corpus is gwaf's. Reporting only one would be choosing the flattering half,
// so both run and both are labelled.
//
// What is genuinely comparable is the *shape* of each engine's errors: which
// kinds of ordinary request each one mistakes for an attack.
func TestFalsePositivesOnOrdinaryTraffic(t *testing.T) {
	rulesDir := os.Getenv("CRS_RULES")
	if rulesDir == "" {
		t.Skip("CRS_RULES must be set; see the package doc")
	}
	path := os.Getenv("GWAF_BENIGN")
	if path == "" {
		path = "../../testdata/corpus/benign.jsonl"
	}

	f, err := os.Open(path)
	if err != nil {
		t.Skipf("benign corpus not readable at %s: %v", path, err)
	}
	defer f.Close()

	g, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	cz, err := newCoraza(rulesDir)
	if err != nil {
		t.Fatalf("coraza: %v", err)
	}
	engines := []engine{gwafEngine{waf: g}, corazaEngine{waf: cz}}

	var total int
	fps := make([]int, len(engines))
	examples := make([][]string, len(engines))

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var r benignRequest
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		st := conformance.Stage{Input: conformance.Input{
			Method:  r.Method,
			URI:     r.Target,
			Headers: withClientHeaders(r.Headers),
			Data:    r.Body,
		}}
		total++
		for i, e := range engines {
			if e.Blocks(st) {
				fps[i]++
				if len(examples[i]) < 5 {
					examples[i] = append(examples[i], r.Name)
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	if total == 0 {
		t.Fatal("corpus was empty")
	}

	t.Logf("false positives on %d ordinary requests (gwaf's calibration corpus)", total)
	for i, e := range engines {
		t.Logf("%-12s %5d  (%.2f%%)  e.g. %s",
			e.Name(), fps[i], 100*float64(fps[i])/float64(total),
			strings.Join(examples[i], ", "))
	}
	t.Log("READ THE CAVEATS BEFORE QUOTING EITHER NUMBER:")
	t.Log("  1. This corpus is gwaf's home turf. Every gwaf rule is calibrated " +
		"against it and fails the build above its tier's ceiling, so gwaf " +
		"scoring well here is close to tautological. Coraza has never seen it. " +
		"The CRS corpus in TestHeadToHead is CRS's home turf, and Coraza wins " +
		"there decisively. Both are reported for that reason.")
	t.Log("  2. Coraza runs UNTUNED CRS at paranoia level 1, loaded from " +
		"crs-setup.conf.example with no per-application exclusion rules. Every " +
		"real CRS deployment adds those, and tuning is the normal answer to " +
		"exactly this. A tuned deployment would score far better.")
	t.Log("  3. The traffic is API-shaped -- JSON bodies, JWTs, gRPC-Web, " +
		"protobuf. That is where signature engines are documented to struggle, " +
		"and it is the gap gwaf's schema tier targets, so the corpus plays to " +
		"a structural difference rather than to an implementation detail.")
}

// withClientHeaders fills in the headers every real client sends.
//
// Without this the comparison measures the harness rather than the engines. The
// corpus records carry only the headers gwaf cares about, because gwaf does no
// protocol enforcement — so a replayed request often had no Host, no
// User-Agent, and no Accept. CRS enforces all three (920280 "Request Missing a
// Host Header", 911013, 913013, 920013), so it flagged 87% of ordinary traffic
// and the number said nothing about Coraza's precision.
//
// A request with no Host header is malformed under HTTP/1.1, and CRS is right
// to say so. Supplying what a browser actually sends is what makes the
// remaining differences differences between the engines.
func withClientHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h)+4)
	for k, v := range h {
		out[k] = v
	}
	defaults := map[string]string{
		"Host":            "localhost",
		"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate",
		"Connection":      "keep-alive",
	}
	for k, v := range defaults {
		if _, ok := out[k]; !ok {
			out[k] = v
		}
	}
	return out
}
