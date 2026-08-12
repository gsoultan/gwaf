// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package headtohead

// gwaf against Coraza + CRS on real CVE exploit traffic, over a real socket.
//
// The other file in this package compares the two on the CRS regression suite,
// which is CRS's home turf. This one uses projectdiscovery/nuclei-templates: the
// industry's maintained corpus of exploit requests for real CVEs, written by
// people with no stake in either engine, and replayed through both as ordinary
// net/http middleware in front of the same origin. That is the integration an
// adopter deploys, not a library call.
//
// Reproducing it:
//
//	git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates /tmp/nuclei-templates
//	python3 extract_corpus.py /tmp/nuclei-templates/http > /tmp/corpus.json
//	NUCLEI_CORPUS=/tmp/corpus.json go test -run TestNuclei -v ./test/headtohead/
//
// It skips without the corpus rather than failing, because the corpus is a
// 94 MB checkout and vendoring it would put someone else's CVE database in this
// repository.
//
// # Reading the numbers
//
// Detection rate alone is not a result. This reports it beside the false
// positive rate on ordinary traffic, because an engine that blocks everything
// scores 100% on any corpus of attacks, and beside latency, because an engine
// nobody can afford to run protects nothing. All three come from the same run.
//
// Roughly 47% of the corpus carries no payload at all — nuclei templates are
// multi-step and the first step is usually a version probe
// ("GET /wp-content/plugins/x/readme.txt"). No per-request WAF can block those,
// and counting them as misses understates both engines by about twenty points
// while saying nothing about either. They are reported separately.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	corazahttp "github.com/corazawaf/coraza/v3/http"
	"github.com/gsoultan/gwaf"
	gwafmw "github.com/gsoultan/gwaf/middleware"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/core"
	"github.com/gsoultan/gwaf/ruleset/profiles"
	"github.com/gsoultan/gwaf/types"
)

type nucleiCase struct {
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	ID       string            `json:"id"`
	Class    string            `json:"class"`
	Severity string            `json:"severity"`
	Payload  bool              `json:"payload"`
}

// nucleiBenignRequest is ordinary traffic, carried inline because it is small
// and because the false-positive half of the comparison must not depend on an
// external checkout that might not be there.
type nucleiBenignRequest struct {
	method, path, ctype, body, why string
}

var nucleiBenign = []nucleiBenignRequest{
	{"GET", "/", "", "", "home page"},
	{"GET", "/?s=how+to+select+a+theme", "", "", "search with a SQL word"},
	{"GET", "/?s=union+square+cafe", "", "", "search with another"},
	{"GET", "/wp-admin/theme-editor.php?file=functions.php&theme=twentytwentyfour", "", "", "the theme editor takes a file path by design"},
	{"GET", "/api/products?search=t-shirt+%22slim+fit%22&order=-price", "", "", "quoted product search"},
	{"POST", "/wp-login.php", "application/x-www-form-urlencoded", "log=admin&pwd=P%40ssw0rd%21&wp-submit=Log+In", "login"},
	{"POST", "/wp-admin/admin-ajax.php", "application/x-www-form-urlencoded",
		"action=update_option&option_name=x&value=a%3A2%3A%7Bs%3A4%3A%22name%22%3Bs%3A5%3A%22Alice%22%3B%7D",
		"the options API stores serialized PHP"},
	{"POST", "/wp-json/wp/v2/posts/1", "application/json",
		`{"content":"<!-- wp:paragraph --><p>Hello <strong>world</strong></p><!-- /wp:paragraph -->"}`,
		"block editor markup"},
	{"POST", "/wp-json/wp/v2/posts/2", "application/json",
		`{"title":"Understanding SQL injection","content":"<pre><code>SELECT * FROM users WHERE id = 1 OR 1=1--</code></pre>"}`,
		"a security blog post quoting a payload"},
	{"POST", "/wp-comments-post.php", "application/x-www-form-urlencoded",
		"comment=In+PHP+you+write+%3C%3Fphp+echo+%24name%3B+%3F%3E&author=Dev&url=https%3A%2F%2Fdev.example.com",
		"a comment quoting PHP, and the commenter's own site"},
	{"POST", "/api/webhooks", "application/json",
		`{"url":"https://hooks.example.com/t/abc","events":["order.created"]}`,
		"webhook registration, which is an off-origin URL by design"},
	{"POST", "/api/v1/reports", "application/json",
		`{"name":"Q1","query":"select revenue where region = 'EU'"}`, "a report DSL"},
}

// nucleiOrigin answers 200 for everything and reflects nothing, so a request
// reaching it means the WAF let it through — which is what is being counted.
func nucleiOrigin() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Powered-By", "PHP/8.2.10")
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.7.1"></head><body>ok</body></html>`)
	})
}

func loadNucleiCorpus(t *testing.T) []nucleiCase {
	t.Helper()
	path := os.Getenv("NUCLEI_CORPUS")
	if path == "" {
		t.Skip("NUCLEI_CORPUS not set; see the package comment for how to build it")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("NUCLEI_CORPUS unreadable: %v", err)
	}
	var doc struct {
		Cases []nucleiCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("corpus is empty")
	}
	return doc.Cases
}

type engineResult struct {
	name    string
	blocked int
	total   int
	elapsed time.Duration
	byClass map[string][2]int
	fps     []string

	// misses are the requests this engine let through, kept so the gap can be
	// read rather than guessed at.
	//
	// A per-class score says RCE is 287/378 and stops there, which is enough to
	// know a gap exists and not enough to close one. Every detection improvement
	// after that point is a guess about which 91 requests those are -- and the
	// corpus is right here, so guessing is a choice. GWAF_DUMP_MISSES=<class>
	// prints them, or "all" for every class.
	misses map[string][]nucleiCase
}

// dumpMissesFor reports which classes the caller asked to see missed requests
// for. Empty means none, which is the default: 322 requests is not something to
// print on every run.
func dumpMissesFor() map[string]bool {
	spec := os.Getenv("GWAF_DUMP_MISSES")
	if spec == "" {
		return nil
	}
	out := map[string]bool{}
	for _, c := range strings.Split(spec, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out[c] = true
		}
	}
	return out
}

// nucleiHost is the hostname every replayed request is addressed to.
//
// It is a constant rather than a literal in two places because it is also the
// origin declared to gwaf: the rules that ask "does this point somewhere else"
// need a "here", and here is whatever the replay claims to be. Changing one
// without the other silently disarms those rules.
const nucleiHost = "target.local"

// bodyPreview renders a body for the miss report, bounded so one templated
// upload does not fill the log.
func bodyPreview(b string) string {
	if b == "" {
		return ""
	}
	b = strings.ReplaceAll(strings.ReplaceAll(b, "\n", `\n`), "\r", `\r`)
	const max = 160
	if len(b) > max {
		b = b[:max] + "..."
	}
	return "  body=" + b
}

func replayNuclei(srv *httptest.Server, cases []nucleiCase) engineResult {
	client := &http.Client{Timeout: 30 * time.Second}
	r := engineResult{byClass: map[string][2]int{}, misses: map[string][]nucleiCase{}}
	start := time.Now()
	for _, c := range cases {
		method := c.Method
		if method == "" {
			method = "GET"
		}
		var body io.Reader
		if c.Body != "" {
			body = strings.NewReader(c.Body)
		}
		req, err := http.NewRequest(method, srv.URL+c.Path, body)
		if err != nil {
			continue // a target the template built that is not a valid URL
		}
		req.Host = nucleiHost
		setClientHeaders(req)
		for k, v := range c.Headers {
			req.Header.Set(k, v)
		}
		if c.Body != "" && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		r.total++
		n := r.byClass[c.Class]
		n[1]++
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusServiceUnavailable {
			r.blocked++
			n[0]++
		} else {
			r.misses[c.Class] = append(r.misses[c.Class], c)
		}
		r.byClass[c.Class] = n
	}
	r.elapsed = time.Since(start)
	return r
}

func replayBenign(srv *httptest.Server) []string {
	client := &http.Client{Timeout: 30 * time.Second}
	var fps []string
	for _, b := range nucleiBenign {
		var body io.Reader
		if b.body != "" {
			body = strings.NewReader(b.body)
		}
		req, err := http.NewRequest(b.method, srv.URL+b.path, body)
		if err != nil {
			continue
		}
		req.Host = nucleiHost
		setClientHeaders(req)
		if b.ctype != "" {
			req.Header.Set("Content-Type", b.ctype)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusServiceUnavailable {
			fps = append(fps, b.why)
		}
	}
	return fps
}

// TestNucleiHeadToHead is the comparison. It reports and does not assert a
// detection rate: the number moves with the upstream corpus, and a test that
// fails when somebody else adds templates is a test nobody keeps.
//
// The false-positive count is asserted, because that one is ours.
func TestNucleiHeadToHead(t *testing.T) {
	all := loadNucleiCorpus(t)

	var payload []nucleiCase
	for _, c := range all {
		if c.Payload {
			payload = append(payload, c)
		}
	}
	t.Logf("corpus: %d requests, %d payload-bearing (%d are version probes carrying nothing to detect)",
		len(all), len(payload), len(all)-len(payload))

	// WithOrigins is what both replays make true: every request is sent with
	// Host: target.local, so that is the hostname this application answers on.
	//
	// Without it the off-origin redirect rule and SSRFParamRule compile, lint
	// clean, and match nothing -- they have no origin to call a destination
	// foreign to. This harness omitted it from the day the origins requirement
	// landed, which meant the published redirect and SSRF numbers were measured
	// against two rules that could not fire, and the `tuned` config below was
	// opting into one of them. gwaf.New said so on stderr both times; the
	// harness was not reading its own output.
	plain, err := gwaf.New(gwaf.WithOrigins(nucleiHost))
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	tuned, err := gwaf.New(
		gwaf.WithOrigins(nucleiHost),
		gwaf.WithExceptions(profiles.WordPress()...),
		// WithBodyPhase, because an opt-in rule does not go through Default()
		// and so is compiled exactly as written -- at the header phase, seeing
		// the query string only. Without it SSRFParamRule inspects everything
		// except the JSON bodies that webhook and import endpoints are made of,
		// which is both a coverage hole and a flattering false-positive count:
		// the two benign cases below that carry a foreign URL carry it in a
		// body, so the unmirrored rule never saw them.
		gwaf.WithRuleset(core.WithBodyPhase(
			rules.Set{
				core.CRLFHeaderRule(1007),
				core.SSRFParamRule(1016),
				core.SQLSinkRule(2011),
				core.PathSinkRule(1017),
			})),
		// Name-anchored, so it needs no body-phase counterpart: the operator
		// reads siblings from the argument collection, which the body phase
		// fills for JSON and form fields alike.
		gwaf.WithRuleset(rules.Set{core.CommandSinkRule(4022)}),
		// The fetch half fires on webhook registration, because registering a
		// webhook *is* handing the server a foreign URL. That is the measured
		// reason the rule is opt-in rather than core, and it does not go away
		// by declaring origins -- hooks.example.com is genuinely somewhere
		// else. An adopter who runs both a webhook endpoint and this rule scopes
		// the one route, which is narrower than turning the rule off, so that is
		// what is modelled here. Both IDs: the counterpart carries its own.
		gwaf.WithExceptions(
			rules.Exception{
				RuleID: 1016, Path: "/api/webhooks",
				Target: types.TargetArgs, Key: "url",
				Note: "webhook registration takes a third-party URL by design",
			},
			rules.Exception{
				RuleID: 1916, Path: "/api/webhooks",
				Target: types.TargetArgs, Key: "url",
				Note: "the body-phase counterpart of 1016, which is where a JSON registration arrives",
			},
		),
	)
	if err != nil {
		t.Fatalf("gwaf.New(tuned): %v", err)
	}

	gs := httptest.NewServer(gwafmw.HTTP(plain)(nucleiOrigin()))
	defer gs.Close()
	ts := httptest.NewServer(gwafmw.HTTP(tuned)(nucleiOrigin()))
	defer ts.Close()
	rulesDir := os.Getenv("CRS_RULES")
	if rulesDir == "" {
		t.Skip("CRS_RULES must be set so Coraza runs the real ruleset; see the package doc")
	}
	cwaf, err := newCoraza(rulesDir)
	if err != nil {
		t.Fatalf("newCoraza: %v", err)
	}
	cs := httptest.NewServer(corazahttp.WrapHandler(cwaf, nucleiOrigin()))
	defer cs.Close()

	engines := []struct {
		name string
		srv  *httptest.Server
	}{
		{"gwaf", gs},
		{"gwaf+profile+optin", ts},
		{"coraza+crs", cs},
	}

	results := make([]engineResult, 0, len(engines))
	for _, e := range engines {
		r := replayNuclei(e.srv, payload)
		r.name = e.name
		r.fps = replayBenign(e.srv)
		results = append(results, r)
	}

	t.Log("=== detection on payload-bearing CVE exploits ===")
	for _, r := range results {
		t.Logf("  %-20s %4d/%4d (%5.1f%%)  %6.0fus/req",
			r.name, r.blocked, r.total, 100*float64(r.blocked)/float64(r.total),
			float64(r.elapsed.Microseconds())/float64(max(r.total, 1)))
	}

	classes := map[string]bool{}
	for _, c := range payload {
		classes[c.Class] = true
	}
	var ck []string
	for k := range classes {
		ck = append(ck, k)
	}
	sort.Strings(ck)
	t.Log("=== by vulnerability class ===")
	for _, cl := range ck {
		line := fmt.Sprintf("  %-16s", cl)
		for _, r := range results {
			n := r.byClass[cl]
			if n[1] == 0 {
				continue
			}
			line += fmt.Sprintf(" %s %3d/%-4d", r.name, n[0], n[1])
		}
		t.Log(line)
	}

	// Which requests were missed, for the classes the caller asked about.
	//
	// Off by default because 322 requests is not a thing to print every run, and
	// on by name because closing a gap starts with reading it. The template ID
	// is included so the miss can be traced back to the upstream template and
	// the payload seen in full.
	if want := dumpMissesFor(); len(want) > 0 {
		t.Log("=== missed requests (GWAF_DUMP_MISSES) ===")
		for _, r := range results {
			for _, cl := range ck {
				if !want[cl] && !want["all"] {
					continue
				}
				ms := r.misses[cl]
				if len(ms) == 0 {
					continue
				}
				t.Logf("  --- %s / %s: %d missed ---", r.name, cl, len(ms))
				for _, m := range ms {
					method := m.Method
					if method == "" {
						method = "GET"
					}
					t.Logf("      [%s] %s %s%s", m.ID, method, m.Path, bodyPreview(m.Body))
				}
			}
		}
	}

	t.Log("=== false positives on ordinary traffic ===")
	for _, r := range results {
		t.Logf("  %-20s %d/%d", r.name, len(r.fps), len(nucleiBenign))
		for _, f := range r.fps {
			t.Logf("        %s", f)
		}
	}

	// The tuned configuration is the one an adopter deploys, and it is the one
	// held to zero. A profile exists precisely so that ordinary traffic for a
	// known platform passes; if it does not, the profile is wrong.
	for _, r := range results {
		if r.name == "gwaf+profile+optin" && len(r.fps) > 0 {
			t.Errorf("tuned gwaf blocked %d/%d ordinary requests: %v",
				len(r.fps), len(nucleiBenign), r.fps)
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// setClientHeaders gives a request the protocol hygiene a real browser sends.
//
// It matters more than it looks: CRS scores a missing Host header at 5, which is
// its entire default anomaly threshold, so a harness that omits it measures
// every request as blocked for a reason unrelated to its payload. The first
// version of this comparison did exactly that and reported a flawless 100%
// detection rate next to a 100% false-positive rate.
func setClientHeaders(req *http.Request) {
	for k, v := range withClientHeaders(nil) {
		if k == "Host" {
			continue // set via req.Host, which is where net/http reads it
		}
		req.Header.Set(k, v)
	}
}
