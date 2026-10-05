// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"iter"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/types"
)

// probeRuleID is the one rule each population case compiles.
const probeRuleID types.RuleID = 9_100_001

// exchange is a whole request and response, driven through every phase.
type exchange struct {
	method, target, proto string
	remote                string
	headers               [][2]string
	contentType           string
	body                  string
	status                int
	respHeaders           [][2]string
	respBody              string
}

// probeResolver supplies one embedder value, for the RESOLVED case.
type probeResolver struct{ value string }

func (probeResolver) Name() string { return "probe" }

func (r probeResolver) Resolve() iter.Seq2[string, []byte] {
	return func(yield func(string, []byte) bool) {
		if r.value != "" {
			yield("v", []byte(r.value))
		}
	}
}

// fired drives x through every phase and reports whether the probe rule
// refused it. Engine-level refusals (framing, limits) carry no rule ID and so
// cannot be mistaken for the probe firing.
func fired(t *testing.T, w *gwaf.WAF, x exchange, resolved string) bool {
	t.Helper()
	tx := w.NewTransaction()
	defer tx.Close()

	tx.AddResolver(probeResolver{value: resolved})
	method, proto, remote := x.method, x.proto, x.remote
	if method == "" {
		method = "GET"
	}
	if proto == "" {
		proto = "HTTP/1.1"
	}
	if remote == "" {
		remote = "192.0.2.1"
	}
	tx.SetRequestLine(method, x.target, proto)
	tx.SetRemoteAddr(remote)
	for _, h := range x.headers {
		tx.AddRequestHeader(h[0], h[1])
	}
	if x.contentType != "" {
		tx.AddRequestHeader("Content-Type", x.contentType)
	}
	steps := []func() gwaf.Decision{
		tx.ProcessRequestHeaders,
		func() gwaf.Decision {
			if x.body != "" {
				tx.SetRequestBody([]byte(x.body))
			}
			return tx.ProcessRequestBody()
		},
		func() gwaf.Decision {
			status := x.status
			if status == 0 {
				status = 200
			}
			tx.SetResponseStatus(status)
			for _, h := range x.respHeaders {
				tx.AddResponseHeader(h[0], h[1])
			}
			return tx.ProcessResponseHeaders()
		},
		func() gwaf.Decision {
			tx.WriteResponseBody([]byte(x.respBody))
			return tx.ProcessResponseBody()
		},
	}
	for _, step := range steps {
		if d := step(); d.Blocked() {
			return d.RuleID() == probeRuleID
		}
	}
	return false
}

// populationCase is one target kind: a rule on it, an exchange that carries
// the probe in that collection, and one that carries it only somewhere else.
//
// The miss is what keeps a case honest. One that merely omits the probe would
// pass for a kind wired to the wrong collection -- ARGS_GET reading body
// arguments too, a named cookie selecting every cookie.
type populationCase struct {
	target   types.Target
	op       rules.Operator
	hit      exchange
	miss     exchange
	resolved [2]string // hit, miss values for the RESOLVED probe
}

const formType = "application/x-www-form-urlencoded"

func populationCases() map[types.TargetKind][]populationCase {
	probe := op.Contains("gwafprobe")
	cookie := func(v string) [][2]string { return [][2]string{{"Cookie", v}} }
	multipart := "--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"gwafprobe.php\"\r\n" +
		"Content-Type: text/plain\r\n\r\nx\r\n--B--\r\n"
	return map[types.TargetKind][]populationCase{
		types.TargetRequestMethod: {{target: types.Target{Kind: types.TargetRequestMethod}, op: op.Equals("DELETE"),
			hit: exchange{method: "DELETE", target: "/"}, miss: exchange{target: "/?m=DELETE"}}},
		types.TargetRequestURI: {{target: types.Target{Kind: types.TargetRequestURI}, op: probe,
			hit: exchange{target: "/x?gwafprobe"}, miss: exchange{target: "/x", headers: [][2]string{{"X-P", "gwafprobe"}}}}},
		types.TargetRequestPath: {{target: types.Target{Kind: types.TargetRequestPath}, op: probe,
			hit: exchange{target: "/gwafprobe"}, miss: exchange{target: "/x?q=gwafprobe"}}},
		types.TargetRequestProtocol: {{target: types.Target{Kind: types.TargetRequestProtocol}, op: op.Equals("HTTP/1.0"),
			hit: exchange{target: "/", proto: "HTTP/1.0"}, miss: exchange{target: "/?p=HTTP/1.0"}}},
		types.TargetRequestLine: {{target: types.Target{Kind: types.TargetRequestLine}, op: op.Contains("GET /gwafprobe HTTP"),
			hit: exchange{target: "/gwafprobe"}, miss: exchange{target: "/x", headers: [][2]string{{"X-P", "GET /gwafprobe HTTP"}}}}},
		types.TargetRequestHeaders: {{target: types.Target{Kind: types.TargetRequestHeaders, Name: "x-p"}, op: probe,
			hit:  exchange{target: "/", headers: [][2]string{{"X-P", "gwafprobe"}}},
			miss: exchange{target: "/", headers: [][2]string{{"X-Other", "gwafprobe"}}}}},
		types.TargetRequestHeaderNames: {{target: types.Target{Kind: types.TargetRequestHeaderNames}, op: probe,
			hit:  exchange{target: "/", headers: [][2]string{{"X-Gwafprobe", "1"}}},
			miss: exchange{target: "/", headers: [][2]string{{"X-Other", "gwafprobe"}}}}},
		types.TargetArgs: {{target: types.Target{Kind: types.TargetArgs, Name: "q"}, op: probe,
			hit: exchange{target: "/?q=gwafprobe"}, miss: exchange{target: "/?r=gwafprobe"}}},
		types.TargetArgNames: {{target: types.Target{Kind: types.TargetArgNames}, op: probe,
			hit: exchange{target: "/?gwafprobe=1"}, miss: exchange{target: "/?a=gwafprobe"}}},
		types.TargetArgsGet: {
			{target: types.Target{Kind: types.TargetArgsGet}, op: probe,
				hit:  exchange{target: "/?q=gwafprobe"},
				miss: exchange{method: "POST", target: "/", contentType: formType, body: "q=gwafprobe"}},
			{target: types.Target{Kind: types.TargetArgsGet, Name: "q"}, op: probe,
				hit: exchange{target: "/?a=1&q=gwafprobe"}, miss: exchange{target: "/?r=gwafprobe"}},
		},
		types.TargetArgsPost: {
			{target: types.Target{Kind: types.TargetArgsPost}, op: probe,
				hit:  exchange{method: "POST", target: "/", contentType: formType, body: "q=gwafprobe"},
				miss: exchange{method: "POST", target: "/?q=gwafprobe", contentType: formType, body: "q=1"}},
			{target: types.Target{Kind: types.TargetArgsPost, Name: "q"}, op: probe,
				hit:  exchange{method: "POST", target: "/", contentType: "application/json", body: `{"q":"gwafprobe"}`},
				miss: exchange{method: "POST", target: "/", contentType: "application/json", body: `{"r":"gwafprobe"}`}},
		},
		types.TargetRequestBody: {{target: types.Target{Kind: types.TargetRequestBody}, op: probe,
			hit:  exchange{method: "POST", target: "/", contentType: "text/plain", body: "gwafprobe"},
			miss: exchange{target: "/?q=gwafprobe"}}},
		types.TargetRequestCookies: {
			{target: types.Target{Kind: types.TargetRequestCookies}, op: probe,
				hit: exchange{target: "/", headers: cookie("a=1; sid=gwafprobe")}, miss: exchange{target: "/?sid=gwafprobe"}},
			{target: types.Target{Kind: types.TargetRequestCookies, Name: "SID"}, op: probe,
				hit:  exchange{target: "/", headers: cookie("a=1;sid=gwafprobe")},
				miss: exchange{target: "/", headers: cookie("sid=x; other=gwafprobe")}},
			// HTTP/2 sends each cookie as its own header field.
			{target: types.Target{Kind: types.TargetRequestCookies, Name: "sid"}, op: op.Equals("gwafprobe"),
				hit:  exchange{target: "/", headers: [][2]string{{"Cookie", "a=1"}, {"Cookie", "sid=gwafprobe"}}},
				miss: exchange{target: "/", headers: cookie("sid=gwafprobex")}},
		},
		types.TargetRequestCookieNames: {{target: types.Target{Kind: types.TargetRequestCookieNames}, op: probe,
			hit: exchange{target: "/", headers: cookie("a=1; gwafprobe=1")}, miss: exchange{target: "/", headers: cookie("a=gwafprobe")}}},
		types.TargetRemoteAddr: {{target: types.Target{Kind: types.TargetRemoteAddr}, op: op.Equals("192.0.2.77"),
			hit: exchange{target: "/", remote: "192.0.2.77"}, miss: exchange{target: "/?a=192.0.2.77"}}},
		types.TargetResponseStatus: {{target: types.Target{Kind: types.TargetResponseStatus}, op: op.Equals("418"),
			hit: exchange{target: "/", status: 418}, miss: exchange{target: "/?s=418", status: 200}}},
		types.TargetResponseHeaders: {{target: types.Target{Kind: types.TargetResponseHeaders, Name: "x-out"}, op: probe,
			hit:  exchange{target: "/", respHeaders: [][2]string{{"X-Out", "gwafprobe"}}},
			miss: exchange{target: "/", respHeaders: [][2]string{{"X-Other", "gwafprobe"}}}}},
		types.TargetResponseHeaderNames: {{target: types.Target{Kind: types.TargetResponseHeaderNames}, op: probe,
			hit:  exchange{target: "/", respHeaders: [][2]string{{"X-Gwafprobe", "1"}}},
			miss: exchange{target: "/", respHeaders: [][2]string{{"X-Out", "gwafprobe"}}}}},
		types.TargetResponseBody: {{target: types.Target{Kind: types.TargetResponseBody}, op: probe,
			hit: exchange{target: "/", respBody: "gwafprobe"}, miss: exchange{target: "/?b=gwafprobe", respBody: "x"}}},
		types.TargetArgsJoined: {{target: types.Target{Kind: types.TargetArgsJoined}, op: op.Contains("gwafprobe"),
			hit: exchange{target: "/?a=gwaf&b=probe"}, miss: exchange{target: "/?a=gwaf", headers: [][2]string{{"X-P", "probe"}}}}},
		types.TargetResolved: {{target: types.Target{Kind: types.TargetResolved, Name: "probe.v"}, op: probe,
			hit: exchange{target: "/"}, miss: exchange{target: "/?v=gwafprobe"}, resolved: [2]string{"gwafprobe", "x"}}},
		types.TargetFileNames: {{target: types.Target{Kind: types.TargetFileNames}, op: probe,
			hit:  exchange{method: "POST", target: "/", contentType: "multipart/form-data; boundary=B", body: multipart},
			miss: exchange{method: "POST", target: "/", contentType: formType, body: "f=gwafprobe.php"}}},
	}
}

// TestEveryTargetKindIsPopulated proves a rule on each target kind can fire,
// and fires only on its own collection.
//
// ARGS_GET, ARGS_POST, ARGS_JOINED, REQUEST_COOKIES and REQUEST_COOKIE_NAMES
// were defined, compiled, linted clean and accepted by the SecLang bridge, and
// no transaction ever recorded a value under them, so every rule on them --
// every imported CRS cookie rule among them -- could never match. And
// RESPONSE_STATUS was recorded but left outside the response window, because
// SetResponseStatus did not open it. A kind added without a case here fails
// this test rather than repeating that.
func TestEveryTargetKindIsPopulated(t *testing.T) {
	cases := populationCases()
	for k := types.TargetKind(1); int(k) < types.TargetKindCount(); k++ {
		if len(cases[k]) == 0 {
			t.Errorf("%s has no population case: a kind nothing proves is filled is a kind that may not be", k)
		}
	}
	for k, list := range cases {
		for _, c := range list {
			t.Run(c.target.String(), func(t *testing.T) {
				phase := k.Phase()
				w := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(rules.Set{{
					ID: probeRuleID, Phase: phase, Targets: []types.Target{c.target}, Op: c.op,
					Actions: []rules.Action{rules.Block}, Severity: types.SeverityCritical,
					Confidence: types.Certain, Msg: "population probe",
				}}))
				if !fired(t, w, c.hit, c.resolved[0]) {
					t.Errorf("a rule on %s did not fire on a request carrying the probe there", c.target)
				}
				if fired(t, w, c.miss, c.resolved[1]) {
					t.Errorf("a rule on %s fired on a request carrying the probe only outside it", c.target)
				}
			})
		}
	}
}

// TestArgsGetHoldsOnlyTheQuery proves ARGS_GET stays the query when a rule
// reads it in the body phase, after body arguments exist, and when an embedder
// hands over the body before running the header phase.
func TestArgsGetHoldsOnlyTheQuery(t *testing.T) {
	w := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(rules.Set{{
		ID: probeRuleID, Phase: types.PhaseRequestBody, Targets: []types.Target{{Kind: types.TargetArgsGet}},
		Op: op.Contains("gwafprobe"), Actions: []rules.Action{rules.Block},
		Severity: types.SeverityCritical, Confidence: types.Certain, Msg: "query probe",
	}}))
	post := exchange{method: "POST", target: "/?q=1", contentType: formType, body: "q=gwafprobe"}
	if fired(t, w, post, "") {
		t.Error("a body-phase ARGS_GET rule fired on a body argument")
	}
	if !fired(t, w, exchange{method: "POST", target: "/?q=gwafprobe", contentType: formType, body: "q=1"}, "") {
		t.Error("a body-phase ARGS_GET rule did not fire on a query argument")
	}

	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("POST", "/?q=1", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", formType)
	tx.SetRequestBody([]byte("q=gwafprobe"))
	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		t.Fatalf("header phase: %v", d)
	}
	if d := tx.ProcessRequestBody(); d.Blocked() {
		t.Errorf("ARGS_GET took a body argument when the body arrived before the header phase: %v", d)
	}
}

// cookieWAF compiles one rule on target, with MaxArgs lowered to maxArgs.
func cookieWAF(t *testing.T, target types.Target, maxArgs int) *gwaf.WAF {
	t.Helper()
	limits := gwaf.DefaultLimits()
	limits.MaxArgs = maxArgs
	return newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithLimits(limits), gwaf.WithRuleset(rules.Set{{
		ID: probeRuleID, Phase: types.PhaseRequestHeaders, Targets: []types.Target{target},
		Op: op.Contains("gwafprobe"), Actions: []rules.Action{rules.Block},
		Severity: types.SeverityCritical, Confidence: types.Certain, Msg: "cookie probe",
	}}))
}

// TestCookieCountIsBounded proves a request cannot push a cookie past the
// collection by sending more of them than the limit admits. Dropping the
// excess would be a padding bypass, so the request is refused as over the
// limit instead -- and one at the limit is still inspected in full.
func TestCookieCountIsBounded(t *testing.T) {
	w := cookieWAF(t, types.Target{Kind: types.TargetRequestCookies}, 3)

	at := exchange{target: "/", headers: [][2]string{{"Cookie", "a=1; b=2; c=gwafprobe"}}}
	if !fired(t, w, at, "") {
		t.Error("the third of three cookies was not inspected")
	}

	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/", "HTTP/1.1")
	tx.AddRequestHeader("Cookie", "a=1; b=2; c=3; d=gwafprobe")
	d := tx.ProcessRequestHeaders()
	if !d.Blocked() || d.Reason() != gwaf.ReasonLimit {
		t.Errorf("four cookies against a limit of three: got %v, want a limit refusal", d)
	}
}

// TestCookieWithoutEqualsIsInspectedBothWays proves a pair with no '=' is read
// as a name and as a value, since origins disagree about which it is.
func TestCookieWithoutEqualsIsInspectedBothWays(t *testing.T) {
	x := exchange{target: "/", headers: [][2]string{{"Cookie", "a=1;  gwafprobe ;"}}}
	for _, kind := range []types.TargetKind{types.TargetRequestCookies, types.TargetRequestCookieNames} {
		if !fired(t, cookieWAF(t, types.Target{Kind: kind}, 100), x, "") {
			t.Errorf("a bare cookie pair was not inspected under %s", kind)
		}
	}
}

// TestDerivedViewsAllocateNothing holds the zero-allocation SLO for a request
// whose rules read every derived collection. The views share spans with the
// values they are cut from, so a warm transaction builds them without a single
// allocation.
func TestDerivedViewsAllocateNothing(t *testing.T) {
	if raceEnabled {
		t.Skip("race instrumentation allocates; not measurable under -race")
	}
	w := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(rules.Set{
		{ID: probeRuleID, Phase: types.PhaseRequestBody,
			Targets: []types.Target{{Kind: types.TargetArgsGet}, {Kind: types.TargetArgsPost},
				{Kind: types.TargetArgsJoined}, {Kind: types.TargetRequestCookies},
				{Kind: types.TargetRequestCookieNames}},
			Op: op.Contains("gwafprobe"), Actions: []rules.Action{rules.Block},
			Severity: types.SeverityCritical, Confidence: types.Certain, Msg: "views probe"},
	}))
	body := []byte("a=1&b=2")
	run := func() {
		tx := w.NewTransaction()
		tx.SetRequestLine("POST", "/x?q=1&r=2", "HTTP/1.1")
		tx.AddRequestHeader("Cookie", "sid=abc; theme=dark")
		tx.AddRequestHeader("Content-Type", formType)
		tx.ProcessRequestHeaders()
		tx.SetRequestBody(body)
		tx.ProcessRequestBody()
		tx.Close()
	}
	for range 2000 {
		run()
	}
	if got := testing.AllocsPerRun(10000, run); got > 0.05 {
		t.Errorf("allocations per request = %.4f, want <= 0.05", got)
	}
}
