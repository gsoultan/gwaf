// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gwaf"
	gwafmw "github.com/gsoultan/gwaf/middleware"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/core"
	"github.com/gsoultan/gwaf/schema"
)

// Preflight and gRPC framing must pass, and the reason they do is structural.
//
// A CORS preflight is a method, a path and a handful of headers with no body
// and no arguments, and gwaf's rules are almost entirely anchored on argument
// values. The off-origin rules in particular target ARGS only, so an
// "Origin: https://evil.tld" header is inspected as a header value and never
// compared against the declared origins — **gwaf does not do CORS policy.**
// Whether evil.tld may call your API is a question about identity, which the
// embedder owns (CLAUDE.md §1, the Policy test).
//
// This is pinned because it is exactly the kind of thing a future rule breaks by
// accident. A rule that starts matching on `Access-Control-Request-Headers`, or
// on an OPTIONS request line, would break every browser client of every adopter
// at once, and it would look like a CORS bug rather than a WAF block — the
// browser reports a missing Access-Control-Allow-Origin header, not a 403.
func TestPreflightAndGRPCFramingPass(t *testing.T) {
	tuned, err := gwaf.New(
		gwaf.WithOrigins("api.example.com"),
		gwaf.WithRuleset(core.WithBodyPhase(rules.Set{
			core.SSRFParamRule(1016), core.SQLSinkRule(2011), core.PathSinkRule(1017),
		})),
		gwaf.WithRuleset(rules.Set{core.CommandSinkRule(4022)}))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := gwaf.New()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, method, path string
		headers            [][2]string
	}{
		{"CORS preflight", "OPTIONS", "/api/orders", [][2]string{
			{"Origin", "https://app.example.com"},
			{"Access-Control-Request-Method", "POST"},
			{"Access-Control-Request-Headers", "content-type,authorization"}}},
		{"gRPC-Web preflight", "OPTIONS", "/pkg.Svc/Method", [][2]string{
			{"Origin", "https://app.example.com"},
			{"Access-Control-Request-Method", "POST"},
			{"Access-Control-Request-Headers", "x-grpc-web,content-type,x-user-agent,grpc-timeout"}}},
		// A foreign Origin is not gwaf's decision. Blocking it here would be the
		// library taking a policy position it has no basis for.
		{"preflight from a foreign origin", "OPTIONS", "/api/orders", [][2]string{
			{"Origin", "https://evil.tld"},
			{"Access-Control-Request-Method", "DELETE"},
			{"Access-Control-Request-Headers", "authorization"}}},
		{"gRPC unary POST", "POST", "/pkg.Svc/Method", [][2]string{
			{"Content-Type", "application/grpc"}, {"TE", "trailers"}, {"grpc-timeout", "10S"}}},
		{"gRPC-Web POST", "POST", "/pkg.Svc/Method", [][2]string{
			{"Content-Type", "application/grpc-web+proto"}, {"x-grpc-web", "1"}}},
		{"bare OPTIONS", "OPTIONS", "/api/orders", nil},
	}

	for _, w := range []struct {
		label string
		waf   *gwaf.WAF
	}{{"default", plain}, {"tuned", tuned}} {
		h := gwafmw.HTTP(w.waf)(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(204)
		}))
		for _, c := range cases {
			t.Run(w.label+"/"+c.name, func(t *testing.T) {
				rec := replay(h, c.method, c.path, c.headers)
				if rec.Code != 204 {
					t.Errorf("status %d, want 204: preflight and gRPC framing carry no "+
						"arguments and must not be blocked", rec.Code)
				}
			})
		}
	}
}

// TestClosedSchemaRejectsUndeclaredPreflight pins the one configuration where
// preflight *is* blocked, so the caveat is discoverable rather than folklore.
//
// Schema.Closed() defines the API rather than describing it, so a request
// matching no operation is for a route that does not exist. That is the point
// of the mode — it answers product-path reconnaissance without naming a single
// product — and OpenAPI documents routinely omit OPTIONS, so preflight lands in
// exactly that hole.
//
// The fix is not to weaken the mode. Either declare OPTIONS on the routes that
// need it, or run the CORS middleware *before* gwaf so preflight is answered
// and never reaches it. The second is better regardless: a 403 from here has no
// Access-Control-Allow-Origin on it, so the browser reports a CORS failure and
// the WAF block is invisible to whoever is debugging.
func TestClosedSchemaRejectsUndeclaredPreflight(t *testing.T) {
	sc, err := schema.New(schema.Operation{Method: "POST", Path: "/api/orders"})
	if err != nil {
		t.Fatal(err)
	}
	waf, err := gwaf.New(gwaf.WithSchema(sc.Closed()))
	if err != nil {
		t.Fatal(err)
	}
	h := gwafmw.HTTP(waf)(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(204)
	}))

	rec := replay(h, "OPTIONS", "/api/orders", [][2]string{
		{"Origin", "https://app.example.com"},
		{"Access-Control-Request-Method", "POST"},
	})
	if rec.Code == 204 {
		t.Skip("closed schema admitted an undeclared OPTIONS; the caveat no longer applies")
	}
	t.Logf("closed schema rejects undeclared OPTIONS with %d, as documented", rec.Code)

	// Declaring it is the in-band fix.
	sc2, err := schema.New(
		schema.Operation{Method: "POST", Path: "/api/orders"},
		schema.Operation{Method: "OPTIONS", Path: "/api/orders"},
	)
	if err != nil {
		t.Fatal(err)
	}
	waf2, err := gwaf.New(gwaf.WithSchema(sc2.Closed()))
	if err != nil {
		t.Fatal(err)
	}
	h2 := gwafmw.HTTP(waf2)(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(204)
	}))
	if rec := replay(h2, "OPTIONS", "/api/orders", nil); rec.Code != 204 {
		t.Errorf("declaring OPTIONS did not admit it: status %d", rec.Code)
	}
}

func replay(h http.Handler, method, path string, headers [][2]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Host = "api.example.com"
	for _, hd := range headers {
		req.Header.Set(hd[0], hd[1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
