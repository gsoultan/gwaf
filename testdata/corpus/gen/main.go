// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Command gen builds the benign calibration corpus.
//
// # Provenance, stated plainly
//
// The request *shapes* here are real. Paths, query parameter names, Connect
// service and method names, JSON field names, and header sets were extracted
// from the gateon API gateway: its React client's fetch calls, its protobuf
// service definitions, and its REST handlers. gateon is gwaf's first adopter,
// so this is the traffic gwaf will actually sit in front of.
//
// The *values* are plausible rather than observed. gateon has no production
// access logs, so nothing here was captured from a real client.
//
// That distinction matters and is why this file exists rather than a hand-typed
// JSONL blob: a generator can be reviewed against the real surface it claims to
// model, and a reviewer can see exactly which parts are real and which are
// invented.
//
// # What this corpus can and cannot prove
//
// Statistical power is bounded by the number of *distinct* requests, not the
// line count. Padding with near-duplicates lowers the reported minimum
// detectable rate without making the measurement mean more, which is why the
// generator emits combinations that differ in ways rules can actually see.
//
// Even so, validating a Certain claim (one false positive in ten thousand)
// needs ten thousand distinct benign requests. That cannot be produced honestly
// from a code surface; it needs production traffic. `gwaf calibrate` prints
// which tiers remain unvalidated, and the answer is always more corpus.
//
// # Why admin-console traffic is over-represented
//
// A gateway's own configuration API is the hardest benign traffic a firewall
// ever sees: it carries file paths, regular expressions, TLS material, CIDR
// blocks, and — in gateon's case — SecLang WAF rules, which are literally
// strings full of SQL and markup metacharacters. If a ruleset produces false
// positives anywhere, it produces them here first.
//
//	go run ./testdata/corpus/gen > testdata/corpus/benign.jsonl
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type request struct {
	Name    string            `json:"name"`
	Method  string            `json:"method,omitempty"`
	Target  string            `json:"target,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Args    map[string]string `json:"args,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// ---- real surface, extracted from gateon --------------------------------

// listPaths are the REST endpoints gateon's client actually calls.
var listPaths = []string{
	"/v1/routes", "/v1/services", "/v1/middlewares", "/v1/entryPoints",
	"/v1/tlsOptions", "/v1/certs", "/v1/users", "/v1/audit/archives",
	"/v1/traces", "/v1/alerts", "/v1/waf/rules", "/v1/geoip/status",
	"/v1/diagnostics", "/v1/diag/agg-stats", "/v1/diag/path-stats",
	"/v1/diag/limit-stats", "/v1/diag/circuit-breaker/events",
	"/v1/middlewares/presets", "/v1/cloudflare-ips", "/v1/global", "/v1/me",
}

// connectMethods are the Connect/gRPC methods from gateon's protobuf service.
var connectMethods = []string{
	"GetStatus", "ListTraces", "GetTrace", "ListRoutes", "UpdateRoute",
	"DeleteRoute", "ListServices", "UpdateService", "DeleteService",
	"DiscoverGrpcServices", "DiscoverTech", "GetGlobalConfig",
	"UpdateGlobalConfig", "ListEntryPoints", "UpdateEntryPoint",
	"ListMiddlewares", "UpdateMiddleware", "GetCloudflareIPs",
	"ListTLSOptions", "UpdateTLSOption", "Login",
}

// searchTerms are what an operator types into gateon's list filters. Free text
// is where apostrophes, SQL keywords, and markup legitimately appear, so this
// is the highest false-positive-risk field in the whole API.
var searchTerms = []string{
	"api", "backend", "prod", "staging", "auth-service", "user's service",
	"orders", "web", "grpc", "internal", "v2", "canary",
	"select-backend", "union-gateway", "table-service", "drop-zone",
	"a < b", "rate > 100", "x = y", "50% traffic", "AT&T", "O'Brien",
	"café", "日本語", "team's api", "don't route", "<legacy>",
	"health-check", "tls-1.3", "ipv6", "cors", "waf",
}

// userAgents are the clients that reach a gateway's admin console.
var userAgents = []string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
	"curl/8.4.0", "Go-http-client/2.0", "kube-probe/1.29",
	"Prometheus/2.48.0", "Datadog Agent/7.50.0", "Terraform/1.7.0",
	"gateon-cli/0.9.1", "GitHub-Hookshot/abc1234",
}

// hostNames are realistic gateway hosts.
var hostNames = []string{
	"gateway.example.com", "admin.example.internal", "api.example.com",
	"gw-01.eu-west-1.example.net", "localhost:8080", "10.0.3.14:9090",
}

// ---- config payloads: the hardest benign traffic ------------------------

// configBodies are the shapes gateon's own admin API sends. They carry file
// paths, regular expressions, CIDR blocks, TLS material, and SecLang WAF rules
// — all of which look like attacks to a naive matcher.
var configBodies = []struct{ name, body string }{
	{"route update", `{"id":"r-01","name":"api-route","enabled":true,` +
		`"rule":"Host(` + "`" + `api.example.com` + "`" + `) && PathPrefix(` + "`" + `/v1` + "`" + `)",` +
		`"service_id":"svc-01","priority":100}`},
	{"route with regex", `{"id":"r-02","name":"legacy","enabled":true,` +
		`"rule":"HostRegexp(` + "`" + `^(www|api)\\.example\\.com$` + "`" + `)","service_id":"svc-02"}`},
	{"service backend", `{"id":"svc-01","name":"orders","enabled":true,` +
		`"url":"https://orders.internal:8443","weight":100,"healthy":true}`},
	{"tls option", `{"id":"tls-01","name":"modern","cert_file":"/etc/ssl/certs/server.pem",` +
		`"key_file":"/etc/ssl/private/server.key","ca_file":"/etc/ssl/certs/ca-bundle.crt",` +
		`"min_version":"VersionTLS13"}`},
	{"database config", `{"database_url":"postgres://gateon:pw@db.internal:5432/gateon?sslmode=require",` +
		`"sqlite_path":"/var/lib/gateon/gateon.db","max_conns":25}`},
	{"cors middleware", `{"id":"mw-cors","type":"cors","enabled":true,` +
		`"config":{"allowed_origins":"https://app.example.com,https://admin.example.com",` +
		`"allowed_methods":"GET,POST,PUT,DELETE,OPTIONS","allowed_headers":"Authorization,Content-Type"}}`},
	{"ratelimit middleware", `{"id":"mw-rl","type":"ratelimit","enabled":true,` +
		`"config":{"average":"100","burst":"200","period":"1s"}}`},
	{"ipfilter middleware", `{"id":"mw-ip","type":"ipfilter","enabled":true,` +
		`"config":{"allow":"10.0.0.0/8,172.16.0.0/12,192.168.0.0/16","deny":"0.0.0.0/0"}}`},
	{"headers middleware", `{"id":"mw-hdr","type":"headers","enabled":true,` +
		`"config":{"custom_response_headers":"X-Frame-Options=DENY&Content-Security-Policy=default-src 'self'"}}`},
	{"rewrite middleware", `{"id":"mw-rw","type":"rewrite","enabled":true,` +
		`"config":{"regex":"^/old/(.*)$","replacement":"/new/$1"}}`},
	{"alerting config", `{"enabled":true,"threshold":10,"category":"security",` +
		`"url":"https://hooks.slack.com/services/T00/B00/xxxx","message":"gateway alert"}`},
	{"geoip config", `{"enabled":true,"update_interval_hours":24,` +
		`"database_url":"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City"}`},
	{"log config", `{"level":"info","format":"json","path":"/var/log/gateon/access.log",` +
		`"sample_rate":100}`},
	{"otel config", `{"enabled":true,"endpoint":"http://otel-collector.observability:4318",` +
		`"service_name":"gateon","sample_rate":0.1}`},
	{"auth config", `{"type":"oidc","issuer":"https://auth.example.com/realms/main",` +
		`"client_id":"gateon-admin","scopes":"openid profile email"}`},
	{"health check", `{"type":"http","path":"/healthz","interval":"10s","timeout":"2s",` +
		`"healthy_threshold":2,"unhealthy_threshold":3}`},
	{"ebpf config", `{"enabled":true,"interface":"eth0","shun_duration":"600s",` +
		`"knocking_sequence":"1111,2222,3333"}`},
	{"user create", `{"username":"operator","name":"Ops Team","enabled":true,` +
		`"permission":"read-write","email":"ops@example.com"}`},

	// gateon stores WAF rules as SecLang directives, which are strings full of
	// SQL and markup metacharacters. This is the single most likely source of a
	// false positive in the entire product, so it is deliberately included.
	{"seclang rule simple", `{"id":"wr-01","name":"block-scanner","enabled":true,` +
		`"category":"scanner","paranoia_level":1,` +
		`"directive":"SecRule REQUEST_HEADERS:User-Agent \"@contains sqlmap\" \"id:100001,phase:1,deny,status:403\""}`},
	{"seclang rule regex", `{"id":"wr-02","name":"block-traversal","enabled":true,` +
		`"category":"traversal","paranoia_level":2,` +
		`"directive":"SecRule REQUEST_URI \"@rx (?i)\\\\.\\\\./\" \"id:100002,phase:1,t:urlDecodeUni,deny\""}`},
	{"seclang rule select", `{"id":"wr-03","name":"detect-union","enabled":true,` +
		`"category":"sqli","paranoia_level":1,` +
		`"directive":"SecRule ARGS \"@rx union\\\\s+select\" \"id:100003,phase:2,log,pass,msg:'possible sqli'\""}`},
	{"seclang rule script", `{"id":"wr-04","name":"detect-script","enabled":true,` +
		`"category":"xss","paranoia_level":1,` +
		`"directive":"SecRule ARGS \"@rx (?i)<script\" \"id:100004,phase:2,log,pass,msg:'possible xss'\""}`},
	{"seclang setvar", `{"id":"wr-05","name":"anomaly-threshold","enabled":true,` +
		`"category":"config","paranoia_level":1,` +
		`"directive":"SecAction \"id:100005,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=5\""}`},
}

func main() {
	enc := json.NewEncoder(os.Stdout)
	seen := map[string]bool{}
	n := 0

	emit := func(r request) {
		key := r.Method + " " + r.Target + " " + r.Body + fmt.Sprint(r.Args)
		if seen[key] {
			return
		}
		seen[key] = true
		if err := enc.Encode(r); err != nil {
			panic(err)
		}
		n++
	}

	fmt.Fprintln(os.Stderr, "# generated from gateon's real API surface; values are plausible, not observed")
	fmt.Println("# gwaf benign calibration corpus.")
	fmt.Println("# Generated: go run ./testdata/corpus/gen > testdata/corpus/benign.jsonl")
	fmt.Println("# Request SHAPES are extracted from gateon (paths, params, proto fields,")
	fmt.Println("# Connect methods). VALUES are plausible, not captured from production.")
	fmt.Println("# See testdata/corpus/gen/main.go for provenance and limits.")

	browser := func(i int) map[string]string {
		return map[string]string{
			"User-Agent":      userAgents[i%len(userAgents)],
			"Accept":          "application/json, text/plain, */*",
			"Accept-Language": []string{"en-US,en;q=0.9", "en-GB,en;q=0.9,fr;q=0.8", "de-DE,de;q=0.9"}[i%3],
			"Host":            hostNames[i%len(hostNames)],
			"Referer":         "https://" + hostNames[i%len(hostNames)] + "/dashboard",
		}
	}

	// Plain list requests across every real endpoint and client.
	for i, p := range listPaths {
		for j := range userAgents {
			h := browser(i + j)
			emit(request{
				Name: fmt.Sprintf("list %s ua%d", p, j), Target: p, Headers: h,
			})
		}
	}

	// Paginated list requests using gateon's real parameter names.
	pages := []string{"1", "2", "3", "7", "42"}
	sizes := []string{"10", "25", "50", "100", "1000"}
	for i, p := range listPaths {
		for j, page := range pages {
			for k, size := range sizes {
				emit(request{
					Name:    fmt.Sprintf("paged %s p%s n%s", p, page, size),
					Target:  fmt.Sprintf("%s?page=%s&pageSize=%s", p, page, size),
					Headers: browser(i + j + k),
					Args:    map[string]string{"page": page, "pageSize": size},
				})
			}
		}
	}

	// Search filters: free text, and the highest false-positive risk in the API.
	for i, p := range listPaths {
		for j, term := range searchTerms {
			emit(request{
				Name:    fmt.Sprintf("search %s %q", p, term),
				Target:  p + "?search=" + urlEncode(term),
				Headers: browser(i + j),
				Args:    map[string]string{"search": term, "page": "1", "pageSize": "25"},
			})
		}
	}

	// Connect/gRPC calls against the real service.
	for i, m := range connectMethods {
		for j := range 3 {
			h := browser(i + j)
			h["Content-Type"] = []string{
				"application/json", "application/connect+json", "application/proto",
			}[j]
			emit(request{
				Name:    fmt.Sprintf("connect %s ct%d", m, j),
				Method:  "POST",
				Target:  "/gateon.v1.ApiService/" + m,
				Headers: h,
				Body:    `{"page":1,"page_size":50}`,
			})
		}
	}

	// Configuration writes: paths, regexes, TLS material, CIDRs, SecLang.
	for i, c := range configBodies {
		for j, verb := range []string{"POST", "PUT"} {
			h := browser(i + j)
			h["Content-Type"] = "application/json"
			h["Authorization"] = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJzdWIiOiJvcHMiLCJleHAiOjE3NzAwMDAwMDB9.7Xk2QhVn3pLm8sTfR1cWqYbNjKdEgAoIuZxMvBhCtPs"
			emit(request{
				Name:    fmt.Sprintf("config %s %s", verb, c.name),
				Method:  verb,
				Target:  "/v1/config",
				Headers: h,
				Body:    c.body,
			})
		}
	}

	// Single-resource reads, which is where identifiers appear in paths.
	ids := []string{
		"r-01", "svc-02", "mw-cors", "tls-01",
		"550e8400-e29b-41d4-a716-446655440000",
		"01HQ8Z9K3M4N5P6R7S8T9V0W1X", "12345",
	}
	for i, p := range []string{"/v1/routes", "/v1/services", "/v1/middlewares", "/v1/certs"} {
		for j, id := range ids {
			emit(request{
				Name:    fmt.Sprintf("get %s/%s", p, id),
				Target:  p + "/" + id,
				Headers: browser(i + j),
			})
		}
	}

	// Infrastructure traffic: probes, metrics, discovery.
	infra := []struct{ name, target, ua string }{
		{"liveness", "/healthz", "kube-probe/1.29"},
		{"readiness", "/readyz", "kube-probe/1.29"},
		{"startup", "/startupz", "kube-probe/1.29"},
		{"metrics", "/metrics", "Prometheus/2.48.0"},
		{"oidc discovery", "/.well-known/openid-configuration", "Go-http-client/2.0"},
		{"jwks", "/jwks", "Go-http-client/2.0"},
		{"favicon", "/favicon.ico", userAgents[0]},
		{"ui root", "/", userAgents[0]},
		{"ui asset js", "/assets/index-a1b2c3d4.js", userAgents[0]},
		{"ui asset css", "/assets/index-e5f6a7b8.css", userAgents[0]},
		{"ui sourcemap", "/assets/index-a1b2c3d4.js.map", userAgents[2]},
		{"robots", "/robots.txt", "Googlebot/2.1"},
	}
	for i, in := range infra {
		h := browser(i)
		h["User-Agent"] = in.ua
		emit(request{Name: in.name, Target: in.target, Headers: h})
	}

	// Auth flows.
	emit(request{
		Name: "login", Method: "POST", Target: "/v1/login",
		Headers: map[string]string{"Content-Type": "application/json", "Host": hostNames[0]},
		Body:    `{"username":"operator","password":"correct horse battery staple"}`,
	})
	emit(request{
		Name: "2fa verify", Method: "POST", Target: "/v1/auth/2fa/verify",
		Headers: map[string]string{"Content-Type": "application/json", "Host": hostNames[0]},
		Body:    `{"token":"492013"}`,
	})
	emit(request{
		Name: "logout", Method: "POST", Target: "/v1/logout",
		Headers: map[string]string{"Host": hostNames[0]},
	})
	emit(request{
		Name: "config export", Target: "/v1/config/export",
		Headers: map[string]string{"Accept": "application/json", "Host": hostNames[1]},
	})
	emit(request{
		Name: "analyze config", Method: "POST", Target: "/v1/AnalyzeConfig",
		Headers: map[string]string{"Content-Type": "application/json", "Host": hostNames[1]},
		Body:    `{"focus":"security"}`,
	})

	fmt.Fprintf(os.Stderr, "generated %d distinct benign requests\n", n)
}

// urlEncode percent-encodes a query value.
func urlEncode(s string) string {
	const hex = "0123456789ABCDEF"
	out := make([]byte, 0, len(s)*3)
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			out = append(out, c)
		case c == ' ':
			out = append(out, '+')
		default:
			out = append(out, '%', hex[c>>4], hex[c&0x0f])
		}
	}
	return string(out)
}
