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

// TestBenignTrafficStillEvaluatesNoRules guards the cost of multi-interpretation.
// Enumerating readings must be free on traffic that has no ambiguity, or the
// security win was paid for with the performance thesis.
func TestBenignTrafficStillEvaluatesNoRules(t *testing.T) {
	w := newWAF(t)

	for _, b := range benignTraffic {
		// Values containing encoding markers legitimately produce extra
		// readings; the claim is about traffic with no ambiguity at all.
		if strings.ContainsAny(b.arg+b.body+b.target, "%\\&+") {
			continue
		}
		t.Run(b.name, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			target := b.target
			if target == "" {
				target = "/search"
			}
			tx.SetRequestLine("GET", target, "HTTP/1.1")
			if b.header[0] != "" {
				tx.AddRequestHeader(b.header[0], b.header[1])
			}
			if b.arg != "" {
				tx.AddArgument("q", b.arg)
			}
			tx.ProcessRequestHeaders()

			if got := tx.RulesEvaluated(); got != 0 {
				t.Errorf("RulesEvaluated() = %d, want 0", got)
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
