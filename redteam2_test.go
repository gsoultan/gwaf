package gwaf_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/core"
)

func rt2WAF(t *testing.T) *gwaf.WAF {
	return newWAF(t,
		gwaf.WithOrigins("target.local"),
		gwaf.WithRuleset(core.WithBodyPhase(rules.Set{
			core.CRLFHeaderRule(1007), core.SSRFParamRule(1016),
			core.SQLSinkRule(2011), core.PathSinkRule(1017),
		})),
		gwaf.WithRuleset(rules.Set{core.CommandSinkRule(4022)}))
}

func gzb(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

// TestRedTeam2 is the second adversarial round: limits, nested encodings,
// normalization, and the places a professional looks once the obvious ones fail.
//
// Two bypasses in twenty. One was real -- base64(base64(shell)), where a single
// decode left printable base64 that was recorded and never looked at again.
//
// # The other was not, and that distinction is the interesting part
//
// gzip(gzip(payload)) declared as "Content-Encoding: gzip" is not detected, and
// must not be. gwaf decompresses once and sees gzip bytes; **the origin also
// decompresses once and sees gzip bytes**. The payload never executes, so there
// is no disagreement to exploit and nothing to detect. Teaching gwaf to
// decompress a layer nobody declared would invent a reading no origin performs
// -- the mirror image of every bug this file has found -- and would open a
// decompression-bomb surface, since nested gzip is the cheapest way to build
// one.
//
// "Content-Encoding: gzip, gzip" *is* blocked, because there the origin does
// unwrap twice and the two would otherwise disagree. The rule is the same one
// throughout: follow the readings the origin performs, and no others.
func TestRedTeam2(t *testing.T) {
	w := rt2WAF(t)
	const shell = "<?php system($_GET['c']); ?>"
	const sqli = "1' UNION SELECT password FROM users--"

	// Limit-exhaustion payloads.
	manyArgs := strings.Builder{}
	for i := 0; i < 1200; i++ {
		fmt.Fprintf(&manyArgs, "f%d=x&", i)
	}
	manyArgs.WriteString("q=" + strings.ReplaceAll(sqli, " ", "+"))

	deep := strings.Repeat(`{"a":`, 40) + `"` + "; whoami" + `"` + strings.Repeat("}", 40)

	manyParts := strings.Builder{}
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&manyParts, "--B\r\nContent-Disposition: form-data; name=\"p%d\"\r\n\r\nx\r\n", i)
	}
	manyParts.WriteString("--B\r\nContent-Disposition: form-data; name=\"cmd\"\r\n\r\n; cat /etc/passwd\r\n--B--\r\n")

	manyFields := strings.Builder{}
	manyFields.WriteString("{")
	for i := 0; i < 1200; i++ {
		fmt.Fprintf(&manyFields, `"f%d":"x",`, i)
	}
	manyFields.WriteString(`"q":"` + sqli + `"}`)

	type atk struct {
		name, method, target, ctype, body string
		raw                               []byte
		hdrs                              [][2]string
	}
	for _, a := range []atk{
		// ---- limits, and what happens past them ----
		{name: "payload past MaxArgs", target: "/x?" + manyArgs.String()},
		{name: "payload past MaxParts", ctype: "multipart/form-data; boundary=B", body: manyParts.String()},
		{name: "payload past MaxFields", ctype: "application/json", body: manyFields.String()},
		{name: "payload past MaxDepth", ctype: "application/json", body: deep},

		// ---- nested encoding chains ----
		{name: "double base64 shell", ctype: "application/json",
			body: `{"d":"` + base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(shell)))) + `"}`},
		{name: "gzip of base64 shell", ctype: "application/json",
			raw:  gzb(`{"d":"` + base64.StdEncoding.EncodeToString([]byte(shell)) + `"}`),
			hdrs: [][2]string{{"Content-Encoding", "gzip"}}},
		{name: "base64url shell", ctype: "application/json",
			body: `{"d":"` + base64.RawURLEncoding.EncodeToString([]byte(shell)) + `"}`},

		// ---- charset at the part level (the CVE-2026-21876 vector) ----
		{name: "utf7 in a multipart part", ctype: "multipart/form-data; boundary=B",
			body: "--B\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Type: text/plain; charset=utf-7\r\n\r\n+ADw-script+AD4-alert(1)+ADw-/script+AD4-\r\n--B--\r\n"},
		{name: "utf7 in a later part only", ctype: "multipart/form-data; boundary=B",
			body: "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n" +
				"--B\r\nContent-Disposition: form-data; name=\"b\"\r\nContent-Type: text/plain; charset=utf-7\r\n\r\n+ADw-script+AD4-alert(1)+ADw-/script+AD4-\r\n--B--\r\n"},

		// ---- unicode normalization ----
		{name: "fullwidth script tag", target: "/x?q=＜script＞alert(1)＜/script＞"},
		{name: "unicode escape in json string", ctype: "application/json",
			body: `{"q":"<script>alert(1)</script>"}`},
		{name: "unicode escaped sql keyword", ctype: "application/json",
			body: `{"q":"1' UNION SELECT pw--"}`},

		// ---- path / route confusion ----
		{name: "semicolon path segment", target: "/api/..;/admin?cmd=id"},
		{name: "encoded dot segments in path", target: "/api/%2e%2e/%2e%2e/etc/passwd"},
		{name: "double slash path", target: "//api//../../etc/passwd"},

		// ---- content-encoding chains ----
		{name: "gzip declared twice", ctype: "application/json",
			raw:  gzb(`{"cmd":"; whoami"}`),
			hdrs: [][2]string{{"Content-Encoding", "gzip, gzip"}}},

		// ---- header-borne ----
		{name: "sqli in a header", target: "/x",
			hdrs: [][2]string{{"X-Filter", sqli}}},
		{name: "shell in user-agent", target: "/x",
			hdrs: [][2]string{{"User-Agent", "() { :; }; /bin/bash -c 'id'"}}},
		{name: "traversal in referer", target: "/x",
			hdrs: [][2]string{{"Referer", "http://x/../../etc/passwd"}}},
	} {
		m := a.method
		if m == "" {
			m = "GET"
		}
		tgt := a.target
		if tgt == "" {
			tgt = "/x"
		}
		body := a.raw
		if body == nil && a.body != "" {
			body = []byte(a.body)
		}
		if body != nil {
			m = "POST"
		}
		tx := w.NewTransaction()
		tx.SetRequestLine(m, tgt, "HTTP/1.1")
		tx.SetRemoteAddr("192.0.2.1")
		if a.ctype != "" {
			tx.AddRequestHeader("Content-Type", a.ctype)
		}
		for _, h := range a.hdrs {
			tx.AddRequestHeader(h[0], h[1])
		}
		d := tx.ProcessRequestHeaders()
		if !d.Blocked() && body != nil {
			tx.SetRequestBody(body)
			d = tx.ProcessRequestBody()
		}
		if !d.Blocked() {
			t.Errorf("BYPASS %s: reason=%v", a.name, d.Reason())
		}
		tx.Close()
	}
}
