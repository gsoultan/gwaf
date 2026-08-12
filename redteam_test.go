// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Adversarial suite: attacks composed rather than replayed.
//
// The evasion corpus and the head-to-head both replay payloads somebody else
// wrote — known techniques against known CVEs. This file is the other half: an
// attacker sitting down with the source and composing the request that gets
// through. Every case here was written by asking "what would I try next", not
// by looking anything up.
//
// The first run found four bypasses in twenty-four attempts, and three were
// real:
//
//   - a base64 PHP web shell in a JSON field, because the decode floor was 64
//     characters and "<?php system($_GET['c']); ?>" encodes to 40;
//   - "cmd[]=id", because the shell sink checked the parameter name without
//     stripping the PHP array suffix that every other sink rule strips;
//   - filename="a.php\x00.jpg", because the null-byte rule matches the encoded
//     spelling, which is the one that does *not* work in a multipart header.
//
// # One framing is deliberately absent
//
// "?q=1'+UNION&q=+SELECT+pw--" is not here, and it is not fixed. Neither value
// is an attack alone; the injection exists only under the comma-joining that
// ASP.NET and some other stacks apply to repeated parameters. Evaluating a
// joined view of duplicate names is a real gap and a real design decision —
// which separator, recorded where, and at what cost to the zero-allocation
// argument path — and it is tracked rather than half-built. Adding it here as a
// failing case would break the build to say something a comment says better.

package gwaf_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/core"
)

func rtWAF(t *testing.T) *gwaf.WAF {
	return newWAF(t,
		gwaf.WithOrigins("target.local"),
		gwaf.WithRuleset(core.WithBodyPhase(rules.Set{
			core.CRLFHeaderRule(1007), core.SSRFParamRule(1016),
			core.SQLSinkRule(2011), core.PathSinkRule(1017),
		})),
		gwaf.WithRuleset(rules.Set{core.CommandSinkRule(4022)}))
}

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestRedTeam(t *testing.T) {
	w := rtWAF(t)
	b64 := base64.StdEncoding.EncodeToString([]byte("<?php system($_GET['c']); ?>"))

	type atk struct {
		name, method, target, ctype, body string
		raw                               []byte
		hdrs                              [][2]string
	}
	attacks := []atk{
		// ---- encoding layers ----
		{name: "unicode-escaped shell in JSON", ctype: "application/json",
			body: `{"cmd":";whoami"}`},
		{name: "unicode-escaped SQL in JSON", ctype: "application/json",
			body: `{"q":"1' UNION SELECT pw--"}`},
		{name: "base64 php in JSON field", ctype: "application/json",
			body: `{"data":"` + b64 + `"}`},
		{name: "double-encoded traversal", target: "/x?path=%252e%252e%252f%252e%252e%252fetc%252fpasswd"},
		{name: "triple-encoded script", target: "/x?q=%25253Cscript%25253Ealert(1)%25253C%25252Fscript%25253E"},
		{name: "overlong utf8 traversal", target: "/x?f=%c0%ae%c0%ae%c0%afetc%c0%afpasswd"},
		{name: "utf7 body", ctype: "text/plain; charset=utf-7",
			body: "+ADw-script+AD4-alert(1)+ADw-/script+AD4-"},
		{name: "gzip body hiding payload", ctype: "application/json",
			raw:  gz(`{"cmd":"; cat /etc/passwd"}`),
			hdrs: [][2]string{{"Content-Encoding", "gzip"}}},

		// ---- structure / framing ----
		{name: "payload in deep json", ctype: "application/json",
			body: `{"a":{"b":{"c":{"d":{"e":{"f":{"g":"; whoami"}}}}}}}`},
		{name: "payload in json array", ctype: "application/json",
			body: `{"p":["ok","; cat /etc/passwd"]}`},
		{name: "payload as json key", ctype: "application/json",
			body: `{"'; DROP TABLE users--":"x"}`},
		{name: "multipart nested payload", ctype: "multipart/form-data; boundary=B",
			body: "--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\n<?php system($_GET[0]);?>\r\n--B--\r\n"},

		// ---- whitespace / separator variants ----
		{name: "vertical tab in sql", target: "/x?id=1'%0bUNION%0bSELECT%0bpw--"},
		{name: "form feed in sql", target: "/x?id=1'%0cOR%0c1=1--"},
		{name: "sql comment splitting", target: "/x?id=1'/**/UNION/**/SELECT/**/pw--"},
		{name: "mysql version comment", target: "/x?id=1'/*!50000UNION*//*!50000SELECT*/pw--"},
		{name: "newline separated shell", target: "/x?h=1.1.1.1%0Acat%20/etc/passwd"},

		// ---- null bytes / truncation ----
		{name: "null byte in path sink", target: "/x?file=../../etc/passwd%00.jpg"},
		{name: "null in filename upload", ctype: "multipart/form-data; boundary=B",
			body: "--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.php\x00.jpg\"\r\n\r\nX\r\n--B--\r\n"},

		// ---- sink-name evasion ----
		{name: "cmd param uppercase", target: "/x?CMD=id"},
		{name: "cmd param array form", target: "/x?cmd[]=id"},
		{name: "sql param namespaced", target: "/x?app_sql=select * from users"},
		{name: "path sink mixed case", target: "/x?FilePath=../../etc/passwd"},
	}

	blocked, missed := 0, 0
	for _, a := range attacks {
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
		if body != nil && a.method == "" {
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
		if d.Blocked() {
			blocked++
		} else {
			missed++
			t.Errorf("BYPASS %s: %s %s %s", a.name, m, tgt, strings.TrimSpace(a.body))
		}
		tx.Close()
	}
	t.Logf("red team: %d blocked, %d bypassed of %d", blocked, missed, len(attacks))
}
