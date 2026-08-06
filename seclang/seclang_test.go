// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package seclang_test

import (
	"errors"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/seclang"
	"github.com/gsoultan/gwaf/types"
)

// crs is shaped like the Core Rule Set: multi-line action lists, quoted
// messages containing commas and '#', line continuations, and the two operators
// ModSecurity shipped as native code.
const crs = `
# ------------------------------------------------------------------------
# OWASP CRS-shaped fixture
# ------------------------------------------------------------------------
SecDefaultAction "phase:2,log,auditlog,pass"

SecRule REQUEST_URI "@rx (?i)/etc/passwd" \
    "id:930120,\
    phase:1,\
    deny,\
    t:none,t:urlDecode,t:lowercase,\
    msg:'OS File Access Attempt',\
    tag:'application-multi',\
    tag:'attack-lfi',\
    severity:'CRITICAL'"

SecRule ARGS "@detectSQLi" \
    "id:942100,\
    phase:2,\
    deny,\
    t:none,t:urlDecode,\
    msg:'SQL Injection Attack Detected via libinjection',\
    tag:'attack-sqli',\
    severity:'CRITICAL'"

SecRule ARGS|ARGS_NAMES "@detectXSS" \
    "id:941100,\
    phase:2,\
    deny,\
    t:none,t:urlDecode,\
    msg:'XSS Attack Detected via libinjection',\
    severity:'CRITICAL'"

SecRule REQUEST_HEADERS:User-Agent "@pm nikto sqlmap nessus" \
    "id:913100,\
    phase:1,\
    deny,\
    t:none,t:lowercase,\
    msg:'Found User-Agent associated with security scanner',\
    severity:'CRITICAL'"

SecRule ARGS "@contains ../" \
    "id:930100,phase:2,deny,t:none,t:urlDecode,msg:'Path Traversal Attack (/../)',severity:'CRITICAL'"

SecRule REQUEST_METHOD "@streq TRACE" \
    "id:911100,phase:1,deny,t:none,msg:'Method is not allowed by policy',severity:'CRITICAL'"

# A rule whose message contains a comma and a hash, which a naive splitter ruins.
SecRule ARGS "@rx (?i)union[\s]+select" \
    "id:942190,phase:2,deny,t:none,t:urlDecode,msg:'SQL keywords: union, select # classic',severity:'CRITICAL'"
`

func TestParsesCRSShapedRules(t *testing.T) {
	set, rep, err := seclang.Parse("crs.conf", []byte(crs),
		seclang.Options{DefaultConfidence: seclang.Medium})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	t.Log("\n" + rep.String())

	if len(set) != 7 {
		t.Fatalf("imported %d rules, want 7", len(set))
	}

	byID := map[types.RuleID]int{}
	for i, r := range set {
		byID[r.ID] = i
	}
	for _, want := range []types.RuleID{930120, 942100, 941100, 913100, 930100, 911100, 942190} {
		if _, ok := byID[want]; !ok {
			t.Errorf("rule %d was not imported", want)
		}
	}

	// The multi-line action list survived continuation joining.
	r := set[byID[930120]]
	if r.Msg != "OS File Access Attempt" {
		t.Errorf("msg = %q", r.Msg)
	}
	if r.Phase != types.PhaseRequestHeaders {
		t.Errorf("phase = %v, want request_headers", r.Phase)
	}
	if r.Severity != types.SeverityCritical {
		t.Errorf("severity = %v", r.Severity)
	}
	if len(r.Transforms) != 2 {
		t.Errorf("transforms = %d, want urlDecode+lowercase (t:none resets)", len(r.Transforms))
	}
	if !hasTag(r.Tags, "attack-lfi") {
		t.Errorf("tags = %v, want attack-lfi", r.Tags)
	}

	// A message containing a comma and a '#' is not truncated.
	m := set[byID[942190]].Msg
	if m != "SQL keywords: union, select # classic" {
		t.Errorf("msg = %q: the action splitter or the comment rule ate it", m)
	}
}

// TestConfidenceMustBeStated is the one option with no default, and the reason
// is worth keeping: a SecLang rule arrives with a severity and a paranoia level
// but with no measured false-positive rate.
func TestConfidenceMustBeStated(t *testing.T) {
	_, _, err := seclang.Parse("x.conf", []byte(crs), seclang.Options{})
	if !errors.Is(err, seclang.ErrNoConfidence) {
		t.Errorf("err = %v, want ErrNoConfidence", err)
	}
}

// TestDetectorsAreAnUpgrade covers the one place translation improves on the
// original: @detectSQLi and @detectXSS become gwaf's structural detectors.
func TestDetectorsAreAnUpgrade(t *testing.T) {
	set, _, err := seclang.Parse("crs.conf", []byte(crs),
		seclang.Options{DefaultConfidence: seclang.High})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range set {
		switch r.ID {
		case 942100:
			if r.Op.Name() != "detect_sqli" {
				t.Errorf("@detectSQLi mapped to %q", r.Op.Name())
			}
		case 941100:
			if r.Op.Name() != "detect_xss" {
				t.Errorf("@detectXSS mapped to %q", r.Op.Name())
			}
		}
	}
}

// TestRegexLiteralsKeepImportedRulesPrefilterable is what makes an import
// usable. Ten thousand CRS rules with no literal would each run against every
// value, which is exactly the interpreter design gwaf exists not to be.
func TestRegexLiteralsKeepImportedRulesPrefilterable(t *testing.T) {
	set, rep, err := seclang.Parse("crs.conf", []byte(crs),
		seclang.Options{DefaultConfidence: seclang.Medium})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Prefiltered < len(set)-1 {
		t.Errorf("only %d of %d rules are prefilterable:\n%s",
			rep.Prefiltered, len(set), rep.String())
	}

	for _, r := range set {
		if r.ID != 930120 {
			continue
		}
		lits, ok := r.Op.Literals()
		if !ok || len(lits) == 0 {
			t.Fatal("the /etc/passwd pattern yielded no literal")
		}
		found := false
		for _, l := range lits {
			if strings.Contains(l, "etc/passwd") {
				found = true
			}
		}
		if !found {
			t.Errorf("literals = %v, want one containing etc/passwd", lits)
		}
	}
}

func TestLiteralExtractionIsSound(t *testing.T) {
	cases := []struct {
		pattern string
		want    []string // each must appear among the extracted literals
		none    bool     // or: no literal may be extracted
	}{
		// A concatenation requires every part, so any single part is a sound
		// key -- and keying on only the most selective one is better than
		// keying on all of them. The prefilter skips a rule when *none* of its
		// literals appear, so an extra literal only widens the candidate set:
		// with {"union", "select"} a value containing "union" alone becomes a
		// candidate and evaluates for nothing, where {"select"} excludes it.
		{pattern: `(?i)union\s+select`, want: []string{"select"}},
		{pattern: `/etc/passwd`, want: []string{"/etc/passwd"}},
		{pattern: `(?:select|insert|update)\s`, want: []string{"select", "insert", "update"}},
		{pattern: `foo(bar)baz`, want: []string{"foobar"}},
		{pattern: `x+yyyy`, want: []string{"yyyy"}},

		// Unsound to extract from: one branch requires nothing, a starred group
		// may be absent, a character class matches many bytes.
		{pattern: `(?:select|.*)`, none: true},
		{pattern: `(abc)*`, none: true},
		{pattern: `[a-z]+`, none: true},
		{pattern: `.*`, none: true},
		{pattern: `a?bc?`, none: true}, // "b" alone is below the length floor
	}

	for _, c := range cases {
		t.Run(c.pattern, func(t *testing.T) {
			src := "SecRule ARGS \"@rx " + c.pattern + "\" \"id:1,phase:2,deny\""
			set, _, err := seclang.Parse("t.conf", []byte(src),
				seclang.Options{DefaultConfidence: seclang.Medium})
			if err != nil {
				t.Fatal(err)
			}
			if len(set) != 1 {
				t.Fatalf("imported %d rules", len(set))
			}
			lits, ok := set[0].Op.Literals()

			if c.none {
				if ok && len(lits) > 0 {
					t.Errorf("extracted %v from a pattern that requires none", lits)
				}
				return
			}
			if !ok {
				t.Fatalf("no literals extracted, want %v", c.want)
			}
			for _, w := range c.want {
				found := false
				for _, l := range lits {
					if strings.Contains(l, w) {
						found = true
					}
				}
				if !found {
					t.Errorf("literals = %v, want one containing %q", lits, w)
				}
			}
		})
	}
}

// TestUntranslatableIsReportedNotApproximated is the package's central promise.
// A silently weakened rule is worse than an absent one, because the operator
// believes they still have it.
func TestUntranslatableIsReportedNotApproximated(t *testing.T) {
	const src = `
SecRule ARGS "@rx (?<=foo)bar" "id:1,phase:2,deny"
SecRule &ARGS "@eq 0" "id:2,phase:2,deny"
SecRule REMOTE_ADDR "@ipMatchFromFile blocklist.txt" "id:3,phase:1,deny"
SecRule TX:score "@gt 5" "id:4,phase:2,deny"
SecRule ARGS "@rx x" "id:5,phase:2,deny,t:cmdLine"
SecRule ARGS "@rx a" "id:6,phase:2,chain,deny"
    SecRule ARGS "@rx b" "t:none"
SecAction "id:7,phase:1,pass,setvar:tx.score=0"
Include /etc/crs/rules.conf
SecRuleEngine On
SecRule ARGS:/^user_/ "@rx x" "id:8,phase:2,deny"
`
	_, rep, err := seclang.Parse("x.conf", []byte(src),
		seclang.Options{DefaultConfidence: seclang.Medium})
	if err != nil {
		t.Fatal(err)
	}
	joined := rep.String()
	for _, want := range []string{
		"RE2",           // lookbehind
		"not a value",   // &ARGS
		"Resolver",      // ipMatchFromFile
		"cmdLine",       // unknown transformation
		"conjunction",   // chain
		"cross-request", // SecAction setvar
		"Include",       // file inclusion
		"gwaf Option",   // SecRuleEngine
		"name pattern",  // ARGS:/regex/
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("report does not explain %q:\n%s", want, joined)
		}
	}
}

// TestChainImportsNothing records the deliberate choice. Importing only a
// chain's head would be strictly more permissive than the original.
func TestChainImportsNothing(t *testing.T) {
	const src = `
SecRule ARGS "@rx evil" "id:100,phase:2,deny,chain"
    SecRule REQUEST_METHOD "@streq POST"
SecRule ARGS "@rx other" "id:101,phase:2,deny"
`
	set, rep, err := seclang.Parse("x.conf", []byte(src),
		seclang.Options{DefaultConfidence: seclang.Medium})
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 || set[0].ID != 101 {
		t.Fatalf("imported %d rules (%v); the chain must not be approximated "+
			"and the rule after it must still arrive", len(set), ids(set))
	}
	if rep.Chains != 1 {
		t.Errorf("Chains = %d, want 1", rep.Chains)
	}
}

// TestRemovalsWinRegardlessOfOrder: SecRuleRemoveById commonly appears after
// the include that defined the rule.
func TestRemovalsWinRegardlessOfOrder(t *testing.T) {
	const src = `
SecRule ARGS "@rx a" "id:1001,phase:2,deny"
SecRule ARGS "@rx b" "id:1002,phase:2,deny"
SecRule ARGS "@rx c" "id:1050,phase:2,deny"
SecRuleRemoveById 1001 1040-1060
`
	set, _, err := seclang.Parse("x.conf", []byte(src),
		seclang.Options{DefaultConfidence: seclang.Medium})
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 || set[0].ID != 1002 {
		t.Errorf("kept %v, want only 1002", ids(set))
	}
}

func TestPrefixAvoidsCollisions(t *testing.T) {
	set, _, err := seclang.Parse("x.conf",
		[]byte(`SecRule ARGS "@rx a" "id:1,phase:2,deny"`),
		seclang.Options{DefaultConfidence: seclang.Medium, Prefix: 900000})
	if err != nil {
		t.Fatal(err)
	}
	if set[0].ID != 900001 {
		t.Errorf("ID = %d, want 900001", set[0].ID)
	}
}

func TestStrictRefusesToImportPartially(t *testing.T) {
	const src = `
SecRule ARGS "@rx a" "id:1,phase:2,deny"
SecRule ARGS "@ipMatch 10.0.0.0/8" "id:2,phase:1,deny"
`
	if _, _, err := seclang.ParseStrict("x.conf", []byte(src),
		seclang.Options{DefaultConfidence: seclang.Medium}); !errors.Is(err, seclang.ErrUntranslatable) {
		t.Errorf("err = %v, want ErrUntranslatable", err)
	}
}

// TestImportedRulesActuallyRun is the end of the bridge: rules somebody wrote
// for ModSecurity, compiled and blocking inside gwaf.
func TestImportedRulesActuallyRun(t *testing.T) {
	set, _, err := seclang.Parse("crs.conf", []byte(crs),
		seclang.Options{DefaultConfidence: seclang.High, Prefix: 800000})
	if err != nil {
		t.Fatal(err)
	}

	w, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set),
		gwaf.WithMinConfidence(types.Low))
	if err != nil {
		t.Fatalf("gwaf.New with imported rules: %v", err)
	}

	for _, c := range []struct {
		name, target, arg, ua string
		blocked               bool
	}{
		{name: "lfi in uri", target: "/index.php?f=/etc/passwd", blocked: true},
		{name: "sqli in arg", arg: "1' OR 1=1--", blocked: true},
		{name: "xss in arg", arg: "<script>alert(1)</script>", blocked: true},
		{name: "scanner ua", ua: "sqlmap/1.7", blocked: true},
		{name: "traversal", arg: "../../etc/hosts", blocked: true},
		{name: "union select", arg: "1 union select password", blocked: true},
		{name: "benign search", arg: "running shoes", blocked: false},
		{name: "benign name", arg: "O'Brien", blocked: false},
		{name: "benign browser", ua: "Mozilla/5.0", blocked: false},
	} {
		t.Run(c.name, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()

			target := c.target
			if target == "" {
				target = "/search"
			}
			tx.SetRequestLine("GET", target, "HTTP/1.1")
			if c.ua != "" {
				tx.AddRequestHeader("User-Agent", c.ua)
			}
			if c.arg != "" {
				tx.AddArgument("q", c.arg)
			}
			d := tx.ProcessRequestHeaders()
			if !d.Blocked() {
				d = tx.ProcessRequestBody()
			}
			if d.Blocked() != c.blocked {
				t.Errorf("blocked = %v, want %v (rule=%d msg=%q)",
					d.Blocked(), c.blocked, d.RuleID(), d.Message())
			}
		})
	}
}

func TestMalformedInput(t *testing.T) {
	if _, _, err := seclang.Parse("x.conf", []byte(`SecRule ARGS "@rx unterminated`),
		seclang.Options{DefaultConfidence: seclang.Medium}); !errors.Is(err, seclang.ErrSyntax) {
		t.Errorf("err = %v, want ErrSyntax", err)
	}
	// Empty and comment-only input compile to nothing without complaint.
	for _, src := range []string{"", "# just a comment\n", "\n\n\n"} {
		if _, _, err := seclang.Parse("x.conf", []byte(src),
			seclang.Options{DefaultConfidence: seclang.Medium}); err != nil {
			t.Errorf("%q: %v", src, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(crs)
	f.Add(`SecRule ARGS "@rx a" "id:1,phase:2,deny"`)
	f.Add(`SecRule "" "" ""`)
	f.Add("SecRule ARGS \"@rx a\" \"id:1\\\n")
	f.Add(`SecRule ARGS|!ARGS:x "@pm a b" "id:2,t:none"`)

	f.Fuzz(func(t *testing.T, src string) {
		// The contract is that a build-time tool never panics on input somebody
		// else wrote, however malformed.
		_, _, _ = seclang.Parse("fuzz.conf", []byte(src),
			seclang.Options{DefaultConfidence: seclang.Medium})
	})
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func ids(set rules.Set) []types.RuleID {
	out := make([]types.RuleID, len(set))
	for i, r := range set {
		out[i] = r.ID
	}
	return out
}

// TestGeneratedSourceCompilesAndDetects is the end of the migration path: a
// CRS-shaped file becomes Go source, that source compiles, and the rules it
// declares block what the originals blocked.
//
// Generating code nobody compiles is how a converter ships broken. This writes
// the output to a temporary module and builds it.
func TestGeneratedSourceCompilesAndDetects(t *testing.T) {
	set, rep, err := seclang.Parse("crs.conf", []byte(crs),
		seclang.Options{DefaultConfidence: seclang.High, Prefix: 800000})
	if err != nil {
		t.Fatal(err)
	}

	src, err := seclang.Generate("converted", set, rep)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Logf("generated %d bytes for %d rules", len(src), len(set))

	// It must at least parse as Go. A full build would need a module with the
	// right replace directives, which the repository's own module graph already
	// provides for the packages the output imports.
	if _, err := parser.ParseFile(token.NewFileSet(), "gen.go", src, parser.AllErrors); err != nil {
		t.Fatalf("generated source does not parse: %v\n\n%s", err, src)
	}

	text := string(src)
	for _, want := range []string{
		"package converted",
		"func Ruleset() rules.Set",
		"seclang.MustRegex(",  // @rx survived as a regex
		"sqli.Operator()",     // @detectSQLi became the structural detector
		"xss.Operator()",      // @detectXSS likewise
		"op.ContainsAny(",     // @pm became a literal set
		"transform.URLDecode", // t:urlDecode survived
		"types.PhaseRequestHeaders",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("generated source is missing %q", want)
		}
	}
}

// TestSkippedDirectivesTravelInTheGeneratedFile: what did not come across is
// the part of a migration that matters, so it belongs in the file somebody
// reviews rather than in a log they did not keep.
func TestSkippedDirectivesTravelInTheGeneratedFile(t *testing.T) {
	const src = `
SecRule ARGS "@rx ok" "id:1,phase:2,deny"
SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8" "id:2,phase:1,deny"
SecRule ARGS "@rx a" "id:3,phase:2,chain,deny"
    SecRule ARGS "@rx b" "t:none"
`
	set, rep, err := seclang.Parse("x.conf", []byte(src),
		seclang.Options{DefaultConfidence: seclang.Medium})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Skipped) == 0 {
		t.Fatal("nothing was reported as skipped")
	}

	out, err := seclang.Generate("x", set, rep)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "Not translated") {
		t.Error("the skipped list is absent from the generated file")
	}
	for _, want := range []string{"ipmatch", "conjunction"} {
		if !strings.Contains(strings.ToLower(text), want) {
			t.Errorf("the generated file does not explain %q", want)
		}
	}
}

// TestGenerateRefusesWhatItCannotRender: emitting source that does not compile
// would be the converter's version of silently weakening a rule.
func TestGenerateRefusesWhatItCannotRender(t *testing.T) {
	set := rules.Set{{
		ID:         1,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         unrenderable{},
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.High,
		Msg:        "x",
	}}
	if _, err := seclang.Generate("x", set, seclang.Report{}); err == nil {
		t.Error("an operator with no source rendering was emitted anyway")
	}
}

type unrenderable struct{}

func (unrenderable) Name() string { return "vendor_custom" }
func (unrenderable) Eval(*rules.EvalContext, []byte) (rules.Match, bool) {
	return rules.Match{}, false
}
func (unrenderable) Literals() ([]string, bool) { return nil, false }
func (unrenderable) Cost() types.Fuel           { return 1 }
