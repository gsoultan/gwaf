// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package ldapi

import (
	"strings"
	"testing"
)

func TestFilterInjectionIsDetected(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    Signal
	}{
		// The authentication bypass: close the clause, open a satisfied OR.
		{"classic or bypass", "*)(uid=*))(|(uid=*", SignalInjectedClause},
		{"and close", "admin)(&))", SignalInjectedClause},
		{"objectclass wildcard", "*)(|(objectClass=*", SignalInjectedClause},
		{"password blind", "admin)(|(userPassword=*", SignalInjectedClause},
		{"not clause", "x)(!(uid=admin", SignalInjectedClause},

		// Nested clause injection.
		{"nested and", "a)(&(uid=admin)(cn=*", SignalInjectedClause},
		{"double close", "x))(|(cn=*", SignalInjectedClause},

		// NUL truncation drops whatever the application appended.
		{"literal nul", "admin\x00)(uid=*", SignalNullByte},
		{"escaped nul", `admin\00`, SignalNullByte},
	}

	d := New()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := d.Analyze([]byte(c.payload))
			if !v.Detected() {
				t.Errorf("not detected: score=%d signals=%v", v.Score, v.Signals)
			}
			if v.Signals&c.want == 0 {
				t.Errorf("signals = %v, want %v set", v.Signals, c.want)
			}
		})
	}
}

// TestBenignTextPasses is the counterweight. Parentheses, ampersands, pipes,
// and asterisks are all ordinary; only their combination in filter position is
// evidence, and this table is what holds the detector to that.
func TestBenignTextPasses(t *testing.T) {
	values := []string{
		// Balanced parentheses in ordinary text.
		"Smith & Sons (Ltd)",
		"see (note 4) for details",
		"the total (including tax) is 42.00",
		"function(a, b) { return a + b }",
		"(0800) 555-0100",
		"Ac(cent)ed (né(sted))",

		// Operators without filter structure.
		"a|b|c",
		"Tom & Jerry",
		"true && false",
		"price > 10 & price < 20",
		"!important",

		// Wildcards a user typed on purpose.
		"*",
		"search*",
		"*.log",
		"a*b*c",
		"SELECT * FROM",

		// Real names and identifiers that contain the vocabulary.
		"O'Brien (Sales)",
		"uid=alice",
		"cn=Alice Smith,ou=People,dc=example,dc=com",
		"(&(objectClass=person))",

		// Ordinary values.
		"alice@example.com",
		"admin",
		"",
	}

	d := New()
	for _, v := range values {
		t.Run(v, func(t *testing.T) {
			if got := d.Analyze([]byte(v)); got.Detected() {
				t.Errorf("false positive: score=%d signals=%v", got.Score, got.Signals)
			}
		})
	}
}

// TestThresholdRequiresAnInjectedClause is the property the declared literals
// depend on, stated directly rather than left to emerge from the weights.
//
// The fuzz harness found "*)" scoring 5 under an earlier weighting, with no
// literal covering it -- so the prefilter would have dropped the value and the
// rule could never have fired. Any future reweighting that breaks this breaks
// the prefilter silently, which is why it is asserted here too.
func TestThresholdRequiresAnInjectedClause(t *testing.T) {
	d := New()
	for _, v := range []string{"*)", "=*)", "a*)", "*))", "uid=*"} {
		got := d.Analyze([]byte(v))
		if got.Detected() {
			t.Errorf("%q reached the threshold without an injected clause: %v",
				v, got.Signals)
		}
	}
}

// TestBalanceAloneIsNotEnough is the design as a test. An unbalanced
// parenthesis is common in text — a smiley, a truncated quote — so it must not
// fire without a clause being opened alongside it.
func TestBalanceAloneIsNotEnough(t *testing.T) {
	d := New()
	for _, v := range []string{
		"unbalanced (paren",
		"closing only)",
		"a :) smiley",
		"((((",
		"))))",
	} {
		got := d.Analyze([]byte(v))
		if got.Detected() {
			t.Errorf("%q fired on balance alone: %v", v, got.Signals)
		}
	}
	// And a clause without any imbalance is equally not enough: a complete,
	// well-formed filter is what an application sends itself.
	if got := d.Analyze([]byte("(&(objectClass=person)(uid=alice))")); got.Detected() {
		t.Errorf("a balanced filter fired: %v", got.Signals)
	}
}

// TestClauseBoundaryIsSeenEvenWhenCountsMatch covers ")(", which balances by
// count and is still a clause boundary the value had no business containing.
func TestClauseBoundaryIsSeenEvenWhenCountsMatch(t *testing.T) {
	d := New()
	v := d.Analyze([]byte("a)(uid=*)(b"))
	if !v.Detected() {
		t.Errorf("clause boundary missed: score=%d signals=%v", v.Score, v.Signals)
	}
}

func TestBounds(t *testing.T) {
	d := New()
	if d.Analyze(nil).Detected() {
		t.Error("nil detected")
	}
	if d.Analyze([]byte(strings.Repeat("(", 100000))).Detected() {
		t.Error("repeated parentheses reached the threshold")
	}
	long := strings.Repeat("a", maxScan*2) + ")(uid=*"
	if d.Analyze([]byte(long)).Detected() {
		t.Error("a payload past the scan bound was reported")
	}
}

// FuzzLiteralsAreExhaustive enforces the claim the prefilter depends on.
func FuzzLiteralsAreExhaustive(f *testing.F) {
	for _, s := range []string{
		"*)(uid=*))(|(uid=*", "admin)(&))", `admin\00`, "admin\x00",
		"Smith & Sons (Ltd)", "", "(", ")", ")(", "(|", "*", "=*",
	} {
		f.Add(s)
	}

	d := New()
	lits, _ := Operator().(*operator).Literals()

	f.Fuzz(func(t *testing.T, value string) {
		if !d.Analyze([]byte(value)).Detected() {
			return
		}
		for _, l := range lits {
			if strings.Contains(value, l) {
				return
			}
		}
		t.Fatalf("detected %q but no literal covers it: the prefilter would drop it", value)
	})
}

func BenchmarkAnalyzeBenign(b *testing.B) {
	d := New()
	v := []byte("cn=Alice Smith,ou=People,dc=example,dc=com")
	b.ReportAllocs()
	for b.Loop() {
		d.Analyze(v)
	}
}

func BenchmarkAnalyzeAttack(b *testing.B) {
	d := New()
	v := []byte("*)(uid=*))(|(uid=*")
	b.ReportAllocs()
	for b.Loop() {
		d.Analyze(v)
	}
}
