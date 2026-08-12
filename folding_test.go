package gwaf_test

import (
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/types"
)

func TestConstantFolding(t *testing.T) {
	w := newWAF(t)
	wide := newWAF(t, gwaf.WithMinConfidence(types.Medium))
	for _, tc := range []struct {
		name, arg string
		want      bool
	}{
		{"php concat call", `('sys'.'tem')('id')`, true},
		// Folds to system('id'), which is Medium by the tier decision in
		// TestMediumTierIsOptInAndReachable. The folding is what makes it
		// visible at all; which tier acts on it is a separate, settled question.
		{"php concat bare", `'sys'.'tem'('id')`, false},
		{"php assert concat", `assert('sys'.'tem(\'id\')')`, false},
		{"php hex escapes", `"\x73\x79\x73\x74\x65\x6d"('id')`, true},
		{"php octal escapes", `"\163\171\163\164\145\155"('id')`, true},
		{"js bracket concat", `window['ale'+'rt'](1)`, true},
		{"js three way concat", `window['al'+'er'+'t'](document.cookie)`, true},
		// Must not invent text nobody sent.
		{"property access", `user.name`, false},
		{"quoted prose", `"the system is down"`, false},
		{"sum of numbers", `1 + 2`, false},
		{"json-ish value", `{"a":"x","b":"y"}`, false},
		{"sql string concat benign", `'Smith' || ' & Sons'`, false},
		{"path with dots", `reports/2026.q1.pdf`, false},
	} {
		tx := w.NewTransaction()
		tx.SetRequestLine("GET", "/x", "HTTP/1.1")
		tx.SetRemoteAddr("192.0.2.1")
		tx.AddArgument("p", tc.arg)
		d := tx.ProcessRequestHeaders()
		if d.Blocked() != tc.want {
			t.Errorf("%-22s blocked=%v want=%v interp=%s  %s",
				tc.name, d.Blocked(), tc.want, d.Interpretation(), tc.arg)
		}
		tx.Close()
	}

	// The two folded forms that land in the Medium tier must be reachable
	// there, or the folding has made them visible to nothing.
	for _, arg := range []string{`'sys'.'tem'('id')`, `assert('sys'.'tem(\'id\')')`} {
		tx := wide.NewTransaction()
		tx.SetRequestLine("GET", "/x", "HTTP/1.1")
		tx.SetRemoteAddr("192.0.2.1")
		tx.AddArgument("p", arg)
		if d := tx.ProcessRequestHeaders(); !d.Blocked() {
			t.Errorf("Medium tier did not block %s; the folded reading reaches nothing", arg)
		}
		tx.Close()
	}
}
