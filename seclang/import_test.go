// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package seclang_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/seclang"
)

// TestPhraseFilesAreInlined covers @pmFromFile, which eighteen Core Rule Set
// rules use and which used to be reported as untranslatable outright.
//
// Two of them are the reason it matters: 930120 carries the LFI filename list
// and 932160 the shell command list, so without this the converted CRS missed
// "../../../../etc/passwd" and "; cat /etc/passwd" entirely while reporting a
// successful import.
func TestPhraseFilesAreInlined(t *testing.T) {
	const src = `
SecRule ARGS "@pmFromFile lfi-os-files.data" \
    "id:930120,phase:2,deny,msg:'LFI'"
`
	data := map[string][]byte{
		"lfi-os-files.data": []byte("# comment\n\netc/passwd\netc/shadow\nproc/self/environ\n"),
	}

	set, rep, err := seclang.Parse("t.conf", []byte(src), seclang.Options{
		DefaultConfidence: seclang.High,
		DataFiles: func(name string) ([]byte, error) {
			b, ok := data[name]
			if !ok {
				return nil, fmt.Errorf("no such file")
			}
			return b, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 {
		t.Fatalf("@pmFromFile did not translate: %s", rep)
	}

	waf, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set))
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/f?p=x", "HTTP/1.1")
	tx.AddArgument("p", "../../../../etc/passwd")
	if d := tx.ProcessRequestBody(); !d.Blocked() {
		t.Error("inlined phrase list did not match a payload it contains")
	}
}

// TestPhraseFileCommentsAndBlanksAreIgnored: a .data file is not a phrase list
// verbatim. An imported "#" or "" would be a phrase matching almost every
// request, which is a false-positive engine rather than a rule.
func TestPhraseFileCommentsAndBlanksAreIgnored(t *testing.T) {
	const src = `SecRule ARGS "@pmFromFile p.data" "id:1,phase:2,deny"`

	set, _, err := seclang.Parse("t.conf", []byte(src), seclang.Options{
		DefaultConfidence: seclang.High,
		DataFiles: func(string) ([]byte, error) {
			return []byte("# a comment\n\n   \nsleep 5\n"), nil
		},
	})
	if err != nil || len(set) != 1 {
		t.Fatalf("set=%d err=%v", len(set), err)
	}

	waf, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set))
	if err != nil {
		t.Fatal(err)
	}
	for _, benign := range []string{"hello world", "a # b", "ordinary text"} {
		tx := waf.NewTransaction()
		tx.SetRequestLine("GET", "/?q=x", "HTTP/1.1")
		tx.AddArgument("q", benign)
		if d := tx.ProcessRequestBody(); d.Blocked() {
			t.Errorf("comment or blank line became a matching phrase: %q blocked", benign)
		}
		tx.Close()
	}
}

// TestPhraseFileNeedsAResolver: with no DataFiles the rule is reported, not
// imported empty. An empty phrase list is a rule that never fires, and the
// operator would believe they had it.
func TestPhraseFileNeedsAResolver(t *testing.T) {
	const src = `SecRule ARGS "@pmFromFile lfi-os-files.data" "id:1,phase:2,deny"`

	set, rep, err := seclang.Parse("t.conf", []byte(src), seclang.Options{
		DefaultConfidence: seclang.High,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 0 {
		t.Fatal("imported a phrase list it could not read")
	}
	if len(rep.Skipped) != 1 || !strings.Contains(rep.Skipped[0].Why, "DataFiles") {
		t.Errorf("skip does not name the fix: %s", rep)
	}
}

// TestUnexpandedMacroIsNotImportedAsText is the difference between a weakened
// rule and a dead one.
//
// CRS 911100 is "REQUEST_METHOD !@within %{tx.allowed_methods}". Imported
// literally it matches the text "%{tx.allowed_methods}", which no request
// contains, so method enforcement silently enforces nothing. Reported instead.
func TestUnexpandedMacroIsNotImportedAsText(t *testing.T) {
	const src = `
SecRule REQUEST_METHOD "@within %{tx.allowed_methods}" \
    "id:911100,phase:1,deny,msg:'Method not allowed'"
`
	set, rep, err := seclang.Parse("t.conf", []byte(src), seclang.Options{
		DefaultConfidence: seclang.High,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 0 {
		t.Fatal("imported a rule whose operator argument is an unexpanded macro")
	}
	if len(rep.Skipped) != 1 {
		t.Fatalf("expected one skip, got %s", rep)
	}
	if !strings.Contains(rep.Skipped[0].Why, "%{tx.allowed_methods}") {
		t.Errorf("skip does not name the macro: %s", rep.Skipped[0])
	}
}

// TestSkipsNameTheFileTheyCameFrom: a migration report is read by whoever has to
// tune it. The CLI used to concatenate every input and pass the joined list as
// one name, so all twenty-seven CRS files shared a location and the line numbers
// were offsets into a buffer that existed nowhere on disk.
func TestSkipsNameTheFileTheyCameFrom(t *testing.T) {
	srcs := []seclang.Source{
		{Name: "a.conf", Data: []byte("SecRule ARGS \"@rx ok\" \"id:1,phase:2,deny\"\n")},
		{Name: "b.conf", Data: []byte("\n\nSecRule ARGS \"@rx x\" \"id:2,phase:2,deny,t:md5\"\n")},
	}

	set, rep, err := seclang.ParseSources(srcs, seclang.Options{DefaultConfidence: seclang.High})
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 {
		t.Fatalf("expected the translatable rule to survive, got %d", len(set))
	}
	if len(rep.Skipped) != 1 {
		t.Fatalf("expected one skip, got %s", rep)
	}
	if got := rep.Skipped[0]; got.File != "b.conf" || got.Line != 3 {
		t.Errorf("skip located at %s:%d, want b.conf:3", got.File, got.Line)
	}
}

// TestStateCarriesAcrossSources: SecLang is stateful between files, so parsing
// them separately must not lose what one file sets for the next.
// SecRuleRemoveById in particular routinely appears after the include defining
// the rule it disables, and importing a rule the operator explicitly removed is
// a false positive nobody asked for.
func TestStateCarriesAcrossSources(t *testing.T) {
	srcs := []seclang.Source{
		{Name: "rules.conf", Data: []byte(`
SecRule ARGS "@rx attack" "id:100,phase:2,deny"
SecRule ARGS "@rx other" "id:101,phase:2,deny"
`)},
		{Name: "exclusions.conf", Data: []byte("SecRuleRemoveById 100\n")},
	}

	set, _, err := seclang.ParseSources(srcs, seclang.Options{DefaultConfidence: seclang.High})
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 {
		t.Fatalf("expected 1 rule after removal, got %d", len(set))
	}
	if set[0].ID != 101 {
		t.Errorf("kept rule %d, expected the removal to drop 100", set[0].ID)
	}
}
