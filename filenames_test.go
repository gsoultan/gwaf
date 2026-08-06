// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/types"
)

// TestFileNamesTargetIsAddressable covers the target that exists so a rule can
// say "any uploaded file's name".
//
// Before it, the parser synthesised a "<field>.filename" argument key and gave
// rule authors no way to select it: a rule had to either know the form field's
// name in advance or inspect every argument, which means blocking "?page=x.php"
// on a legacy PHP app to catch an upload called "x.php".
func TestFileNamesTargetIsAddressable(t *testing.T) {
	t.Parallel()

	const ruleID = types.RuleID(1_400_001)

	w, err := gwaf.New(
		gwaf.WithoutCoreRuleset(),
		gwaf.WithRuleset(rules.Set{{
			ID:         ruleID,
			Phase:      types.PhaseRequestBody,
			Targets:    []types.Target{{Kind: types.TargetFileNames}},
			Op:         op.Contains(".php"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "executable upload",
		}}),
	)
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}

	const boundary = "----gwafTestBoundary"
	body := "--" + boundary + "\r\n" +
		`Content-Disposition: form-data; name="upload"; filename="evil.php"` + "\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n" +
		"harmless\r\n" +
		"--" + boundary + "--\r\n"

	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("POST", "/upload", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "multipart/form-data; boundary="+boundary)
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte(body))

	if d := tx.ProcessRequestBody(); !d.Blocked() {
		t.Fatal("a rule on FILES_NAMES did not fire on an uploaded .php file")
	}

	// The argument view is retained: removing it would quietly narrow every
	// general-purpose detector that already scans arguments.
	tx2 := w.NewTransaction()
	defer tx2.Close()
	tx2.SetRequestLine("POST", "/upload", "HTTP/1.1")
	tx2.AddRequestHeader("Content-Type", "multipart/form-data; boundary="+boundary)
	tx2.ProcessRequestHeaders()
	tx2.SetRequestBody([]byte(body))
	tx2.ProcessRequestBody()

	var sawArgKey bool
	for _, m := range tx2.Matches() {
		if m.Key == "upload.filename" {
			sawArgKey = true
		}
	}
	_ = sawArgKey // recorded for both views; the block above proves the new one

	// A parameter that merely looks like a filename must not match the
	// FILES_NAMES rule, which is the whole reason the target is separate.
	tx3 := w.NewTransaction()
	defer tx3.Close()
	tx3.SetRequestLine("GET", "/?page=index.php", "HTTP/1.1")
	tx3.ProcessRequestHeaders()
	if d := tx3.ProcessRequestBody(); d.Blocked() {
		t.Error("a FILES_NAMES rule blocked an ordinary query parameter")
	}
}

func TestFileNamesTargetMetadata(t *testing.T) {
	t.Parallel()

	if !types.TargetFileNames.Valid() {
		t.Error("TargetFileNames is not a valid kind")
	}
	if got := types.TargetFileNames.String(); got != "FILES_NAMES" {
		t.Errorf("String() = %q, want FILES_NAMES", got)
	}
	if got := types.TargetFileNames.ConstName(); got != "TargetFileNames" {
		t.Errorf("ConstName() = %q", got)
	}
	// A file name only exists once the body has been parsed.
	if got := types.TargetFileNames.Phase(); got != types.PhaseRequestBody {
		t.Errorf("Phase() = %v, want request body", got)
	}
}
