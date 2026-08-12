// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// PathSinkRule reports a traversal segment or a local-file scheme in a
// parameter the application resolves as a filesystem path.
//
// # Why the core traversal rules do not catch these
//
// They require two levels — the declared literals are "../..", `..\..`,
// "..%2f.." and `..%5c..` — because one is genuinely ambiguous. A single "../"
// appears in relative references all over ordinary software, and a core rule
// matching it would fire on template paths, import statements and git-style
// references. Two levels is the point where the value stops looking like a
// relative path and starts looking like an escape.
//
// The corpus disagrees with that only when the *parameter name* says the value
// is a path. Of the 45 LFI misses, eighteen were a single level:
//
//	path=../backup/auto.php
//	filePath=../conf/datasourceCtp.properties
//	fpath=../ecology/WEB-INF/web.xml
//	filename=../appsettings.json
//	lang=../
//
// One "../" is ambiguous in a value. In a parameter called filePath it is not:
// the application is going to resolve it, and resolving it leaves the directory
// the application meant. That is the same key-anchored shape as SSRFParamRule
// and SQLSinkRule — the name carries half the evidence, so this rule reads
// ctx.Key.
//
// # Why file:// is here and not in the SSRF scheme rule
//
// It was deliberately left out of rule 11002, on the reasoning that "the
// local-file case is already covered by the traversal and sensitive-file
// rules". The corpus falsifies that: "source":"file:///etc/" carries no
// traversal and names no sensitive file, and it walked through three times.
//
// The original concern was real and is answered by scoping rather than by
// dropping it. The benign corpus contains three values like
//
//	jar:file:///opt/build/app-1.jar!/META-INF/MANIFEST.MF
//
// under an "artifact" key — Java build tooling, which is exactly the false
// positive that got "jar:" removed from the scheme list. "artifact" is not a
// path sink, so this rule never sees them.
//
// # Why it is opt-in
//
// A file manager navigates with "../" because navigating is the product, and a
// CMS resolves template paths relative to a theme directory. Whether *this*
// application resolves user-supplied paths by design is something the embedder
// knows and gwaf cannot learn from one request — the Ownership test in
// CLAUDE.md §1, and the same reason SSRFParamRule and SQLSinkRule ship
// exported rather than enabled.
//
//	waf, err := gwaf.New(gwaf.WithRuleset(
//	    WithBodyPhase(rules.Set{core.PathSinkRule(1017)}),
//	))
func PathSinkRule(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:    id,
		Phase: types.PhaseRequestHeaders,
		// Arguments only: the parameter name is half the evidence, so an
		// unkeyed collection can never match.
		Targets: []types.Target{{Kind: types.TargetArgs}},
		// decodeChain rather than pathChain: NormalizePath resolves "../" away,
		// which is the entire signal. Percent-decoding is required, because
		// ".%2F..%2Fvendor" is how the corpus spells it.
		Transforms: decodeChain,
		Op:         pathSinkTraversal(),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.High,
		Msg:        "Path traversal or local-file scheme in a path parameter",
		Tags:       []string{"lfi", "traversal", "owasp-a01", "opt-in"},
	}
}

// pathSinkParams are parameter names the application resolves as a path.
//
// "page", "target", "name" and "id" are deliberately absent: each is a name
// ordinary forms use for something that is not a path, and a rule that reads
// them is a rule about every form on the site rather than about file access.
var pathSinkParams = setOf(
	"path", "filepath", "file_path", "fpath", "filename", "file_name",
	"file", "dir", "directory", "folder", "resourcepath", "resource_path",
	"template", "include", "doc", "docpath", "savepath", "save_path",
	"uploadpath", "upload_path", "downloadpath", "download_path",
	"source", "src", "load", "read", "attachment", "mailattach",
)

func pathSinkTraversal() rules.Operator { return pathSinkOp{} }

type pathSinkOp struct{}

func (pathSinkOp) Name() string { return "path_sink_traversal" }

func (pathSinkOp) Eval(ctx *rules.EvalContext, value []byte) (rules.Match, bool) {
	// Argument names are themselves a target, and a name is not a path.
	if ctx == nil || ctx.Target.Kind == types.TargetArgNames {
		return rules.Match{}, false
	}
	if !matchesParam(ctx.Key, pathSinkParams) {
		return rules.Match{}, false
	}
	if indexOfFold(value, "file://") >= 0 {
		return rules.WholeValue(value), true
	}
	if hasDotDotSegment(value) {
		return rules.WholeValue(value), true
	}
	return rules.Match{}, false
}

// hasDotDotSegment reports whether value contains ".." as a whole path segment.
//
// The boundary test is what separates a traversal from a filename: "a..b" is a
// version range, "file..txt" is a typo, and "v1.2..v1.3" is a git revision
// range — none of them leaves a directory. Only ".." delimited by a separator
// or the ends of the value does.
func hasDotDotSegment(v []byte) bool {
	for i := 0; i+1 < len(v); i++ {
		if v[i] != '.' || v[i+1] != '.' {
			continue
		}
		if i > 0 && !isPathSep(v[i-1]) {
			continue
		}
		if i+2 < len(v) && !isPathSep(v[i+2]) {
			continue
		}
		return true
	}
	return false
}

func isPathSep(c byte) bool { return c == '/' || c == '\\' }

// Literals is an honest assertion: every branch needs either ".." or the
// local-file scheme as a substring, so a value carrying neither cannot match.
func (pathSinkOp) Literals() ([]string, bool) {
	return []string{"..", "file://"}, true
}

func (pathSinkOp) Cost() types.Fuel { return types.CostLiteralMatch }
