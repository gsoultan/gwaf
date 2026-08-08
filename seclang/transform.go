// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package seclang

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/transform"
)

// secTransform is one SecLang transformation gwaf can express: the spellings
// ModSecurity accepts for it, the transform the compiler emits, and the
// identifier Generate has to write to name that transform in Go source.
//
// All three live in one row because they used to live in two tables and drifted.
// The compiler accepted t:jsDecode and emitted transform.EscapeDecode;
// generate.go kept its own switch and had no case for it. So `report` counted
// the rule as translated and `convert` then failed on it — and since CRS rule
// 932210 uses t:jsDecode, that was every real conversion of the Core Rule Set.
// A table cannot disagree with itself.
type secTransform struct {
	// tokens are the SecLang spellings, lowercased, that select this transform.
	tokens []string
	// tf is what the compiler puts in the rule.
	tf rules.Transform
	// goName is the exported identifier in rules/transform. It is written into
	// generated source as "transform."+goName, so it has to match the variable
	// name rather than tf.Name(), which is the runtime name and uses snake_case.
	goName string
}

// secTransforms is the whole of what SecLang transformations translate to.
//
// Adding a transform here is what makes it importable *and* renderable at once,
// which is the point of the single table.
var secTransforms = []secTransform{
	{tokens: []string{"lowercase"}, tf: transform.Lowercase, goName: "Lowercase"},
	{tokens: []string{"urldecode", "urldecodeuni"}, tf: transform.URLDecode, goName: "URLDecode"},
	{tokens: []string{"removewhitespace"}, tf: transform.RemoveWhitespace, goName: "RemoveWhitespace"},
	{tokens: []string{"compresswhitespace"}, tf: transform.CompressWhitespace, goName: "CompressWhitespace"},
	{tokens: []string{"normalizepath", "normalizepathwin", "normalisepath"}, tf: transform.NormalizePath, goName: "NormalizePath"},
	{tokens: []string{"jsdecode", "escapeseqdecode"}, tf: transform.EscapeDecode, goName: "EscapeDecode"},
}

// transformFor maps a lowercased SecLang transformation token to the transform
// the compiler should apply.
func transformFor(token string) (rules.Transform, bool) {
	for _, e := range secTransforms {
		for _, t := range e.tokens {
			if t == token {
				return e.tf, true
			}
		}
	}
	return nil, false
}

// transformConst maps a transform's runtime name to the exported identifier
// Generate writes. It is the reverse of the same table transformFor reads, so a
// transform the compiler can emit always has a name to render it with.
func transformConst(name string) (string, bool) {
	for _, e := range secTransforms {
		if e.tf.Name() == name {
			return e.goName, true
		}
	}
	return "", false
}

// droppedTransforms are transformations that translate faithfully to nothing.
//
// A transform rewrites the value once and matches the result, which is the
// single-interpretation model CVE-2026-21876 exploited. gwaf instead evaluates
// every plausible decoding and matches if the rule matches under any of them, so
// for these the decoded form is already in front of the rule:
//
//   - utf8toUnicode and htmlEntityDecode are readings (interpret.ClassOverlongUTF8,
//     interpret.ClassHTMLEntity). Applying them as transforms as well would
//     narrow the rule to that one reading.
//   - removeNulls: interpret.ClassNullTruncate already evaluates the value as a
//     C-backed origin would truncate it.
//   - trim and friends change only leading and trailing whitespace, and every
//     operator gwaf offers is position-independent.
//
// This is deliberately not a place to put a transform that is merely
// inconvenient. t:cmdLine, t:cssDecode, t:replaceComments and t:base64Decode are
// covered by gwaf's own detectors rather than by canonicalization, which does
// nothing for an imported regex — dropping them would make the imported rule
// narrower with no compensation, so they stay reported instead.
var droppedTransforms = []string{
	"trim", "trimleft", "trimright",
	"removenulls",
	"utf8tounicode", "htmlentitydecode",
}

func isDroppedTransform(token string) bool {
	for _, t := range droppedTransforms {
		if t == token {
			return true
		}
	}
	return false
}
