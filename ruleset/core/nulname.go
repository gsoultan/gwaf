// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// rawNullInFilename reports a NUL byte in a client-supplied file name.
//
// # Why the encoded-only rule was not enough
//
// IDNullByteInjection matches "%00" *before* percent-decoding, and its reasoning
// is careful and correct as far as it goes: decoded, a NUL is indistinguishable
// from the NULs that fill ordinary binary upload content, while encoded it is a
// deliberate act no client emits.
//
// That argument holds for values in general and not for file names. A red-team
// pass sent both spellings of the classic upload bypass:
//
//	filename="a.php%00.jpg"   blocked
//	filename="a.php\x00.jpg"  passed
//
// The raw form is the one that reaches a vulnerable origin. An attacker writing
// a multipart part by hand has no reason to percent-encode the byte at all —
// the multipart header is not percent-decoded, so encoding it there would
// *prevent* the truncation the attack depends on. gwaf was catching the
// spelling that does not work and missing the one that does.
//
// # Why this does not reintroduce the false positive
//
// The exemption exists for binary *content*, and this rule is scoped to
// TargetFileNames, which carries nothing else. Every byte of every upload is
// untouched. There is no legitimate NUL in a file name: no filesystem accepts
// one, and no browser emits one.
//
// The target matters for a second reason, found while fixing this. A file name
// containing a NUL *is* binary by IsBinary's reckoning, so the argument view of
// it goes through printable-run extraction and arrives as "a.php" and ".jpg" --
// two clean fragments with the evidence between them removed. TargetFileNames
// is recorded before that split and keeps the name whole, which is the only
// place the byte still exists.
func rawNullInFilename() rules.Operator { return nulFilenameOp{} }

type nulFilenameOp struct{}

func (nulFilenameOp) Name() string { return "raw_null_in_filename" }

func (nulFilenameOp) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	for i, c := range value {
		if c == 0 {
			return rules.Match{Span: types.SpanOf(i, 1)}, true
		}
	}
	return rules.Match{}, false
}

// Literals is an honest assertion: the operator matches only on a NUL byte, so
// a value without one cannot match.
func (nulFilenameOp) Literals() ([]string, bool) { return []string{"\x00"}, true }

func (nulFilenameOp) Cost() types.Fuel { return types.CostLiteralMatch }
