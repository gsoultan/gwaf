// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"github.com/gsoultan/gwaf/internal/body"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// DotNetSerializedRule reports a .NET BinaryFormatter object stream in a
// request value: bare, or as the top-level object of an ObjectStateFormatter
// (ViewState / LosFormatter) payload.
//
// # Why structural rather than a gadget list
//
// IDJavaGadgetClass names the ysoserial.net classes, and that catches the
// gadgets whose class names survive into the request as text. The ones that
// matter most do not: ActivitySurrogateSelector ships a compiled assembly, and
// watchTowr's write-up of Idunno.AntiCsrf CVE-2026-131914 (KEV, 2026-11-24)
// describes exactly that, "creative .NET compiled gadget payloads", in a
// base64 form field. A list is always one gadget behind; the stream header is
// not, because every BinaryFormatter graph begins with the same record and
// Microsoft has removed BinaryFormatter from .NET 9 for this reason. A client
// handing a server one is the attack, whichever class it names.
//
// # What it does not match
//
// An ordinary ViewState. A page's own state starts with a Pair or Triplet
// token, and a [Serializable] object a control stored in it is binary-
// serialized *inside* that structure, not at the top. The ysoserial.net
// ViewState plugin puts the gadget at the top because the gadget is the whole
// graph, which is the shape matched here. The header is required at offset 0
// of the value for the same reason: searched anywhere, seventeen bytes would
// still eventually turn up in random uploads.
//
// The value this reads is produced by the transaction, which records the
// header of a decoded base64 field or a raw body as its own value before the
// binary is split into printable runs (see recordSerializedStream).
func DotNetSerializedRule(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:      id,
		Phase:   types.PhaseRequestHeaders,
		Targets: argTargets,
		// textChain, shared with detect/javaser, rather than no transform. The
		// engine scans each value once per distinct chain, so a rule with a
		// chain of its own adds a pass over every value of every request; a
		// benign JSON POST measured 14% slower with it. The header's fixed bytes
		// hold no '%' or '\', so neither decode can touch them. A ViewState's
		// length varint can, since its bytes are whatever the gadget's size makes
		// them, which is why body.IsDotNetStream looks for the header across the
		// varint's possible offsets instead of parsing it
		// (TestDotNetHeaderSurvivesTextChain).
		Transforms: textChain,
		Op:         dotNetStreamOp{},
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		// High, matching the Java stream signal in detect/javaser: the header is
		// unambiguous, but a legacy .NET Remoting client does send these on
		// purpose, and only calibration on a deployment's traffic can say it
		// never will.
		Confidence: types.High,
		Msg:        ".NET serialized object stream in request value",
		Tags:       []string{"rce", "deserialization", "dotnet", "owasp-a08"},
	}
}

type dotNetStreamOp struct{}

func (dotNetStreamOp) Name() string { return "dotnet_serialized_stream" }

func (dotNetStreamOp) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	if !body.IsDotNetStream(value) {
		return rules.Match{}, false
	}
	return rules.Match{Span: types.SpanOf(0, min(len(value), 32))}, true
}

// Literals is honest: both recognized shapes contain the BinaryFormatter
// header's first nine bytes, so a value without them cannot match.
func (dotNetStreamOp) Literals() ([]string, bool) {
	return []string{"\x00\x01\x00\x00\x00\xff\xff\xff\xff"}, true
}

func (dotNetStreamOp) Cost() types.Fuel { return types.CostLiteralMatch }
