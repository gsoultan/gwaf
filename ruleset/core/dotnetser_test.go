// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"testing"

	"github.com/gsoultan/gwaf/rules"
)

var testBFHeader = []byte{
	0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// TestDotNetHeaderSurvivesTextChain pins the claim that lets the rule share
// javaser's chain: a ViewState wrapper whose length varint contains a '%' or a
// '\' byte still matches after percent- and escape-decoding.
func TestDotNetHeaderSurvivesTextChain(t *testing.T) {
	for _, varint := range [][]byte{
		{0x12},
		{'\\'},              // a one-byte length the decode deletes outright
		{0x80 | 0x01, '%'},  // length 0x25<<7 | 1
		{0x80 | 0x01, '\\'}, // length 0x5c<<7 | 1
		{0x80 | 0x25, '%'},
		{0x80 | 0x01, 0x80 | 0x01, '\\'}, // three bytes, the last deleted by the decode
	} {
		v := append(append([]byte{0xff, 0x01, 0x32}, varint...), testBFHeader...)
		v = append(v, "x"...)
		out := v
		for _, tr := range textChain {
			if next, changed := tr.Apply(nil, out); changed {
				out = next
			}
		}
		if _, ok := (dotNetStreamOp{}).Eval(&rules.EvalContext{}, out); !ok {
			t.Errorf("varint % x: header lost to the transform chain (%q)", varint, out)
		}
	}
	if _, ok := (dotNetStreamOp{}).Eval(&rules.EvalContext{}, []byte("/wEPDwUKMTY1NDU2MTA1MmRk")); ok {
		t.Error("an encoded ordinary ViewState matched")
	}
}
