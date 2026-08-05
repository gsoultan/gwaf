// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

import (
	"strings"
	"testing"
)

// ---- wire-format builders ----------------------------------------------------

func varint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func tag(field, wire int) []byte { return varint(uint64(field)<<3 | uint64(wire)) }

func pbString(field int, s string) []byte {
	out := tag(field, wireBytes)
	out = append(out, varint(uint64(len(s)))...)
	return append(out, s...)
}

func pbBytes(field int, b []byte) []byte {
	out := tag(field, wireBytes)
	out = append(out, varint(uint64(len(b)))...)
	return append(out, b...)
}

func pbVarint(field int, v uint64) []byte {
	return append(tag(field, wireVarint), varint(v)...)
}

func pbFixed64(field int) []byte {
	return append(tag(field, wireFixed64), 1, 2, 3, 4, 5, 6, 7, 8)
}

func pbFixed32(field int) []byte {
	return append(tag(field, wireFixed32), 1, 2, 3, 4)
}

// collect parses a message and returns name→value pairs.
func collect(t *testing.T, data []byte) map[string]string {
	t.Helper()
	var p Parser
	p.Reset(Limits{MaxFields: 1000, MaxValueLen: 1 << 20, MaxTotalSize: 1 << 20})

	out := map[string]string{}
	ok := p.ParseProtobuf(nil, data, func(name, value []byte, _ Kind) bool {
		out[string(name)] = string(value)
		return true
	})
	if !ok {
		t.Fatalf("ParseProtobuf reported malformed input")
	}
	return out
}

func TestIsProtobuf(t *testing.T) {
	yes := [][]byte{
		pbString(1, "hello"),
		pbVarint(1, 42),
		append(pbVarint(1, 1), pbString(2, "x")...),
		pbFixed64(3),
		pbFixed32(4),
		pbBytes(5, pbString(1, "nested")),
	}
	for i, b := range yes {
		if !IsProtobuf(b) {
			t.Errorf("case %d: valid message rejected", i)
		}
	}

	// Strict: a loose check would claim ordinary bodies and slice them apart.
	no := [][]byte{
		nil,
		{},                                       // an empty message is zero bytes; claiming it claims every empty body
		[]byte(`{"a":1}`),                        // JSON
		[]byte("a=1&b=2"),                        // form
		[]byte("hello world"),                    // prose
		{0x00, 0x01},                             // field number 0 is reserved
		append(tag(1, wireBytes), varint(99)...), // declared length overruns
		tag(1, wireStartGroup),                   // groups are not proto3
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // over-long varint
	}
	for i, b := range no {
		if IsProtobuf(b) {
			t.Errorf("case %d: %v claimed as protobuf", i, b)
		}
	}
}

// TestFieldsAreNamedByNumberPath is what lets a descriptor type a field without
// the parser ever needing one.
func TestFieldsAreNamedByNumberPath(t *testing.T) {
	msg := append(pbString(3, "alice"), pbString(7, "hunter2")...)
	got := collect(t, msg)

	if got["3"] != "alice" {
		t.Errorf("m.3 = %q, want alice", got["3"])
	}
	if got["7"] != "hunter2" {
		t.Errorf("m.7 = %q, want hunter2", got["7"])
	}
}

func TestNestedMessagesRecurse(t *testing.T) {
	inner := append(pbString(1, "inner-value"), pbString(2, "second")...)
	msg := pbBytes(4, inner)

	got := collect(t, msg)
	if got["4.1"] != "inner-value" {
		t.Errorf("m.4.1 = %q, want inner-value (nested field not reached)", got["4.1"])
	}
	if got["4.2"] != "second" {
		t.Errorf("m.4.2 = %q", got["4.2"])
	}
}

// TestNumbersAreNotEmitted: no sequence of varints or fixed-width values is an
// injection, so handing them to a text detector is work with no possible payoff.
func TestNumbersAreNotEmitted(t *testing.T) {
	msg := pbVarint(1, 12345)
	msg = append(msg, pbFixed64(2)...)
	msg = append(msg, pbFixed32(3)...)
	msg = append(msg, pbString(4, "only-this-one")...)

	got := collect(t, msg)
	if len(got) != 1 {
		t.Errorf("emitted %d values, want 1: %v", len(got), got)
	}
	if got["4"] != "only-this-one" {
		t.Errorf("m.4 = %q", got["4"])
	}
}

// TestShortFieldsAreNotDropped is the coverage gap this parser closes. Printable
// -run extraction drops anything below minTextRun, which is right for a JPEG and
// wrong for a document made of fields.
func TestShortFieldsAreNotDropped(t *testing.T) {
	const payload = "'OR 1=1" // 7 bytes, below minTextRun
	got := collect(t, pbString(2, payload))

	if got["2"] != payload {
		t.Errorf("a %d-byte field was dropped: %v", len(payload), got)
	}
}

// TestAmbiguousLengthDelimitedTakesBothReadings covers the one place the wire
// format is genuinely undecidable: a string and a nested message look the same.
func TestAmbiguousLengthDelimitedTakesBothReadings(t *testing.T) {
	// Bytes that parse as a message *and* read as text.
	inner := pbString(1, "payload-here")
	got := collect(t, pbBytes(9, inner))

	if got["9.1"] != "payload-here" {
		t.Errorf("the nested reading was not taken: %v", got)
	}
	// The outer value is emitted too when it is not binary, so a string that
	// happens to parse as a message is still inspected as a string.
	if _, ok := got["9"]; !ok {
		t.Errorf("the string reading was not taken: %v", got)
	}
}

func TestMalformedIsReported(t *testing.T) {
	var p Parser
	p.Reset(Limits{MaxFields: 100, MaxValueLen: 1 << 20, MaxTotalSize: 1 << 20})

	// A length that overruns the buffer.
	bad := append(tag(1, wireBytes), varint(500)...)
	bad = append(bad, "short"...)

	if p.ParseProtobuf(nil, bad, func([]byte, []byte, Kind) bool { return true }) {
		t.Error("malformed input reported as parsed; the caller would skip it " +
			"instead of falling back to whole-message inspection")
	}
}

func TestDepthIsBounded(t *testing.T) {
	// Nest far past the ceiling.
	msg := pbString(1, "deep")
	for range maxProtoDepth * 4 {
		msg = pbBytes(1, msg)
	}

	var p Parser
	p.Reset(Limits{MaxFields: 100000, MaxValueLen: 1 << 20, MaxTotalSize: 1 << 20})
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.ParseProtobuf(nil, msg, func([]byte, []byte, Kind) bool { return true })
	}()
	<-done
}

func TestFieldLimitIsHonoured(t *testing.T) {
	var msg []byte
	for i := 1; i <= 200; i++ {
		msg = append(msg, pbString(i, "value")...)
	}

	var p Parser
	p.Reset(Limits{MaxFields: 10, MaxValueLen: 1 << 20, MaxTotalSize: 1 << 20})

	n := 0
	p.ParseProtobuf(nil, msg, func([]byte, []byte, Kind) bool {
		n++
		return true
	})
	if n > 10 {
		t.Errorf("emitted %d fields, limit is 10", n)
	}
}

// FuzzParseProtobuf is non-negotiable: this parses attacker-declared lengths and
// recurses on attacker-controlled nesting.
func FuzzParseProtobuf(f *testing.F) {
	f.Add(pbString(1, "hello"))
	f.Add(pbBytes(2, pbString(1, "nested")))
	f.Add(append(pbVarint(1, 1), pbFixed64(2)...))
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte{0x00, 0x01})
	f.Add([]byte(nil))
	f.Add([]byte{0x0a, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F})

	f.Fuzz(func(t *testing.T, data []byte) {
		var p Parser
		p.Reset(Limits{MaxFields: 256, MaxValueLen: 1 << 16, MaxTotalSize: 1 << 16})

		// Findings are collected rather than asserted inside the callback.
		// t.Fatal calls runtime.Goexit, and unwinding out of a recursive parser
		// callback wedges a fuzz worker rather than reporting a failure.
		emitted := 0
		oversize, unnamed := 0, 0
		ok := p.ParseProtobuf(nil, data, func(name, value []byte, _ Kind) bool {
			emitted++
			if len(value) > len(data) {
				oversize++
			}
			if len(name) == 0 {
				unnamed++
			}
			return true
		})
		if oversize > 0 {
			t.Fatalf("%d values larger than the %d-byte input", oversize, len(data))
		}
		if unnamed > 0 {
			t.Fatalf("%d values emitted with no name", unnamed)
		}

		// Bounded regardless of what the input declared.
		if emitted > 256 {
			t.Fatalf("emitted %d values, limit is 256", emitted)
		}
		// Anything ParseProtobuf accepts must also satisfy IsProtobuf, since the
		// caller uses the latter to decide whether the former is worth running.
		if ok && !IsProtobuf(data) {
			t.Fatal("parsed input that IsProtobuf rejects")
		}
	})
}

func BenchmarkParseProtobuf(b *testing.B) {
	msg := pbString(1, "orders-svc")
	msg = append(msg, pbVarint(2, 42)...)
	msg = append(msg, pbBytes(3, pbString(1, "nested value here"))...)
	msg = append(msg, pbString(4, strings.Repeat("x", 128))...)

	var p Parser
	b.ReportAllocs()
	for b.Loop() {
		p.Reset(Limits{MaxFields: 256, MaxValueLen: 1 << 16, MaxTotalSize: 1 << 16})
		p.ParseProtobuf(nil, msg, func([]byte, []byte, Kind) bool { return true })
	}
}
