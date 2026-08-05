// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

import (
	"bytes"
	"compress/gzip"
	"errors"
	"testing"
)

func msg(payload []byte, compressed bool) []byte {
	f := make([]byte, grpcHeaderLen+len(payload))
	if compressed {
		f[0] = 1
	}
	f[1] = byte(len(payload) >> 24)
	f[2] = byte(len(payload) >> 16)
	f[3] = byte(len(payload) >> 8)
	f[4] = byte(len(payload))
	copy(f[grpcHeaderLen:], payload)
	return f
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func TestIsGRPCFramed(t *testing.T) {
	yes := [][]byte{
		msg([]byte("hello"), false),
		msg(nil, false),
		append(msg([]byte("a"), false), msg([]byte("bb"), false)...),
		msg(gz([]byte("hello")), true),
	}
	for i, b := range yes {
		if !IsGRPCFramed(b) {
			t.Errorf("case %d: well-formed framing not recognised", i)
		}
	}

	// Strict on purpose. A loose check would claim ordinary binary uploads, and
	// unframing those slices payloads out of the middle of a JPEG.
	no := [][]byte{
		nil,
		[]byte("hi"),                      // shorter than a header
		[]byte(`{"a":1}`),                 // JSON
		[]byte("a=1&b=2"),                 // form
		{2, 0, 0, 0, 1, 'x'},              // flag is neither 0 nor 1
		{0, 0, 0, 0, 9, 'x'},              // declared length overruns
		{0, 0, 0, 0, 1, 'x', 'y'},         // trailing byte past the last frame
		{0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10}, // JPEG header
		{0, 0xFF, 0xFF, 0xFF, 0xFF, 'x'},  // forged huge length
	}
	for i, b := range no {
		if IsGRPCFramed(b) {
			t.Errorf("case %d: %v claimed as framing", i, b)
		}
	}
}

func TestUnframeGRPC(t *testing.T) {
	b := append(msg([]byte("first"), false), msg([]byte("second"), false)...)
	frames, _, err := UnframeGRPC(nil, b, EncodingNone, 1<<20)
	if err != nil {
		t.Fatalf("UnframeGRPC: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
	if string(frames[0].Payload) != "first" || string(frames[1].Payload) != "second" {
		t.Errorf("payloads = %q, %q", frames[0].Payload, frames[1].Payload)
	}
}

// TestUnframeDecompresses is the gap this file exists for: gRPC compresses per
// message, which Content-Encoding does not describe, so compress.go never saw it.
func TestUnframeDecompresses(t *testing.T) {
	want := "1' OR 1=1--"
	b := msg(gz([]byte(want)), true)

	frames, _, err := UnframeGRPC(nil, b, EncodingGzip, 1<<20)
	if err != nil {
		t.Fatalf("UnframeGRPC: %v", err)
	}
	if len(frames) != 1 || string(frames[0].Payload) != want {
		t.Fatalf("frames = %+v", frames)
	}
	if !frames[0].Compressed {
		t.Error("Compressed not reported")
	}
}

// TestEachFrameKeepsItsOwnPayload covers an aliasing trap: decompressing into
// shared scratch means the next frame overwrites the previous one before
// anything has inspected it.
func TestEachFrameKeepsItsOwnPayload(t *testing.T) {
	b := append(msg(gz([]byte("aaaaaaaaaaaaaaaa")), true),
		msg(gz([]byte("bbbbbbbbbbbbbbbb")), true)...)

	frames, _, err := UnframeGRPC(nil, b, EncodingGzip, 1<<20)
	if err != nil {
		t.Fatalf("UnframeGRPC: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("got %d frames", len(frames))
	}
	if string(frames[0].Payload) != "aaaaaaaaaaaaaaaa" {
		t.Errorf("frame 0 was overwritten: %q", frames[0].Payload)
	}
	if string(frames[1].Payload) != "bbbbbbbbbbbbbbbb" {
		t.Errorf("frame 1 = %q", frames[1].Payload)
	}
}

// TestUndecodableCodecIsReported: a message nobody could read has not been shown
// to be clean, which is the rule the Content-Encoding path follows too.
func TestUndecodableCodecIsReported(t *testing.T) {
	b := msg(gz([]byte("payload")), true)

	frames, _, err := UnframeGRPC(nil, b, EncodingUnknown, 1<<20)
	if !errors.Is(err, ErrUnsupportedEncoding) {
		t.Errorf("err = %v, want ErrUnsupportedEncoding", err)
	}
	if len(frames) != 1 || frames[0].Payload != nil {
		t.Errorf("an undecodable frame must carry no payload: %+v", frames)
	}

	// A frame claiming compression with no codec named is malformed by the spec,
	// and reading it as plaintext would invent a reading the origin will not take.
	if _, _, err := UnframeGRPC(nil, b, EncodingNone, 1<<20); err == nil {
		t.Error("compressed frame with no codec was accepted")
	}
}

func TestDecompressionBombIsBounded(t *testing.T) {
	huge := bytes.Repeat([]byte("A"), 1<<20)
	b := msg(gz(huge), true)

	if _, _, err := UnframeGRPC(nil, b, EncodingGzip, 1024); err == nil {
		t.Error("a frame expanding past the limit was accepted")
	}
}

func TestDetectGRPCEncoding(t *testing.T) {
	cases := map[string]Encoding{
		"":         EncodingNone,
		"identity": EncodingNone,
		"gzip":     EncodingGzip,
		"GZIP":     EncodingGzip,
		"deflate":  EncodingDeflate,
		// Registered codecs gwaf cannot decode. Recognised as undecodable
		// rather than ignored, because silence here is the bypass.
		"snappy": EncodingUnknown,
		"zstd":   EncodingUnknown,
		"br":     EncodingUnknown,
	}
	for in, want := range cases {
		if got := DetectGRPCEncoding(in); got != want {
			t.Errorf("DetectGRPCEncoding(%q) = %v, want %v", in, got, want)
		}
	}
}

// FuzzUnframeGRPC is non-negotiable: this parses attacker-declared lengths, and
// a forged length is the first thing anyone tries.
func FuzzUnframeGRPC(f *testing.F) {
	f.Add(msg([]byte("hello"), false))
	f.Add(msg(gz([]byte("hello")), true))
	f.Add(append(msg([]byte("a"), false), msg([]byte("b"), false)...))
	f.Add([]byte{0, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{1, 0, 0, 0, 3, 1, 2, 3})
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, enc := range []Encoding{
			EncodingNone, EncodingGzip, EncodingDeflate, EncodingUnknown,
		} {
			frames, _, _ := UnframeGRPC(nil, data, enc, 1<<16)

			// Bounded, and every payload must be a real slice rather than a
			// window past the end of the input.
			if len(frames) > maxFrames {
				t.Fatalf("returned %d frames, cap is %d", len(frames), maxFrames)
			}
			for i := range frames {
				if p := frames[i].Payload; p != nil && len(p) > 1<<16+1 {
					t.Fatalf("frame %d payload is %d bytes, past the limit", i, len(p))
				}
			}

			// A body IsGRPCFramed accepts must unframe without a framing error.
			if enc == EncodingNone && IsGRPCFramed(data) {
				if _, _, err := UnframeGRPC(nil, data, EncodingNone, 1<<16); errors.Is(err, ErrMalformedFrame) {
					t.Fatalf("IsGRPCFramed accepted input that will not unframe: %v", data)
				}
			}
		}
	})
}
