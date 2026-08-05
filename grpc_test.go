// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
)

// gRPC carries a payload in three places a firewall can miss, and this file is
// the regression test for all three.
//
//	[1 byte compressed-flag][4 bytes big-endian length][payload]
//
// The framing bytes must not be read as text — that was 1.2% of random protobuf
// blocked. The compressed flag means the payload is compressed *per message*,
// which Content-Encoding does not describe. And grpc-web-text base64-encodes the
// whole body, which is printable, has no grammar, and matched nothing at all.

// grpcFrame wraps a payload in the gRPC message framing.
func grpcMsg(payload []byte, compressed bool) []byte {
	f := make([]byte, 5+len(payload))
	if compressed {
		f[0] = 1
	}
	f[1] = byte(len(payload) >> 24)
	f[2] = byte(len(payload) >> 16)
	f[3] = byte(len(payload) >> 8)
	f[4] = byte(len(payload))
	copy(f[5:], payload)
	return f
}

// protoString encodes a length-delimited string into protobuf field 3, which is
// where an attacker-controlled value actually lives.
func protoString(s string) []byte {
	return append([]byte{0x1a, byte(len(s))}, s...)
}

func gzipOf(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

const sqliPayload = "1' OR 1=1--"

// TestGRPCBinaryFramesAreInspected covers the paths that already worked, so a
// change to the new ones cannot quietly break them.
func TestGRPCBinaryFramesAreInspected(t *testing.T) {
	w := newWAF(t)
	body := string(grpcMsg(protoString(sqliPayload), false))

	for _, ct := range []string{
		"application/grpc",
		"application/grpc+proto",
		"application/grpc-web+proto",
		"application/connect+proto",
		"application/proto",
	} {
		t.Run(ct, func(t *testing.T) {
			d := run(t, w, req{method: "POST", target: "/pkg.Svc/Method", body: body,
				headers: map[string]string{"Content-Type": ct}})
			if !d.Blocked() {
				t.Error("payload in a protobuf string field was not detected")
			}
		})
	}
}

// TestGRPCWebTextIsDecoded covers the first gap. Browsers that cannot send
// binary framing base64 the entire body, and that form was invisible: base64 is
// printable so it is not binary, and there is no grammar in it to match.
func TestGRPCWebTextIsDecoded(t *testing.T) {
	w := newWAF(t)

	for _, name := range []string{"short frame", "long frame"} {
		payload := sqliPayload
		if name == "long frame" {
			payload += " and padding well past the sixty-four byte field floor"
		}
		enc := base64.StdEncoding.EncodeToString(grpcMsg(protoString(payload), false))

		t.Run(name, func(t *testing.T) {
			d := run(t, w, req{method: "POST", target: "/pkg.Svc/Method", body: enc,
				headers: map[string]string{"Content-Type": "application/grpc-web-text"}})
			if !d.Blocked() {
				t.Errorf("base64-wrapped payload not detected (len=%d)", len(enc))
			}
		})
	}

	// URL-safe alphabet, which some clients emit.
	enc := base64.RawURLEncoding.EncodeToString(grpcMsg(protoString(sqliPayload), false))
	if d := run(t, w, req{method: "POST", target: "/s/M", body: enc,
		headers: map[string]string{"Content-Type": "application/grpc-web-text"}}); !d.Blocked() {
		t.Error("URL-safe base64 not detected")
	}
}

// TestGRPCPerFrameCompression covers the second gap, which is the same bypass
// class as the Content-Encoding one: a compressed payload is opaque, nothing
// matches, and the origin decompresses and acts on it.
func TestGRPCPerFrameCompression(t *testing.T) {
	w := newWAF(t)
	body := string(grpcMsg(gzipOf(protoString(sqliPayload)), true))

	d := run(t, w, req{method: "POST", target: "/pkg.Svc/Method", body: body,
		headers: map[string]string{
			"Content-Type":  "application/grpc",
			"Grpc-Encoding": "gzip",
		}})
	if !d.Blocked() {
		t.Error("payload inside a compressed gRPC frame was not detected")
	}

	// Compressed and then base64-wrapped: both gaps at once, which is what a
	// grpc-web-text client with compression enabled actually sends.
	enc := base64.StdEncoding.EncodeToString(grpcMsg(gzipOf(protoString(sqliPayload)), true))
	d = run(t, w, req{method: "POST", target: "/s/M", body: enc,
		headers: map[string]string{
			"Content-Type":  "application/grpc-web-text",
			"Grpc-Encoding": "gzip",
		}})
	if !d.Blocked() {
		t.Error("compressed payload inside a base64-wrapped frame was not detected")
	}
}

// TestGRPCUndecodableCodecIsNotReportedClean is the rule the Content-Encoding
// path already follows: a message nobody could read has not been shown to be
// clean. snappy and zstd are registered gRPC codecs gwaf cannot decode.
func TestGRPCUndecodableCodecIsNotReportedClean(t *testing.T) {
	w := newWAF(t)
	body := string(grpcMsg(gzipOf(protoString(sqliPayload)), true))

	d := run(t, w, req{method: "POST", target: "/s/M", body: body,
		headers: map[string]string{
			"Content-Type":  "application/grpc",
			"Grpc-Encoding": "snappy",
		}})
	if d.Blocked() {
		return // fail-closed configurations may reject outright, which is fine
	}
	if !strings.Contains(d.Detail(), "grpc-encoding") {
		t.Errorf("an undecodable codec was passed silently: detail=%q", d.Detail())
	}
}

// TestGRPCMultipleFrames covers a streaming request: every message is
// inspected, not merely the first. This is the same property the multipart
// parser has, and for the same reason — CVE-2026-21876 was the Core Rule Set
// examining only one part.
func TestGRPCMultipleFrames(t *testing.T) {
	w := newWAF(t)

	var b []byte
	b = append(b, grpcMsg(protoString("orders-svc"), false)...)
	b = append(b, grpcMsg(protoString("gateway-01"), false)...)
	b = append(b, grpcMsg(protoString(sqliPayload), false)...) // last
	if d := run(t, w, req{method: "POST", target: "/s/M", body: string(b),
		headers: map[string]string{"Content-Type": "application/grpc"}}); !d.Blocked() {
		t.Error("a payload in the last frame was missed")
	}

	b = b[:0]
	b = append(b, grpcMsg(protoString(sqliPayload), false)...) // first
	b = append(b, grpcMsg(protoString("orders-svc"), false)...)
	if d := run(t, w, req{method: "POST", target: "/s/M", body: string(b),
		headers: map[string]string{"Content-Type": "application/grpc"}}); !d.Blocked() {
		t.Error("a payload in the first frame was missed")
	}
}

// TestBenignGRPCPasses is the counterweight, and it is the measurement that
// forced binary handling in the first place: 1.2% of random protobuf was being
// blocked because a two-byte shell literal turns up by chance in binary.
func TestBenignGRPCPasses(t *testing.T) {
	w := newWAF(t)

	values := []string{
		"orders-svc", "gateway-01", "tls-modern", "api-route",
		"O'Brien", "Marks & Spencer", "café", "日本語",
		"user_1234", "SKU-000042", "2026-01-15T09:30:00Z",
	}
	for _, v := range values {
		t.Run(v, func(t *testing.T) {
			plain := string(grpcMsg(protoString(v), false))
			if d := run(t, w, req{method: "POST", target: "/s/M", body: plain,
				headers: map[string]string{"Content-Type": "application/grpc"}}); d.Blocked() {
				t.Errorf("benign protobuf blocked: rule=%d msg=%q", d.RuleID(), d.Message())
			}

			enc := base64.StdEncoding.EncodeToString(grpcMsg(protoString(v), false))
			if d := run(t, w, req{method: "POST", target: "/s/M", body: enc,
				headers: map[string]string{"Content-Type": "application/grpc-web-text"}}); d.Blocked() {
				t.Errorf("benign grpc-web-text blocked: rule=%d msg=%q", d.RuleID(), d.Message())
			}

			gz := string(grpcMsg(gzipOf(protoString(v)), true))
			if d := run(t, w, req{method: "POST", target: "/s/M", body: gz,
				headers: map[string]string{
					"Content-Type": "application/grpc", "Grpc-Encoding": "gzip",
				}}); d.Blocked() {
				t.Errorf("benign compressed frame blocked: rule=%d msg=%q", d.RuleID(), d.Message())
			}
		})
	}
}

// TestNonGRPCBodiesAreNotUnframed guards the other direction. Unframing is
// strict on purpose: a loose check would slice payloads out of the middle of a
// JPEG and inspect the pieces as if they were messages.
func TestNonGRPCBodiesAreNotUnframed(t *testing.T) {
	w := newWAF(t)

	cases := []struct{ name, ctype, body string }{
		{"json", "application/json", `{"sku":"SKU-1","qty":2}`},
		{"form", "application/x-www-form-urlencoded", "a=1&b=2"},
		{"text", "text/plain", "just some prose about orders"},
		{"jpeg", "image/jpeg", "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01" + strings.Repeat("\x7f", 200)},
		{"empty", "application/grpc", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if d := run(t, w, req{method: "POST", target: "/x", body: c.body,
				headers: map[string]string{"Content-Type": c.ctype}}); d.Blocked() {
				t.Errorf("blocked: rule=%d msg=%q", d.RuleID(), d.Message())
			}
		})
	}

	// A payload in a JSON body must still be caught: unframing must not have
	// taken over the ordinary path.
	if d := run(t, w, req{method: "POST", target: "/x",
		body:    `{"q":"` + sqliPayload + `"}`,
		headers: map[string]string{"Content-Type": "application/json"}}); !d.Blocked() {
		t.Error("JSON inspection regressed")
	}
}

// TestMalformedFramingIsInspectedWhole covers the safe direction: a body that
// claims to be framed and is not still gets looked at.
func TestMalformedFramingIsInspectedWhole(t *testing.T) {
	w := newWAF(t)

	// A length field far larger than the body.
	bad := []byte{0, 0xFF, 0xFF, 0xFF, 0xFF}
	bad = append(bad, protoString(sqliPayload)...)
	if d := run(t, w, req{method: "POST", target: "/s/M", body: string(bad),
		headers: map[string]string{"Content-Type": "application/grpc"}}); !d.Blocked() {
		t.Error("a payload in a malformed frame was skipped rather than inspected whole")
	}
}
