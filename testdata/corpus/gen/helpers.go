// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

// grpcBody builds a gRPC length-prefixed frame around a plausible protobuf
// message: a couple of varint fields and a string field.
//
// The framing bytes are what a text detector must not read as a sentence, and
// the string field is what it must still inspect.
func grpcBody(i, j int) string {
	names := []string{"api-route", "orders-svc", "gateway-01", "tls-modern"}
	name := names[(i+j)%len(names)]

	var pb []byte
	pb = append(pb, 0x08, byte(1+i%120))   // field 1 varint
	pb = append(pb, 0x10, byte(1+j%50))    // field 2 varint
	pb = append(pb, 0x1a, byte(len(name))) // field 3 length-delimited
	pb = append(pb, name...)
	pb = append(pb, 0x20, 0x01) // field 4 varint (bool)

	frame := make([]byte, 5+len(pb))
	frame[0] = 0
	frame[1] = byte(len(pb) >> 24)
	frame[2] = byte(len(pb) >> 16)
	frame[3] = byte(len(pb) >> 8)
	frame[4] = byte(len(pb))
	copy(frame[5:], pb)
	return string(frame)
}

// urlEncode percent-encodes a query value.
func urlEncode(s string) string {
	const hex = "0123456789ABCDEF"
	out := make([]byte, 0, len(s)*3)
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			out = append(out, c)
		case c == ' ':
			out = append(out, '+')
		default:
			out = append(out, '%', hex[c>>4], hex[c&0x0f])
		}
	}
	return string(out)
}

// base64Encode encodes without importing encoding/base64, so the generator
// stays a single self-contained program with no dependency on how the library
// itself decodes.
func base64Encode(src []byte) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, 0, (len(src)+2)/3*4)
	for i := 0; i < len(src); i += 3 {
		var n uint32
		rem := len(src) - i
		n = uint32(src[i]) << 16
		if rem > 1 {
			n |= uint32(src[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(src[i+2])
		}
		out = append(out, alpha[n>>18&0x3f], alpha[n>>12&0x3f])
		if rem > 1 {
			out = append(out, alpha[n>>6&0x3f])
		} else {
			out = append(out, '=')
		}
		if rem > 2 {
			out = append(out, alpha[n&0x3f])
		} else {
			out = append(out, '=')
		}
	}
	return string(out)
}
