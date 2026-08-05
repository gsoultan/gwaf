// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

import "errors"

// gRPC framing, and the two ways a payload hides inside it.
//
// A gRPC body is a sequence of length-prefixed messages:
//
//	[1 byte compressed-flag][4 bytes big-endian length][length bytes payload]
//
// Both fields of that header are places a payload can hide, and gwaf missed
// both until they were measured:
//
//  1. **Per-frame compression.** When the flag is set, the payload is
//     compressed with the codec named by the `grpc-encoding` header. This is a
//     *different mechanism* from Content-Encoding — it applies per message, not
//     per body — so the Content-Encoding handling in compress.go does not see
//     it. A compressed frame inspected as-is is opaque, exactly like a gzipped
//     body: no grammar in a DEFLATE stream, nothing matches, request reported
//     clean, origin decompresses and acts on the payload.
//
//  2. **grpc-web-text.** Browsers that cannot send binary framing base64 the
//     whole body instead. That is handled in binary.go, because it is a
//     property of the body rather than of the framing.
//
// Unframing matters for a third reason with no attacker behind it: the five
// header bytes of every message are binary noise between the payloads. Feeding
// them to a text detector is the same category error that made 1.2% of random
// protobuf look like shell injection.

// Frame limits, all bounded because this parses attacker-supplied input.
const (
	// maxFrames bounds how many messages are unframed from one body. A
	// streaming request may carry many; anything past this is inspected as a
	// whole rather than enumerated.
	maxFrames = 256

	// maxFrameLen bounds a single declared frame length before it is trusted
	// enough to slice, so a forged length cannot drive an allocation.
	maxFrameLen = 64 << 20

	// grpcHeaderLen is the fixed message header.
	grpcHeaderLen = 5
)

// ErrMalformedFrame reports a body that does not unframe cleanly.
var ErrMalformedFrame = errors.New("body: malformed gRPC frame")

// IsGRPCFramed reports whether data parses as a sequence of gRPC messages.
//
// Deliberately strict: every frame must be well formed and the last must end
// exactly at the end of the body. A loose check would claim ordinary binary
// uploads, and unframing those would slice payloads out of the middle of a JPEG
// and inspect the pieces as if they were messages.
//
// Content-Type is not consulted, for the reason it is never consulted here: it
// is attacker-controlled, and a body that *is* gRPC framing is gRPC framing
// whatever it claims to be.
func IsGRPCFramed(data []byte) bool {
	if len(data) < grpcHeaderLen {
		return false
	}
	frames := 0
	for i := 0; i < len(data); {
		if i+grpcHeaderLen > len(data) {
			return false
		}
		// The compressed flag is 0 or 1. Anything else is not a gRPC header,
		// and this single byte rejects most non-gRPC binary immediately.
		if data[i] > 1 {
			return false
		}
		n := frameLen(data[i+1:])
		if n > maxFrameLen || i+grpcHeaderLen+n > len(data) {
			return false
		}
		i += grpcHeaderLen + n
		frames++
		if frames > maxFrames {
			return false
		}
	}
	return frames > 0
}

// frameLen reads the 4-byte big-endian length.
func frameLen(b []byte) int {
	if len(b) < 4 {
		return -1
	}
	return int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
}

// GRPCFrame is one unframed message.
type GRPCFrame struct {
	// Payload is the message, decompressed when it needed to be.
	Payload []byte

	// Compressed reports that the frame carried the compressed flag.
	Compressed bool
}

// UnframeGRPC splits data into messages, decompressing any that are compressed.
//
// enc is the codec from the `grpc-encoding` header. A compressed frame whose
// codec gwaf cannot decode is returned with its Payload nil and the error set,
// because a message nobody could read has not been shown to be clean — the same
// rule the Content-Encoding path follows.
//
// dst is reused scratch for decompression; the returned frames may point into
// it, so the caller must copy anything it retains.
func UnframeGRPC(dst []byte, data []byte, enc Encoding, limit int) ([]GRPCFrame, []byte, error) {
	if limit <= 0 {
		limit = DefaultLimits().MaxTotalSize
	}

	var out []GRPCFrame
	var firstErr error
	scratch := dst

	for i := 0; i < len(data); {
		if i+grpcHeaderLen > len(data) {
			return out, scratch, ErrMalformedFrame
		}
		compressed := data[i] == 1
		n := frameLen(data[i+1:])
		if n < 0 || n > maxFrameLen || i+grpcHeaderLen+n > len(data) {
			return out, scratch, ErrMalformedFrame
		}
		payload := data[i+grpcHeaderLen : i+grpcHeaderLen+n]
		i += grpcHeaderLen + n

		if !compressed {
			out = append(out, GRPCFrame{Payload: payload})
			if len(out) >= maxFrames {
				break
			}
			continue
		}

		// A frame declaring compression with no codec named is malformed by the
		// spec, and treating it as plaintext would be inventing a reading the
		// origin will not take.
		if enc == EncodingNone || !enc.Decodable() {
			out = append(out, GRPCFrame{Compressed: true})
			if firstErr == nil {
				firstErr = ErrUnsupportedEncoding
			}
			if len(out) >= maxFrames {
				break
			}
			continue
		}

		// Each frame decompresses into its own copy, because the next frame
		// would otherwise overwrite it before anything had inspected it.
		decoded, err := Decompress(scratch, payload, enc, limit)
		if err != nil {
			out = append(out, GRPCFrame{Compressed: true})
			if firstErr == nil {
				firstErr = err
			}
			if len(out) >= maxFrames {
				break
			}
			continue
		}
		scratch = decoded[:0]
		out = append(out, GRPCFrame{
			Payload:    append([]byte(nil), decoded...),
			Compressed: true,
		})
		if len(out) >= maxFrames {
			break
		}
	}
	return out, scratch, firstErr
}

// DetectGRPCEncoding maps a grpc-encoding header value onto an Encoding.
//
// Separate from DetectEncoding because the vocabularies differ: gRPC names its
// identity codec "identity" and adds "snappy" and "zstd", and it never carries
// a comma-separated chain the way Content-Encoding does.
func DetectGRPCEncoding(header string) Encoding {
	switch trimSpaceStr(lowerStr(header)) {
	case "", "identity":
		return EncodingNone
	case "gzip":
		return EncodingGzip
	case "deflate":
		return EncodingDeflate
	default:
		// snappy, zstd, and anything a codec registry added. Recognised as
		// undecodable rather than ignored, which is the whole point: silence
		// here is the bypass.
		return EncodingUnknown
	}
}
