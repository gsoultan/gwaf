// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
)

// Compression, and why an undecoded body is a total bypass.
//
// A compressed request body is opaque bytes. Every detector runs over the
// compressed form, finds nothing — there is no grammar in a DEFLATE stream —
// and the request is reported clean. The origin then decompresses it and acts
// on the payload.
//
// Measured before this existed: `{"q":"1 UNION SELECT password FROM users"}`
// was blocked when sent plainly and allowed when sent gzipped. That is not a
// weakness, it is the whole firewall switched off by one header.
//
// So a declared encoding is decoded and the decoded body is what gets
// inspected, in the form the application will receive it.

// Compression-specific errors.
var (
	// ErrUnsupportedEncoding reports a Content-Encoding gwaf cannot decode.
	//
	// This is deliberately an error rather than a shrug. A body that cannot be
	// decoded has not been shown to be clean, and treating it as clean is
	// exactly the bypass this file exists to close. The caller applies its fail
	// mode; brotli is the case that matters, because decoding it needs a
	// third-party library the core module will not carry.
	ErrUnsupportedEncoding = errors.New("body: unsupported content encoding")

	// ErrDecompressionBomb reports content that expanded past the limit.
	ErrDecompressionBomb = errors.New("body: decompressed size exceeds limit")
)

// Encoding names a content encoding.
type Encoding uint8

// Encodings.
const (
	EncodingNone Encoding = iota
	EncodingGzip
	EncodingDeflate
	EncodingZlib
	// EncodingBrotli is recognised but not decodable here. Recognising it is
	// the point: an unrecognised encoding would be silently inspected as
	// binary, which is the bypass.
	EncodingBrotli
	EncodingUnknown
)

// String implements fmt.Stringer.
func (e Encoding) String() string {
	switch e {
	case EncodingGzip:
		return "gzip"
	case EncodingDeflate:
		return "deflate"
	case EncodingZlib:
		return "zlib"
	case EncodingBrotli:
		return "br"
	case EncodingUnknown:
		return "unknown"
	default:
		return "none"
	}
}

// Decodable reports whether gwaf can decompress this encoding.
func (e Encoding) Decodable() bool {
	switch e {
	case EncodingGzip, EncodingDeflate, EncodingZlib:
		return true
	default:
		return false
	}
}

// DetectEncoding maps a Content-Encoding header value onto an Encoding.
//
// Only the last encoding in a chain is considered, because that is the one
// applied last and therefore the one to undo first. A chain gwaf cannot fully
// unwind reports Unknown, which the caller must treat as undecidable rather
// than clean.
func DetectEncoding(header string) Encoding {
	if header == "" {
		return EncodingNone
	}

	// Take the final token of a possibly comma-separated list.
	last := header
	for i := len(header) - 1; i >= 0; i-- {
		if header[i] == ',' {
			last = header[i+1:]
			break
		}
	}
	last = trimSpaceStr(lowerStr(last))

	switch last {
	case "", "identity":
		return EncodingNone
	case "gzip", "x-gzip":
		return EncodingGzip
	case "deflate":
		// "deflate" on the wire is zlib-wrapped more often than raw, but both
		// occur; Decompress tries zlib first and falls back to raw.
		return EncodingDeflate
	case "zlib":
		return EncodingZlib
	case "br", "brotli":
		return EncodingBrotli
	default:
		return EncodingUnknown
	}
}

// SniffGzip reports whether data carries the gzip magic number.
//
// Used as an *additional* reading rather than a replacement for the declared
// encoding: an origin that sniffs will decompress a body whose header says
// nothing, and gwaf does not know which the origin does. Evaluating both is the
// same reasoning as the multi-interpretation decoding in internal/interpret.
func SniffGzip(data []byte) bool {
	return len(data) >= 3 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 0x08
}

// Decompress decodes data into dst and returns the decoded bytes.
//
// The limit bounds the decompressed size. Compression ratios of a thousand to
// one are ordinary and a crafted stream reaches far higher, so decompressing
// without a ceiling turns a small request into an out-of-memory condition —
// the decompression bomb. Exceeding the limit is reported, never truncated,
// because a partially decompressed body is a partially inspected one.
func Decompress(dst []byte, data []byte, enc Encoding, limit int) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultLimits().MaxTotalSize
	}

	var r io.ReadCloser
	var err error

	switch enc {
	case EncodingGzip:
		r, err = gzip.NewReader(bytes.NewReader(data))
	case EncodingZlib:
		r, err = zlib.NewReader(bytes.NewReader(data))
	case EncodingDeflate:
		// "deflate" is zlib-wrapped in most clients and raw in some. Trying
		// both matters: refusing the form the origin accepts would leave the
		// body uninspected.
		if zr, zerr := zlib.NewReader(bytes.NewReader(data)); zerr == nil {
			r = zr
		} else {
			r = flate.NewReader(bytes.NewReader(data))
		}
	default:
		return nil, ErrUnsupportedEncoding
	}
	if err != nil {
		return nil, err
	}
	defer r.Close()

	// One byte past the limit distinguishes "exactly at the limit" from "over".
	out, err := readAtMost(dst, r, limit+1)
	if err != nil {
		return nil, err
	}
	if len(out) > limit {
		return nil, ErrDecompressionBomb
	}
	return out, nil
}

// readAtMost reads up to max bytes into dst, growing it as needed.
func readAtMost(dst []byte, r io.Reader, max int) ([]byte, error) {
	dst = dst[:0]
	buf := make([]byte, 32<<10)

	for len(dst) < max {
		n, err := r.Read(buf)
		if n > 0 {
			room := max - len(dst)
			if n > room {
				n = room
			}
			dst = append(dst, buf[:n]...)
		}
		if err == io.EOF {
			return dst, nil
		}
		if err != nil {
			// A truncated or corrupt stream still yields whatever decoded
			// cleanly. Some origins accept exactly that, so inspecting it is
			// the safe direction; the caller decides what the error means.
			return dst, err
		}
	}
	return dst, nil
}
