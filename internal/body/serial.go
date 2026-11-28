// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

// serialPrefixLen is how much of a recognized object stream is kept for the
// detectors. The header is what identifies the stream, and every recognized
// header fits well inside it; the rest is the gadget graph, which the
// printable-run extraction already presents in pieces.
const serialPrefixLen = 64

// bfHeader is the .NET BinaryFormatter SerializedStreamHeader record: record
// type 0, root id 1, header id -1, major version 1, minor version 0. Every
// BinaryFormatter stream begins with exactly these seventeen bytes, which is
// why it identifies the format alone.
var bfHeader = []byte{
	0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// SerializedStreamPrefix reports how many leading bytes of b to keep as the
// header of a native object-serialization stream, or 0 when b does not begin
// with one.
//
// # Why this exists
//
// A binary value is inspected as its printable runs (ExtractText), which is
// right for an image and wrong here: the bytes that say "this is a serialized
// object" are not printable, so the split discards exactly the evidence. A Java
// object stream in a 2 KiB base64 form field, or posted raw as
// application/x-java-serialized-object, reached the detectors as class names
// with the 0xACED magic gone, and the class names alone are deliberately not
// enough to block (detect/javaser explains why). Oracle PeopleSoft
// CVE-2026-35273 is delivered as the raw form; Idunno.AntiCsrf CVE-2026-131914
// and every ysoserial.net ViewState payload as the base64 one.
//
// The streams recognized all begin with a fixed header that no text and no
// common file format starts with:
//
//   - Java serialization: 0xACED, version 0x0005.
//   - .NET BinaryFormatter: the SerializedStreamHeader record (bfHeader).
//   - .NET ObjectStateFormatter (ViewState, LosFormatter) wrapping a
//     BinaryFormatter graph at the top level: 0xFF 0x01, token 0x32, a 7-bit
//     encoded length, then bfHeader. A real page's ViewState starts with a
//     Pair or Triplet token (0x0F, 0x10); a top-level binary-serialized object
//     is what the ysoserial.net ViewState plugin emits, because the gadget is
//     the whole graph.
//
// Anchored at offset 0 on purpose. A three-byte pattern searched anywhere in
// arbitrary binary content would match random uploads; a header at the start
// of a decoded value or a raw body is a statement about what the bytes are.
func SerializedStreamPrefix(b []byte) int {
	if !isSerializedStream(b) {
		return 0
	}
	return min(len(b), serialPrefixLen)
}

func isSerializedStream(b []byte) bool {
	if len(b) >= 4 && b[0] == 0xac && b[1] == 0xed && b[2] == 0x00 && b[3] == 0x05 {
		return true
	}
	return IsDotNetStream(b)
}

// IsDotNetStream reports whether b begins with a .NET BinaryFormatter stream,
// bare or wrapped at the top level of an ObjectStateFormatter (ViewState)
// payload. See SerializedStreamPrefix for why each header identifies the
// format.
func IsDotNetStream(b []byte) bool {
	if hasBFHeader(b) {
		return true
	}
	if len(b) < 3 || b[0] != 0xff || b[1] != 0x01 || b[2] != 0x32 {
		return false
	}
	// The graph follows a 7-bit encoded length of one to five bytes. The header
	// is looked for at each of those offsets rather than after a parsed length,
	// because a rule's transform chain can rewrite a length byte that happens
	// to be '\' or '%' -- and an attacker chooses the length by choosing the
	// padding, so a parse that a decode can misalign is a bypass.
	for i := 3; i <= 8 && i < len(b); i++ {
		if hasBFHeader(b[i:]) {
			return true
		}
	}
	return false
}

func hasBFHeader(b []byte) bool {
	if len(b) < len(bfHeader) {
		return false
	}
	for i, c := range bfHeader {
		if b[i] != c {
			return false
		}
	}
	return true
}
