// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

// Protobuf wire parsing, and why extracting printable runs is not enough.
//
// A gRPC message is protobuf, and until now gwaf inspected it the way it
// inspects any binary blob: pull out the printable runs and hand those to the
// detectors. That works, and it has an arbitrary floor — runs shorter than
// minTextRun are dropped, because in *unstructured* binary a short printable run
// is a coincidence rather than a string.
//
// In a protobuf message it is not a coincidence. A length-delimited field is a
// field, whatever its length, and the floor was measured costing coverage:
//
//	"1' OR 1=1"  (9 bytes)  detected
//	"'OR 1=1"    (7 bytes)  missed
//
// Both are SQL injection. The second was invisible only because a heuristic
// meant for JPEG framing was being applied to a structured document.
//
// Parsing the wire format removes the floor and gives every value a stable name
// — "3", "3.1" — which is what lets a descriptor say that field 3 is an int32
// and therefore provably inert (schema/grpc). The parser itself needs no
// descriptor: the wire format is self-describing enough to walk.
//
// # The one ambiguity, and how it is resolved
//
// Wire type 2 is length-delimited, and the wire format does not distinguish a
// string from a nested message. A parser must guess, and guessing wrong in
// either direction costs something:
//
//   - Read a nested message as a string, and the detectors see framing bytes as
//     prose — the chance-match problem again.
//   - Read a string as a nested message, and its contents are never inspected.
//
// So both readings are taken when both are plausible, which is the same rule
// internal/interpret follows for ambiguous encodings. Bytes that parse cleanly
// as a message are recursed into; bytes that are not binary are also emitted as
// a value. A nested message rarely survives the text test and a string rarely
// parses cleanly, so in practice each is read one way — and where both are
// plausible, gwaf does not have to be right.

// Protobuf wire types.
const (
	wireVarint     = 0
	wireFixed64    = 1
	wireBytes      = 2
	wireStartGroup = 3
	wireEndGroup   = 4
	wireFixed32    = 5
)

// Bounds. Everything here parses attacker-supplied bytes.
const (
	// maxProtoDepth bounds nesting. Protobuf permits arbitrary depth and a
	// crafted message nests as far as its length allows, so recursion needs a
	// ceiling that does not depend on the input.
	maxProtoDepth = 16

	// maxProtoFields bounds how many values one message contributes.
	maxProtoFields = 1024

	// maxVarintLen is the longest a valid varint can be: ten groups of seven
	// bits covers a 64-bit value.
	maxVarintLen = 10
)

// IsProtobuf reports whether data parses cleanly as a protobuf message.
//
// "Cleanly" means every field has a valid wire type and the last one ends
// exactly at the end of the input. That is a strong filter: random bytes almost
// never satisfy it, and neither does JSON, form encoding, or a JPEG.
//
// An empty input is not a message. Protobuf encodes an empty message as zero
// bytes, so accepting it would claim every empty body.
func IsProtobuf(data []byte) bool {
	n, ok := scanProtobuf(data, 0)
	return ok && n > 0
}

// scanProtobuf validates a message and counts its fields.
func scanProtobuf(data []byte, depth int) (fields int, ok bool) {
	if depth > maxProtoDepth {
		return 0, false
	}
	i := 0
	for i < len(data) {
		key, n := readVarint(data[i:])
		if n == 0 {
			return fields, false
		}
		i += n

		// Field number 0 is reserved and never valid on the wire; rejecting it
		// is most of what stops random bytes from parsing.
		if key>>3 == 0 {
			return fields, false
		}

		switch key & 7 {
		case wireVarint:
			_, n := readVarint(data[i:])
			if n == 0 {
				return fields, false
			}
			i += n
		case wireFixed64:
			if i+8 > len(data) {
				return fields, false
			}
			i += 8
		case wireFixed32:
			if i+4 > len(data) {
				return fields, false
			}
			i += 4
		case wireBytes:
			size, n := readVarint(data[i:])
			if n == 0 {
				return fields, false
			}
			i += n
			if size > uint64(len(data)-i) {
				return fields, false
			}
			i += int(size)
		default:
			// Groups are deprecated and were removed from proto3. Treating them
			// as unparseable is safe: the caller falls back to whole-message
			// text extraction rather than skipping the content.
			return fields, false
		}

		fields++
		if fields > maxProtoFields {
			return fields, false
		}
	}
	return fields, i == len(data)
}

// ParseProtobuf walks a message, emitting each field that can carry a payload.
//
// Varints and fixed-width fields are numbers: no sequence of them is an
// injection, so they are skipped rather than emitted. Only length-delimited
// fields — strings, bytes, and nested messages — reach a detector.
//
// Names are the field-number path: "3" for a top-level field, "3.1" for field 1
// of the message in field 3. A descriptor can then say what field 3 is without
// the parser ever needing one.
//
// Reports whether the message parsed cleanly. On false the caller should fall
// back to whole-message inspection: a document gwaf could not read is not a
// document it may ignore.
func (p *Parser) ParseProtobuf(prefix []byte, data []byte, fn Emit) bool {
	if !IsProtobuf(data) {
		return false
	}
	// p.path carries the current full field path and is grown and truncated in
	// place, so nesting costs no allocation. An earlier version copied the path
	// per nested field, which was the parser's only per-field allocation and
	// showed up as GC pressure under fuzzing.
	p.path = append(p.path[:0], prefix...)
	p.walkProtobuf(data, 0, fn)
	return true
}

func (p *Parser) walkProtobuf(data []byte, depth int, fn Emit) bool {
	if depth > maxProtoDepth {
		return true
	}

	i := 0
	for i < len(data) {
		key, n := readVarint(data[i:])
		if n == 0 {
			return true
		}
		i += n
		field := key >> 3

		switch key & 7 {
		case wireVarint:
			_, n := readVarint(data[i:])
			if n == 0 {
				return true
			}
			i += n
			continue
		case wireFixed64:
			if i+8 > len(data) {
				return true
			}
			i += 8
			continue
		case wireFixed32:
			if i+4 > len(data) {
				return true
			}
			i += 4
			continue
		case wireBytes:
			// handled below
		default:
			return true
		}

		size, n := readVarint(data[i:])
		if n == 0 {
			return true
		}
		i += n
		if size > uint64(len(data)-i) {
			return true
		}
		value := data[i : i+int(size)]
		i += int(size)

		p.fields++
		if p.fields > p.limits.MaxFields {
			return false
		}

		// Extend the path for this field, and truncate back on the way out.
		// The separator is omitted at the root so a top-level field is "3"
		// rather than ".3": a schema names fields by their number path, and the
		// name it declares has to be the name the parser emits.
		mark := len(p.path)
		if len(p.path) > 0 {
			p.path = append(p.path, '.')
		}
		p.path = itoa(p.path, int(field))

		// Both readings, where both are plausible. A nested message that also
		// reads as text is rare, and so is the reverse.
		nested := false
		if depth < maxProtoDepth {
			if fields, ok := scanProtobuf(value, depth+1); ok && fields > 0 {
				nested = true
				if !p.walkProtobuf(value, depth+1, fn) {
					p.path = p.path[:mark]
					return false
				}
			}
		}
		if !nested || !IsBinary(value) {
			if !fn(p.path, value, KindString) {
				p.path = p.path[:mark]
				return false
			}
		}
		p.path = p.path[:mark]
	}
	return true
}

// readVarint decodes a base-128 varint, returning the value and its length.
//
// A zero length means the encoding was truncated or over-long. Both are
// malformed, and treating an over-long varint as valid would let a message
// declare a length its bytes cannot support.
func readVarint(b []byte) (uint64, int) {
	var v uint64
	var shift uint
	for i := 0; i < len(b) && i < maxVarintLen; i++ {
		c := b[i]
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, i + 1
		}
		shift += 7
	}
	return 0, 0
}
