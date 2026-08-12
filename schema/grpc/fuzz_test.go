// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package grpc_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/gsoultan/gwaf/schema/grpc"
)

// A descriptor set is protobuf wire format, and this package had no fuzz target.
//
// CLAUDE.md §4 makes one non-negotiable for a parser taking attacker input, and
// the trust argument here is the same one seclang needed: a descriptor set is
// usually a build artefact the operator produced, but Parse is exported and
// docs/PERFORMANCE.md says never to trust a runtime-supplied schema. A
// multi-tenant control plane loading a tenant's descriptor set is parsing
// somebody else's bytes.
//
// The properties are the ones a wire-format parser fails on: a varint whose
// continuation bits never end, a length prefix pointing past the buffer,
// nesting deep enough to exhaust the stack, and arithmetic that wraps. None of
// them should panic, hang, or read out of bounds — and a malformed descriptor
// must produce an error rather than a schema, because a schema built from
// nonsense would validate traffic against nonsense.
func FuzzParseDescriptorSet(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x00})
	f.Add(bytes.Repeat([]byte{0xFF}, 64))             // continuation bits forever
	f.Add(bytes.Repeat([]byte{0x80}, 19))             // varint overflow width
	f.Add([]byte{0x0A, 0xFF, 0xFF, 0xFF, 0x7F, 'x'})  // length past the buffer
	f.Add([]byte{0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F}) // length that wraps
	f.Add([]byte{0x0A})                               // truncated after a tag
	f.Add(bytes.Repeat([]byte{0x0B}, 4096))           // group start, never ended
	f.Add(nestedLengthDelimited(120))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			// A schema built from a descriptor gwaf could not read would
			// validate traffic against nonsense, so an error is the only other
			// acceptable answer.
			sc, _, err := grpc.Parse(data, grpc.Options{})
			if err == nil && sc == nil {
				t.Error("no error and no schema: the caller cannot tell what happened")
			}
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("did not terminate: a descriptor set must not be able to hang the parser")
		}
	})
}

// nestedLengthDelimited builds nested length-delimited fields, which is how a
// wire-format parser is driven into recursion.
func nestedLengthDelimited(n int) []byte {
	buf := []byte{}
	for i := 0; i < n; i++ {
		if len(buf) > 120 {
			break
		}
		buf = append([]byte{0x0A, byte(len(buf))}, buf...)
	}
	return buf
}
