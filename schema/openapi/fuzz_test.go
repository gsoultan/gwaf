// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package openapi_test

import (
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gwaf/schema/openapi"
)

// An OpenAPI document is YAML, and this package had no fuzz target.
//
// The trust argument is the same one seclang and schema/grpc needed. A spec is
// usually a build artefact, but Parse is exported and docs/PERFORMANCE.md says
// never to trust a runtime-supplied schema — a control plane loading a tenant's
// spec is parsing somebody else's bytes, and YAML is a format with a history of
// making that expensive: anchors and aliases expand, and "billion laughs" was a
// YAML attack before it was an XML one.
//
// A schema built from a document gwaf could not read would validate traffic
// against nonsense, so an error is the only acceptable alternative to a schema.
func FuzzParseDocument(f *testing.F) {
	f.Add("")
	f.Add("openapi: 3.1.0\npaths:\n  /a:\n    get: {}\n")
	f.Add("{}")
	f.Add("[")
	f.Add("\x00\x00\x00")
	f.Add(strings.Repeat("- ", 4096)) // deep sequence nesting
	f.Add(strings.Repeat("{", 4096))  // deep flow mapping
	f.Add("a: &x [1]\nb: *x\n")       // an alias
	// The YAML expansion bomb, in the shape that made it famous.
	f.Add("a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n" +
		"c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n")

	f.Fuzz(func(t *testing.T, doc string) {
		if len(doc) > 1<<20 {
			t.Skip()
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			sc, _, err := openapi.Parse([]byte(doc), openapi.Options{})
			if err == nil && sc == nil {
				t.Error("no error and no schema: the caller cannot tell what happened")
			}
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("did not terminate: a document must not be able to hang the parser")
		}
	})
}
