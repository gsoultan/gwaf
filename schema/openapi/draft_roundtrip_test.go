// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package openapi_test

import (
	"bytes"
	"reflect"
	"strconv"
	"testing"

	"github.com/gsoultan/gwaf/schema"
	"github.com/gsoultan/gwaf/schema/infer"
	"github.com/gsoultan/gwaf/schema/openapi"
)

// A draft is only useful if the document it writes compiles back to the
// operations it was written from. The writer lives in core, which cannot
// import this module, so the claim is checked here.
func TestALearnedDraftCompilesBackToWhatWasLearned(t *testing.T) {
	l := infer.New(infer.Limits{MinSamples: 3})
	for i := range 10 {
		l.Observe("GET", "/orders/"+strconv.Itoa(100+i), []infer.Pair{
			{Name: "page", Value: strconv.Itoa(i)},
			{Name: "price", Value: strconv.Itoa(i) + ".5"},
			{Name: "open", Value: "true"},
			{Name: "customer", Value: "123e4567-e89b-12d3-a456-42661417400" + strconv.Itoa(i)},
			{Name: "q", Value: "shoes"},
		})
		l.Observe("POST", "/orders", nil)
	}
	drafted := l.Draft()

	var doc bytes.Buffer
	if err := infer.WriteOpenAPI(&doc, "Draft", drafted); err != nil {
		t.Fatal(err)
	}
	compiled, report, err := openapi.Compile(doc.Bytes(), openapi.Options{})
	if err != nil {
		t.Fatalf("the draft does not compile: %v\n%s", err, doc.String())
	}
	t.Logf("report: %+v", report)

	type shape struct {
		Method, Path string
		Query        map[string]schema.Field
	}
	shapes := func(ops []schema.Operation) []shape {
		var out []shape
		for _, op := range ops {
			s := shape{Method: op.Method, Path: op.Path, Query: map[string]schema.Field{}}
			for _, f := range op.Query {
				s.Query[f.Name] = schema.Field{Name: f.Name, Kind: f.Kind, Format: f.Format, MaxLength: f.MaxLength}
			}
			out = append(out, s)
		}
		return out
	}
	want, got := shapes(drafted), shapes(compiled)
	if len(want) != 2 {
		t.Fatalf("drafted %d operations, want 2", len(want))
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g.Method == w.Method && g.Path == w.Path {
				found = true
				if !reflect.DeepEqual(g.Query, w.Query) {
					t.Errorf("%s %s compiled back as\n %+v\nwant\n %+v", w.Method, w.Path, g.Query, w.Query)
				}
			}
		}
		if !found {
			t.Errorf("%s %s is missing from the compiled document: %+v", w.Method, w.Path, got)
		}
	}
}
