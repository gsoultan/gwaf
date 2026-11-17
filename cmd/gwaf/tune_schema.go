// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/gsoultan/gwaf/calibrate"
	"github.com/gsoultan/gwaf/schema/infer"
)

// draftSchema writes the OpenAPI document the corpus implies.
//
// It is the positive-security counterpart of the exceptions tune suggests, and
// it follows the same rule: this prints, and a human reads it before anything
// enforces it. A draft is a description of what traffic looked like during the
// capture, which is not the same thing as what the API accepts -- an endpoint
// nobody called that week is absent, and a parameter that only ever held
// numbers is declared an integer whether or not the application agrees.
//
// The draft is loose on purpose (see infer.Learner.Draft): nothing is required,
// nothing is strict, and no value seen in the corpus appears in the output.
func draftSchema(out, diag io.Writer, corpus []calibrate.Request, minSamples int) error {
	if minSamples < 1 {
		return fmt.Errorf("-min-samples must be at least 1")
	}
	limits := infer.DefaultLimits()
	limits.MinSamples = minSamples
	l := infer.New(limits)

	for i := range corpus {
		method, path, query := shapeOf(&corpus[i])
		l.Observe(method, path, query)
	}

	ops := l.Draft()
	st := l.Stats()
	fmt.Fprintf(diag,
		"gwaf tune: drafted %d operations from %d of %d requests (at least %d each).\n",
		len(ops), st.Observed, len(corpus), minSamples)
	if n := len(corpus) - int(st.Observed); n > 0 {
		fmt.Fprintf(diag, "  %d requests were left out: an unusable method or path, or past the %d-operation limit.\n",
			n, limits.MaxOperations)
	}
	if st.DroppedFields > 0 {
		fmt.Fprintf(diag, "  %d parameters were left out: an unusable name, or past %d per operation.\n",
			st.DroppedFields, limits.MaxFields)
	}
	if len(ops) == 0 {
		return fmt.Errorf("nothing was seen %d times; capture more traffic or lower -min-samples", minSamples)
	}
	fmt.Fprintln(diag, "  Review it before enforcing it: it describes the capture, not the API.")
	return infer.WriteOpenAPI(out, "Draft learned from traffic", ops)
}

// shapeOf reads a corpus entry the way a transaction would see it: the query
// string on the target and the entry's own arguments are both parameters.
func shapeOf(r *calibrate.Request) (method, path string, query []infer.Pair) {
	method = r.Method
	if method == "" {
		method = "GET"
	}
	path = r.Target
	if path == "" {
		path = "/"
	}
	raw := ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, raw = path[:i], path[i+1:]
	}
	// A query string that does not parse contributes what did parse. The
	// learner bounds and vets names itself.
	values, _ := url.ParseQuery(raw)
	for name, vs := range values {
		for _, v := range vs {
			query = append(query, infer.Pair{Name: name, Value: v})
		}
	}
	for name, v := range r.Args {
		query = append(query, infer.Pair{Name: name, Value: v})
	}
	return method, path, query
}
