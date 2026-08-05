// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Command gen builds the benign calibration corpus.
//
// # Why this file exists rather than a hand-typed JSONL blob
//
// A generator can be reviewed against the surface it claims to model. A
// reviewer can see exactly which parts are drawn from a real API and which are
// invented, which is not true of ten thousand lines of JSON.
//
// # What the corpus is for, and what it cannot do
//
// Confidence is a measured property (docs/CONCEPT.md §8): a rule declaring
// Certain claims a false-positive rate below one in ten thousand, and
// `gwaf calibrate` fails the build when the corpus disagrees. Statistical power
// is bounded by the number of *distinct* requests, so padding with
// near-duplicates lowers the reported minimum detectable rate without making
// the measurement mean more. Everything here differs in ways a rule can
// actually see.
//
// The honest limit: synthetic traffic can falsify a confidence claim, never
// confirm one. A rule surviving ten thousand generated requests has been shown
// not to match *these* — worth having, and not the same as a measured rate
// against production. Real access logs remain the thing that would make this
// corpus mean what its size implies.
//
// # Why several application archetypes rather than one
//
// The corpus was drawn entirely from one application, and that is a measurement
// bias rather than merely a size limit: a detector can only be shown safe
// against traffic shapes it has actually met. Each archetype exists because it
// carries something no other one does —
//
//   - commerce:  free-text search, prices, addresses, apostrophes at volume
//   - cms:       template syntax authored on purpose, the sharpest SSTI risk
//   - graphql:   one endpoint, a whole query language in the body
//   - grpcweb:   binary framing a text detector must not read as prose
//   - odata:     $filter and friends, colliding with MongoDB operators
//   - jsonapi:   bracketed parameter names, colliding with NoSQL injection
//   - saas:      admin surfaces carrying regexes, CIDRs, and secrets
//   - webhooks:  third-party payloads nobody controls the shape of
//   - mobile:    compact clients, base64 blobs, unusual header sets
//   - cicd:      shell commands and template expressions travelling as data
//
// The last is deliberate. A CI configuration API legitimately carries
// `make build && ./deploy.sh` in a JSON field: a shell command travelling as
// data, which is exactly what detect/shelli must not report. Every archetype
// here was chosen to be adversarial to a specific detector rather than to be
// representative of the web in general.
//
//	go run ./testdata/corpus/gen > testdata/corpus/benign.jsonl
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type request struct {
	Name    string            `json:"name"`
	Method  string            `json:"method,omitempty"`
	Target  string            `json:"target,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Args    map[string]string `json:"args,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// archetype is one application shape, emitted as a group so the generator can
// report per shape rather than as one undifferentiated pile.
type archetype struct {
	name string
	emit func(func(request))
}

var archetypes = []archetype{
	{"gateon", emitGateon},
	{"commerce", emitCommerce},
	{"cms", emitCMS},
	{"graphql", emitGraphQL},
	{"grpcweb", emitGRPCWeb},
	{"odata", emitOData},
	{"jsonapi", emitJSONAPI},
	{"saas", emitSaaS},
	{"webhooks", emitWebhooks},
	{"mobile", emitMobile},
	{"cicd", emitCICD},
}

func main() {
	enc := json.NewEncoder(os.Stdout)
	seen := map[string]bool{}

	fmt.Println("# gwaf benign calibration corpus.")
	fmt.Println("# Generated: go run ./testdata/corpus/gen > testdata/corpus/benign.jsonl")
	fmt.Println("#")
	fmt.Println("# Several application archetypes, because a detector can only be shown")
	fmt.Println("# safe against traffic shapes it has actually met. Shapes are modelled")
	fmt.Println("# on real APIs; values are plausible, not captured from production.")
	fmt.Println("# See testdata/corpus/gen/main.go for the limits.")

	total := 0
	for _, a := range archetypes {
		n := 0
		a.emit(func(r request) {
			key := r.Method + " " + r.Target + " " + r.Body + fmt.Sprint(r.Args)
			if seen[key] {
				return
			}
			seen[key] = true
			r.Name = a.name + "/" + r.Name
			if err := enc.Encode(r); err != nil {
				panic(err)
			}
			n++
		})
		fmt.Fprintf(os.Stderr, "%-10s %6d\n", a.name, n)
		total += n
	}
	fmt.Fprintf(os.Stderr, "%-10s %6d distinct benign requests\n", "total", total)
}
