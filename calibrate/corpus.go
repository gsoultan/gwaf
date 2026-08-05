// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package calibrate

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/types"
)

// Request is one benign request in a calibration corpus.
//
// The shape is deliberately close to what an access log holds, so a corpus can
// be built from real traffic rather than invented. A corpus of invented
// requests measures how well the rules match the imagination of whoever wrote
// them.
type Request struct {
	// Name identifies the entry in reports. It should say what kind of traffic
	// this is, so a failure is legible: "search with apostrophe" beats "req-417".
	Name string `json:"name"`

	Method  string            `json:"method,omitempty"`
	Target  string            `json:"target,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Args    map[string]string `json:"args,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// apply feeds the request into a transaction.
func (r *Request) apply(tx *gwaf.Transaction) {
	method := r.Method
	if method == "" {
		method = "GET"
	}
	target := r.Target
	if target == "" {
		target = "/"
	}
	tx.SetRequestLine(method, target, "HTTP/1.1")
	tx.SetRemoteAddr("192.0.2.1")

	for k, v := range r.Headers {
		tx.AddRequestHeader(k, v)
	}
	for k, v := range r.Args {
		tx.AddArgument(k, v)
	}
}

// LoadCorpus reads a JSON Lines corpus.
//
// One request per line keeps a corpus appendable and diffable: adding traffic is
// adding lines, and a review shows exactly which requests were added rather
// than a reformatted document.
//
// A malformed line is an error rather than a skip. Silently dropping entries
// would inflate every measured rate's denominator without anyone noticing,
// which is the one failure mode that makes a calibration report lie.
func LoadCorpus(r io.Reader) ([]Request, error) {
	var out []Request
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)

	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(b) == 0 || b[0] == '#' {
			continue
		}

		var req Request
		if err := json.Unmarshal(b, &req); err != nil {
			return nil, fmt.Errorf("calibrate: line %d: %w", line, err)
		}
		if req.Name == "" {
			req.Name = fmt.Sprintf("line %d", line)
		}
		out = append(out, req)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("calibrate: reading corpus: %w", err)
	}
	return out, nil
}

// LoadCorpusFile reads a JSON Lines corpus from a path.
func LoadCorpusFile(path string) ([]Request, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("calibrate: %w", err)
	}
	defer f.Close()
	return LoadCorpus(f)
}

// NewWAF builds a WAF configured for measurement.
//
// Three settings matter and all three are easy to get wrong by hand:
//
//   - Detection-only, so a blocking rule does not end the transaction and hide
//     every rule that would have matched afterwards.
//   - The lowest minimum confidence, so every rule is compiled in. A production
//     policy runs a subset; calibration has to measure the whole set, including
//     the tiers that policy would exclude.
//   - Unmetered fuel, so a large corpus entry is measured rather than cut short
//     by a budget that only exists to bound production latency.
func NewWAF(opts ...gwaf.Option) (*gwaf.WAF, error) {
	base := []gwaf.Option{
		gwaf.WithMode(gwaf.DetectionOnly),
		gwaf.WithMinConfidence(types.Heuristic),
		gwaf.WithFuelLimit(0),
	}
	return gwaf.New(append(base, opts...)...)
}
