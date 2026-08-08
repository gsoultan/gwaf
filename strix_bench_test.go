// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

// Benchmarks matching the Coraza comparison harness request-for-request, so the
// latency and allocation numbers in the Strix write-up are measured on the same
// workload rather than quoted from two different suites.

import (
	"testing"

	"github.com/gsoultan/gwaf"
)

// Benign GET, no body. gwaf's SLO for this workload is p50 < 2us, 0 allocations.
func BenchmarkStrixBenignGET(b *testing.B) {
	w, err := gwaf.New()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		tx := w.NewTransaction()
		tx.SetRemoteAddr("192.0.2.1")
		tx.AddRequestHeader("Host", "example.com")
		tx.AddRequestHeader("User-Agent", "Mozilla/5.0 Chrome/120.0")
		tx.AddRequestHeader("Accept", "text/html,*/*")
		tx.SetRequestLine("GET", "/search?q=hello+world", "HTTP/1.1")
		tx.ProcessRequestHeaders()
		tx.ProcessRequestBody()
		tx.Close()
	}
}

// Benign POST with a ~1KB JSON body. gwaf's SLO is p50 < 15us, < 4KB.
func BenchmarkStrixBenignPOSTJSON(b *testing.B) {
	w, err := gwaf.New()
	if err != nil {
		b.Fatal(err)
	}
	body := benchBody()
	b.ReportAllocs()
	for b.Loop() {
		tx := w.NewTransaction()
		tx.SetRemoteAddr("192.0.2.1")
		tx.AddRequestHeader("Host", "example.com")
		tx.AddRequestHeader("User-Agent", "Mozilla/5.0 Chrome/120.0")
		tx.AddRequestHeader("Accept", "text/html,*/*")
		tx.AddRequestHeader("Content-Type", "application/json")
		tx.SetRequestLine("POST", "/api/order", "HTTP/1.1")
		tx.ProcessRequestHeaders()
		tx.SetRequestBody(body)
		tx.ProcessRequestBody()
		tx.Close()
	}
}

// benchBody builds the same ~1KB JSON document the Coraza harness sends.
func benchBody() []byte {
	pad := make([]byte, 0, 900)
	for len(pad) < 880 {
		pad = append(pad, "the quick brown fox jumps over the lazy dog. "...)
	}
	return []byte(`{"user":"alice","items":[{"sku":"A1","qty":2},{"sku":"B2","qty":1}],"note":"` +
		string(pad[:880]) + `"}`)
}
