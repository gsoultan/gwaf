// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package telemetry_test

import (
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/telemetry"
)

// drive runs one request through a real WAF and returns the decision, so the
// counters are exercised against decisions gwaf actually produces rather than
// values constructed to make the test pass.
func drive(t *testing.T, w *gwaf.WAF, target, arg string) gwaf.Decision {
	t.Helper()
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", target, "HTTP/1.1")
	if arg != "" {
		tx.AddArgument("q", arg)
	}
	d := tx.ProcessRequestHeaders()
	if !d.Blocked() {
		d = tx.Decision()
	}
	return d
}

func TestMetricsCountDecisions(t *testing.T) {
	w, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	var m telemetry.Metrics

	m.Observe(drive(t, w, "/s", "hello world"), 900*time.Nanosecond)
	m.Observe(drive(t, w, "/s", "1' OR 1=1--"), 1200*time.Nanosecond)
	m.Observe(drive(t, w, "/s", "<script>alert(1)</script>"), 1100*time.Nanosecond)

	s := m.Snapshot()
	if s.Requests != 3 {
		t.Errorf("requests = %d, want 3", s.Requests)
	}
	if s.Blocked != 2 {
		t.Errorf("blocked = %d, want 2", s.Blocked)
	}
	if s.Allowed != 1 {
		t.Errorf("allowed = %d, want 1", s.Allowed)
	}
	if got := s.BlockRate(); got < 0.66 || got > 0.67 {
		t.Errorf("block rate = %v, want ~0.667", got)
	}
	if s.MeanLatency == 0 || s.MaxLatency != 1200*time.Nanosecond {
		t.Errorf("latency mean=%v max=%v, want non-zero mean and 1.2µs max", s.MeanLatency, s.MaxLatency)
	}
	if len(s.ByRule) != 2 {
		t.Errorf("ByRule has %d entries, want 2 (sqli, xss): %v", len(s.ByRule), s.ByRule)
	}
	if s.BySeverity["critical"] != 2 {
		t.Errorf("critical count = %d, want 2", s.BySeverity["critical"])
	}
}

// TestSnapshotIsACopy guards the contract that a Snapshot is safe to keep: a
// caller mutating it, or more traffic arriving, must not change what they read.
func TestSnapshotIsACopy(t *testing.T) {
	w, _ := gwaf.New()
	var m telemetry.Metrics
	m.Observe(drive(t, w, "/s", "1' OR 1=1--"), 0)

	s := m.Snapshot()
	before := len(s.ByRule)
	s.ByRule[999999] = 42 // caller mutates their copy

	m.Observe(drive(t, w, "/s", "<script>alert(1)</script>"), 0)
	if got := len(m.Snapshot().ByRule); got != before+1 {
		t.Errorf("ByRule = %d entries after one more rule, want %d", got, before+1)
	}
}

func TestTopRules(t *testing.T) {
	w, _ := gwaf.New()
	var m telemetry.Metrics
	for i := 0; i < 5; i++ {
		m.Observe(drive(t, w, "/s", "1' OR 1=1--"), 0)
	}
	m.Observe(drive(t, w, "/s", "<script>alert(1)</script>"), 0)

	top := m.Snapshot().TopRules(2)
	if len(top) != 2 {
		t.Fatalf("TopRules(2) returned %d", len(top))
	}
	if top[0].Count != 5 {
		t.Errorf("most-fired rule count = %d, want 5", top[0].Count)
	}
	if top[0].Count < top[1].Count {
		t.Error("TopRules is not sorted most-frequent first")
	}
}

func TestUndeclaredCounter(t *testing.T) {
	var m telemetry.Metrics
	m.ObserveUndeclared()
	m.ObserveUndeclared()
	if got := m.Snapshot().Undeclared; got != 2 {
		t.Errorf("undeclared = %d, want 2", got)
	}
}

func TestReset(t *testing.T) {
	w, _ := gwaf.New()
	var m telemetry.Metrics
	m.Observe(drive(t, w, "/s", "1' OR 1=1--"), time.Microsecond)
	m.Reset()

	s := m.Snapshot()
	if s.Requests != 0 || s.Blocked != 0 || len(s.ByRule) != 0 || s.MaxLatency != 0 {
		t.Errorf("counters not cleared: %+v", s)
	}
}

// TestConcurrentObserve backs the documented concurrency claim. Metrics says it
// is safe for any number of goroutines, and an unsynchronised map write here
// would be a data race rather than a wrong number — which is why this runs
// under -race in the gate.
func TestConcurrentObserve(t *testing.T) {
	w, _ := gwaf.New()
	var m telemetry.Metrics

	const goroutines, each = 8, 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				arg := "hello"
				if i%2 == 0 {
					arg = "1' OR 1=1--"
				}
				tx := w.NewTransaction()
				tx.SetRequestLine("GET", "/s", "HTTP/1.1")
				tx.AddArgument("q", arg)
				d := tx.ProcessRequestHeaders()
				if !d.Blocked() {
					d = tx.Decision()
				}
				m.Observe(d, time.Duration(i)*time.Nanosecond)
				tx.Close()
			}
		}(g)
	}
	wg.Wait()

	s := m.Snapshot()
	if s.Requests != goroutines*each {
		t.Errorf("requests = %d, want %d", s.Requests, goroutines*each)
	}
	if s.Blocked+s.Allowed != s.Requests {
		t.Errorf("blocked(%d) + allowed(%d) != requests(%d)", s.Blocked, s.Allowed, s.Requests)
	}
}
