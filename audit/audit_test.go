// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package audit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/audit"
	"github.com/gsoultan/gwaf/types"
)

func blockedDecision(t *testing.T) gwaf.Decision {
	t.Helper()
	w, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/search?q=x", "HTTP/1.1")
	tx.AddArgument("q", "1' OR 1=1--")
	d := tx.ProcessRequestHeaders()
	if !d.Blocked() {
		t.Fatal("expected the injection to be blocked")
	}
	return d
}

// TestRecordIsActionable is the claim this package exists to make: the record
// answers "why was this blocked, and what do I do about it?" on its own.
func TestRecordIsActionable(t *testing.T) {
	rec := audit.NewRecord(blockedDecision(t), audit.Context{
		Method: "GET", Path: "/search", ClientIP: "192.0.2.1", Route: "api",
	}, time.Now())

	if !rec.Blocked || rec.RuleID == 0 {
		t.Fatalf("record does not describe a block: %+v", rec)
	}
	if rec.MatchedBytes == "" {
		t.Error("matched_bytes empty: the operator cannot see what matched")
	}
	if len(rec.TransformChain) == 0 {
		t.Error("transform_chain empty: a decoded match is unexplained")
	}
	if rec.SuggestedException == nil {
		t.Fatal("no suggested exception: a false positive here has no scoped fix")
	}
	if rec.SuggestedException.Target == "" {
		t.Error("suggested exception has no target, so it would suppress the rule globally")
	}
	if rec.Method != "GET" || rec.ClientIP != "192.0.2.1" || rec.Route != "api" {
		t.Errorf("caller context not carried through: %+v", rec)
	}
}

// TestMatchedBytesAreBounded guards the log against becoming an attack surface:
// the span is attacker-controlled and ends up in a SIEM.
func TestMatchedBytesAreBounded(t *testing.T) {
	rec := audit.NewRecord(blockedDecision(t), audit.Context{}, time.Now())
	if len(rec.MatchedBytes) > audit.MaxMatchedBytes {
		t.Errorf("matched bytes = %d, want <= %d", len(rec.MatchedBytes), audit.MaxMatchedBytes)
	}
}

// TestJSONSinkWritesOnePerLine pins the format: appendable and tailable, so a
// log that is never closed is still valid.
func TestJSONSinkWritesOnePerLine(t *testing.T) {
	var buf bytes.Buffer
	s := audit.NewJSON(&buf)

	rec := audit.NewRecord(blockedDecision(t), audit.Context{Path: "/a"}, time.Now())
	for i := 0; i < 3; i++ {
		if err := s.Write(rec); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("wrote %d lines, want 3", len(lines))
	}
	for i, l := range lines {
		var out audit.Record
		if err := json.Unmarshal([]byte(l), &out); err != nil {
			t.Errorf("line %d is not valid JSON on its own: %v", i, err)
		}
	}
}

func TestRelevantOnlyDropsQuietRecords(t *testing.T) {
	var buf bytes.Buffer
	s := audit.NewJSON(&buf)
	s.RelevantOnly = true

	if err := s.Write(audit.Record{Path: "/health"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("quiet record was written: %s", buf.String())
	}

	if err := s.Write(audit.NewRecord(blockedDecision(t), audit.Context{}, time.Now())); err != nil {
		t.Fatalf("write: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("a block was dropped by RelevantOnly")
	}
}

// failingSink reports an error so Multi's contract can be checked.
type failingSink struct{ called bool }

func (f *failingSink) Write(audit.Record) error { f.called = true; return errors.New("disk full") }

type countingSink struct{ n int }

func (c *countingSink) Write(audit.Record) error { c.n++; return nil }

// TestMultiTriesEverySink is the availability contract: a full disk must not
// stop the record reaching the SIEM.
func TestMultiTriesEverySink(t *testing.T) {
	bad := &failingSink{}
	good := &countingSink{}
	m := audit.Multi{bad, good}

	err := m.Write(audit.Record{})
	if err == nil {
		t.Error("Multi swallowed the sink error")
	}
	if !bad.called || good.n != 1 {
		t.Errorf("not every sink was attempted: bad=%v good=%d", bad.called, good.n)
	}
}

func TestSeverityFilter(t *testing.T) {
	c := &countingSink{}
	s := audit.SeverityAtLeast(types.SeverityError, c)

	// Below the floor: dropped.
	if err := s.Write(audit.Record{RuleID: 1, Severity: "warning"}); err != nil {
		t.Fatal(err)
	}
	// At the floor and above: kept.
	_ = s.Write(audit.Record{RuleID: 2, Severity: "error"})
	_ = s.Write(audit.Record{RuleID: 3, Severity: "critical"})
	// No rule matched, so no severity: passed through, because the traffic shape
	// is still worth seeing.
	_ = s.Write(audit.Record{Path: "/x"})

	if c.n != 3 {
		t.Errorf("filter passed %d records, want 3", c.n)
	}
}

// TestConcurrentWrite backs the documented claim that a Sink is safe for
// concurrent use. Under -race an unsynchronised writer would fail here.
func TestConcurrentWrite(t *testing.T) {
	var buf bytes.Buffer
	s := audit.NewJSON(&buf)

	var wg sync.WaitGroup
	wg.Add(8)
	for g := 0; g < 8; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				_ = s.Write(audit.Record{Path: "/x", Blocked: true})
			}
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 200 {
		t.Errorf("wrote %d lines, want 200 — a concurrent write was lost or interleaved", len(lines))
	}
}
