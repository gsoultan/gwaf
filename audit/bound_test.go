// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package audit_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/audit"
)

// maxRecordBytes is the ceiling a record may occupy on the wire.
//
// Derived, not chosen: MatchedBytes (256) + Key (256) + Target (256) +
// Exception.Key (256) + Exception.Target (256) + Path (2048) + the fixed
// fields, with room for JSON escaping — which can triple a byte, so the
// ceiling has to allow for the worst case rather than the typical one.
const maxRecordBytes = 16 << 10

// TestRecordIsBoundedRegardlessOfInput is the harness for the claim that an
// audit sink cannot be driven by the request it is describing.
//
// The bug it was written for: a 1 MiB parameter name produced a 3.1 MiB record.
// MatchedBytes was bounded and nothing else was, so the name was written as the
// key, again inside the suggested exception, and a third time inside the
// rendered target ("ARGS:<key>"). A 1 MiB *value* produced 672 bytes, correctly,
// which is exactly why the omission survived review — the field that looked
// dangerous was the one that had been handled.
//
// An audit sink a client can drive to three times its input is the sink becoming
// the outage. Filling a disk or a SIEM quota is a denial of service that also
// destroys the evidence of the attack that caused it.
//
// This asserts the property over the whole record rather than field by field,
// so a field added later that carries attacker input fails here without anyone
// remembering to extend the list.
func TestRecordIsBoundedRegardlessOfInput(t *testing.T) {
	w, err := gwaf.New()
	if err != nil {
		t.Fatal(err)
	}

	const big = 1 << 20
	sqli := "1' OR '1'='1"

	cases := []struct {
		name, key, val, path string
	}{
		{"ordinary", "q", sqli, "/search"},
		{"huge parameter name", strings.Repeat("k", big), sqli, "/search"},
		{"huge value", "q", strings.Repeat("A", big) + sqli, "/search"},
		{"huge path", "q", sqli, "/" + strings.Repeat("p", big)},
		{"huge everything", strings.Repeat("k", big), strings.Repeat("A", big) + sqli, "/" + strings.Repeat("p", big)},
		{"name carries the attack", sqli + strings.Repeat("k", big), "1", "/search"},
		{"multibyte name", strings.Repeat("é", big/2), sqli, "/search"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := w.NewTransaction()
			defer tx.Close()
			tx.SetRequestLine("GET", tc.path, "HTTP/1.1")
			tx.SetRemoteAddr("192.0.2.1")
			tx.AddArgument(tc.key, tc.val)
			d := tx.ProcessRequestHeaders()

			rec := audit.NewRecord(d, audit.Context{
				Method: "GET", Path: tc.path, ClientIP: "192.0.2.1",
			}, time.Now())

			var buf bytes.Buffer
			if err := audit.NewJSON(&buf).Write(rec); err != nil {
				t.Fatalf("write: %v", err)
			}
			if buf.Len() > maxRecordBytes {
				t.Errorf("record is %d bytes from %d bytes of input; ceiling is %d\n"+
					"an audit record that scales with the request lets a client "+
					"fill the sink that is supposed to be recording them",
					buf.Len(), len(tc.key)+len(tc.val)+len(tc.path), maxRecordBytes)
			}
			// Still has to be a record, not just a small one.
			var back map[string]any
			if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
				t.Fatalf("record is not valid JSON: %v", err)
			}
			if d.Blocked() && back["rule_id"] == nil {
				t.Error("a blocking decision produced a record with no rule ID")
			}
		})
	}
}

// FuzzRecordIsBounded pushes the same property with input nobody wrote down.
//
// The table above encodes the shapes a person thought of. This is here because
// the bug it guards against was a field that did not look like it held attacker
// input, and a list of fields a person remembered to check is the thing that
// missed it the first time.
func FuzzRecordIsBounded(f *testing.F) {
	f.Add("q", "1' OR '1'='1", "/search")
	f.Add(strings.Repeat("k", 4096), "<script>alert(1)</script>", "/")
	f.Add("../../etc/passwd", "; cat /etc/passwd", "/a/b")

	w, err := gwaf.New()
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, key, val, path string) {
		// Bound the driver, not the property: the claim is that a record stays
		// small for input of any size, so feeding a gigabyte here would test the
		// fuzzer's memory rather than the record's ceiling.
		if len(key)+len(val)+len(path) > 1<<20 {
			t.Skip()
		}
		tx := w.NewTransaction()
		defer tx.Close()
		tx.SetRequestLine("GET", path, "HTTP/1.1")
		tx.SetRemoteAddr("192.0.2.1")
		tx.AddArgument(key, val)
		d := tx.ProcessRequestHeaders()

		rec := audit.NewRecord(d, audit.Context{Method: "GET", Path: path}, time.Now())
		var buf bytes.Buffer
		if err := audit.NewJSON(&buf).Write(rec); err != nil {
			t.Fatalf("write: %v", err)
		}
		if buf.Len() > maxRecordBytes {
			t.Errorf("record is %d bytes from %d bytes of input (key %d, val %d, path %d)",
				buf.Len(), len(key)+len(val)+len(path), len(key), len(val), len(path))
		}
	})
}
