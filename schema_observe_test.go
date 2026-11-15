// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/schema"
)

// observed drives one request through a WAF running the orders API under
// SchemaObserve and returns the final decision and the recorded violation.
func observed(t *testing.T, s *schema.Schema, method, target string, args map[string]string, body string) (gwaf.Decision, schema.Violation, string) {
	t.Helper()
	w := newWAF(t, gwaf.WithSchema(s), gwaf.WithSchemaMode(gwaf.SchemaObserve))
	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine(method, target, "HTTP/1.1")
	for k, v := range args {
		tx.AddArgument(k, v)
	}
	d := tx.ProcessRequestHeaders()
	if !d.Blocked() {
		if body != "" {
			tx.AddRequestHeader("Content-Type", "text/plain")
			tx.SetRequestBody([]byte(body))
		}
		d = tx.ProcessRequestBody()
	}
	v, at := tx.SchemaViolation()
	return d, v, at
}

// TestSchemaObserveRecordsWithoutRefusing covers every way a request can fall
// outside the schema: each is refused under the default mode (the tests beside
// this one) and must be let through and named under SchemaObserve.
func TestSchemaObserveRecordsWithoutRefusing(t *testing.T) {
	tests := []struct {
		name   string
		schema *schema.Schema
		method string
		target string
		args   map[string]string
		body   string
		want   schema.Violation
		at     string
	}{
		{"wrong type", ordersAPI(t, false), "GET", "/api/v1/orders",
			map[string]string{"id": "not-a-number"}, "", schema.ViolationType, "id"},
		{"not in the enum", ordersAPI(t, false), "GET", "/api/v1/orders",
			map[string]string{"status": "deleted"}, "", schema.ViolationEnum, "status"},
		{"undeclared parameter, strict", ordersAPI(t, true), "GET", "/api/v1/orders",
			map[string]string{"debug": "1"}, "", schema.ViolationUndeclared, "debug"},
		{"body to an operation that declares none", ordersAPI(t, false), "GET", "/api/v1/orders",
			nil, "hello", schema.ViolationBody, ""},
		{"path a closed schema does not describe", ordersAPI(t, false).Closed(), "GET", "/admin",
			nil, "", schema.ViolationUndeclared, "/admin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, v, at := observed(t, tt.schema, tt.method, tt.target, tt.args, tt.body)
			if d.Blocked() {
				t.Fatalf("refused under SchemaObserve: reason %v, detail %q", d.Reason(), d.Detail())
			}
			if v != tt.want || at != tt.at {
				t.Errorf("SchemaViolation() = %v at %q, want %v at %q", v, at, tt.want, tt.at)
			}
		})
	}
}

// TestSchemaObserveStillBlocksAttacks is the reason the mode exists rather
// than DetectionOnly: trying a schema must not cost the rules.
func TestSchemaObserveStillBlocksAttacks(t *testing.T) {
	tests := []struct {
		name string
		args map[string]string
		want schema.Violation
	}{
		// The value that fails validation is the one carrying the payload, so
		// it must not be treated as inert.
		{"payload in a field that fails validation",
			map[string]string{"id": "1 UNION SELECT password FROM users--"}, schema.ViolationType},
		// A violation elsewhere in the request must not end inspection of the
		// free-text field.
		{"payload beside a violation",
			map[string]string{"id": "abc", "note": "' OR 1=1 UNION SELECT password FROM users--"}, schema.ViolationType},
		{"payload in a request inside the schema",
			map[string]string{"note": "' OR 1=1 UNION SELECT password FROM users--"}, schema.ViolationNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, v, _ := observed(t, ordersAPI(t, false), "GET", "/api/v1/orders", tt.args, "")
			if !d.Blocked() {
				t.Fatal("attack allowed under SchemaObserve")
			}
			if d.Reason() == gwaf.ReasonSchema {
				t.Error("refused for the schema, which SchemaObserve must not do")
			}
			if v != tt.want {
				t.Errorf("SchemaViolation() = %v, want %v", v, tt.want)
			}
		})
	}
}

func TestSchemaObserveReportsNothingForARequestInsideTheSchema(t *testing.T) {
	d, v, at := observed(t, ordersAPI(t, false), "GET", "/api/v1/orders",
		map[string]string{"id": "42", "status": "shipped"}, "")
	if d.Blocked() || v != schema.ViolationNone || at != "" {
		t.Errorf("blocked=%v violation=%v at %q, want an allowed request with no violation", d.Blocked(), v, at)
	}
}

// TestSchemaViolationIsClearedBetweenTransactions guards the pooled
// transaction: a violation read from the previous request would file one
// client's mistake under another's.
func TestSchemaViolationIsClearedBetweenTransactions(t *testing.T) {
	w := newWAF(t, gwaf.WithSchema(ordersAPI(t, false)), gwaf.WithSchemaMode(gwaf.SchemaObserve))
	for i, id := range []string{"abc", "42"} {
		tx := w.NewTransaction()
		tx.SetRequestLine("GET", "/api/v1/orders", "HTTP/1.1")
		tx.AddArgument("id", id)
		tx.ProcessRequestHeaders()
		tx.ProcessRequestBody()
		v, _ := tx.SchemaViolation()
		tx.Close()
		if want := []schema.Violation{schema.ViolationType, schema.ViolationNone}[i]; v != want {
			t.Errorf("request %d: SchemaViolation() = %v, want %v", i, v, want)
		}
	}
}

func TestSchemaModeString(t *testing.T) {
	if gwaf.SchemaEnforce.String() != "enforce" || gwaf.SchemaObserve.String() != "observe" {
		t.Errorf("String() = %q, %q", gwaf.SchemaEnforce, gwaf.SchemaObserve)
	}
	if schema.ViolationBody.String() != "unexpected_body" {
		t.Errorf("ViolationBody.String() = %q", schema.ViolationBody)
	}
}
