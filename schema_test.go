// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"fmt"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/schema"
)

// ordersAPI is a realistically specified endpoint: a few constrained fields and
// one genuinely free-text field, which is the shape most real APIs have.
func ordersAPI(t testing.TB, strict bool) *schema.Schema {
	t.Helper()
	s, err := schema.New(
		schema.Operation{
			Method: "GET",
			Path:   "/api/v1/orders",
			Strict: strict,
			NoBody: true,
			Query: []schema.Field{
				{Name: "id", Kind: schema.KindInteger},
				{Name: "qty", Kind: schema.KindInteger},
				{Name: "ref", Kind: schema.KindString, Format: schema.FormatUUID},
				{Name: "since", Kind: schema.KindString, Format: schema.FormatDateTime},
				{Name: "status", Kind: schema.KindEnum,
					Enum: []string{"pending", "shipped", "delivered", "cancelled"}},
				{Name: "note", Kind: schema.KindString, Context: schema.ContextText,
					MaxLength: 500},
			},
		},
		schema.Operation{
			Method: "GET",
			Path:   "/api/v1/orders/{id}",
			Query: []schema.Field{
				{Name: "expand", Kind: schema.KindEnum, Enum: []string{"items", "customer"}},
			},
		},
	)
	if err != nil {
		t.Fatalf("schema.New: %v", err)
	}
	return s
}

func schemaReq(t *testing.T, w *gwaf.WAF, target string, args map[string]string) gwaf.Decision {
	t.Helper()
	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", target, "HTTP/1.1")
	for k, v := range args {
		tx.AddArgument(k, v)
	}
	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		return d
	}
	return tx.ProcessRequestBody()
}

// TestSchemaRejectsOutOfSpec is positive security: the request is rejected for
// not being something the API accepts, with no claim about what it was doing.
func TestSchemaRejectsOutOfSpec(t *testing.T) {
	w := newWAF(t, gwaf.WithSchema(ordersAPI(t, false)))

	tests := []struct {
		name string
		args map[string]string
	}{
		{"integer field gets text", map[string]string{"id": "not-a-number"}},
		{"integer field gets payload", map[string]string{"id": "1 UNION SELECT pw"}},
		{"integer field gets float", map[string]string{"qty": "1.5"}},
		{"integer field gets whitespace", map[string]string{"qty": " 1"}},
		{"uuid field malformed", map[string]string{"ref": "not-a-uuid"}},
		{"uuid field truncated", map[string]string{"ref": "550e8400-e29b-41d4-a716"}},
		{"enum field unknown value", map[string]string{"status": "deleted"}},
		{"enum field payload", map[string]string{"status": "<script>"}},
		{"datetime malformed", map[string]string{"since": "yesterday"}},
		{"text field over max length", map[string]string{"note": longString(600)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := schemaReq(t, w, "/api/v1/orders", tt.args)
			if !d.Blocked() {
				t.Errorf("out-of-spec request allowed: %v", tt.args)
			}
			if d.Reason() != gwaf.ReasonSchema {
				t.Errorf("Reason() = %v, want ReasonSchema", d.Reason())
			}
			// The rejection must say which parameter and why, or nobody can
			// tell a client bug from an attack.
			if d.Detail() == "" {
				t.Error("schema rejection carries no detail")
			}
		})
	}
}

func TestSchemaAllowsInSpec(t *testing.T) {
	w := newWAF(t, gwaf.WithSchema(ordersAPI(t, false)))

	tests := []struct {
		name string
		args map[string]string
	}{
		{"integer", map[string]string{"id": "12345"}},
		{"negative integer", map[string]string{"id": "-42"}},
		{"uuid", map[string]string{"ref": "550e8400-e29b-41d4-a716-446655440000"}},
		{"datetime", map[string]string{"since": "2026-08-05T07:38:00Z"}},
		{"datetime with offset", map[string]string{"since": "2026-08-05T07:38:00+07:00"}},
		{"datetime fractional", map[string]string{"since": "2026-08-05T07:38:00.123Z"}},
		{"enum", map[string]string{"status": "shipped"}},
		{"free text", map[string]string{"note": "please deliver before 5pm"}},
		{"text with apostrophe", map[string]string{"note": "it's urgent"}},
		{"all together", map[string]string{
			"id": "1", "qty": "3", "status": "pending",
			"ref": "550e8400-e29b-41d4-a716-446655440000",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if d := schemaReq(t, w, "/api/v1/orders", tt.args); d.Blocked() {
				t.Errorf("in-spec request blocked: reason=%v detail=%q args=%v",
					d.Reason(), d.Detail(), tt.args)
			}
		})
	}
}

// TestSchemaSpecializationSkipsRules is the flagship claim, measured as a
// behaviour rather than asserted in a comment: a value that validates as a
// constrained type evaluates no rules at all, because it provably cannot match
// one.
func TestSchemaSpecializationSkipsRules(t *testing.T) {
	withSchema := newWAF(t, gwaf.WithSchema(ordersAPI(t, false)))
	without := newWAF(t)

	args := map[string]string{
		"id":     "12345",
		"qty":    "7",
		"ref":    "550e8400-e29b-41d4-a716-446655440000",
		"since":  "2026-08-05T07:38:00Z",
		"status": "shipped",
	}

	run := func(w *gwaf.WAF) int {
		tx := w.NewTransaction()
		defer tx.Close()
		tx.SetRequestLine("GET", "/api/v1/orders", "HTTP/1.1")
		for k, v := range args {
			tx.AddArgument(k, v)
		}
		tx.ProcessRequestHeaders()
		return int(tx.FuelSpent())
	}

	specialized := run(withSchema)
	general := run(without)

	if specialized >= general {
		t.Errorf("schema did not reduce work: %d fuel with schema, %d without",
			specialized, general)
	}
	t.Logf("fuel: %d with schema, %d without (%.0f%% reduction)",
		specialized, general, 100*(1-float64(specialized)/float64(general)))
}

// TestFreeTextStillInspected is the necessary counterweight. Specialization
// must not become a blanket exemption: a string field is not constrained, so it
// gets the full pipeline.
func TestFreeTextStillInspected(t *testing.T) {
	w := newWAF(t, gwaf.WithSchema(ordersAPI(t, false)))

	attacks := []string{
		"<script>alert(1)</script>",
		"1 UNION SELECT password FROM users",
		"+ADw-script+AD4-",
		"%253Cscript%253E",
	}

	for _, a := range attacks {
		t.Run(a, func(t *testing.T) {
			d := schemaReq(t, w, "/api/v1/orders", map[string]string{"note": a})
			if !d.Blocked() {
				t.Errorf("payload in a free-text field was not inspected: %q", a)
			}
		})
	}
}

// TestStrictRejectsUndeclaredParameters covers the mode that makes an API
// description a whitelist rather than a hint.
func TestStrictRejectsUndeclaredParameters(t *testing.T) {
	strict := newWAF(t, gwaf.WithSchema(ordersAPI(t, true)))
	lenient := newWAF(t, gwaf.WithSchema(ordersAPI(t, false)))

	args := map[string]string{"debug": "1"}

	d := schemaReq(t, strict, "/api/v1/orders", args)
	if !d.Blocked() {
		t.Error("strict operation accepted an undeclared parameter")
	}
	if d.Reason() != gwaf.ReasonSchema {
		t.Errorf("Reason() = %v, want ReasonSchema", d.Reason())
	}

	if d := schemaReq(t, lenient, "/api/v1/orders", args); d.Blocked() {
		t.Error("lenient operation rejected an undeclared parameter")
	}
}

func TestNoBodyOperationRejectsBody(t *testing.T) {
	w := newWAF(t, gwaf.WithSchema(ordersAPI(t, false)))

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", "/api/v1/orders", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte(`{"unexpected":true}`))

	d := tx.ProcessRequestBody()
	if !d.Blocked() {
		t.Error("body accepted by an operation declaring NoBody")
	}
	if d.Reason() != gwaf.ReasonSchema {
		t.Errorf("Reason() = %v, want ReasonSchema", d.Reason())
	}
}

func TestTemplatedRouteMatching(t *testing.T) {
	w := newWAF(t, gwaf.WithSchema(ordersAPI(t, false)))

	// The templated route declares expand as an enum, so an unknown value is
	// rejected — proving the template matched.
	if d := schemaReq(t, w, "/api/v1/orders/12345",
		map[string]string{"expand": "everything"}); !d.Blocked() {
		t.Error("templated route did not match; enum was not enforced")
	}
	if d := schemaReq(t, w, "/api/v1/orders/12345",
		map[string]string{"expand": "items"}); d.Blocked() {
		t.Error("valid enum value on a templated route was rejected")
	}
}

// TestUnknownRouteFallsBackToFullInspection is the safety property that keeps a
// partial schema from becoming a hole: a route the schema does not describe is
// inspected exactly as if there were no schema at all.
func TestUnknownRouteFallsBackToFullInspection(t *testing.T) {
	w := newWAF(t, gwaf.WithSchema(ordersAPI(t, true)))

	d := schemaReq(t, w, "/legacy/endpoint",
		map[string]string{"q": "1 UNION SELECT password FROM users"})
	if !d.Blocked() {
		t.Error("attack on an undescribed route was not inspected")
	}
	if d.Reason() == gwaf.ReasonSchema {
		t.Error("undescribed route was rejected by schema rather than inspected")
	}
}

// TestSchemaDoesNotWeakenTheEvasionCorpus runs the whole corpus against a WAF
// with a schema that does not describe the corpus routes. Adding a schema must
// never reduce coverage elsewhere.
func TestSchemaDoesNotWeakenTheEvasionCorpus(t *testing.T) {
	w := newWAF(t, gwaf.WithSchema(ordersAPI(t, false)))

	missed := 0
	for _, e := range evasions {
		if d := runEvasion(t, w, e); !d.Blocked() {
			missed++
			t.Errorf("%s not blocked with a schema configured", e.name)
		}
	}
	if missed == 0 {
		t.Logf("all %d evasions still blocked with a schema configured", len(evasions))
	}
}

func TestSchemaDoesNotIntroduceFalsePositives(t *testing.T) {
	w := newWAF(t, gwaf.WithSchema(ordersAPI(t, false)))

	for _, b := range benignTraffic {
		if d := runBenign(t, w, b); d.Blocked() {
			t.Errorf("%s: false positive with a schema configured: reason=%v detail=%q",
				b.name, d.Reason(), d.Detail())
		}
	}
}

// BenchmarkSchemaSpecialized measures the flagship claim.
func BenchmarkSchemaSpecialized(b *testing.B) {
	s, err := schema.New(schema.Operation{
		Method: "GET",
		Path:   "/api/v1/orders",
		Query: []schema.Field{
			{Name: "id", Kind: schema.KindInteger},
			{Name: "qty", Kind: schema.KindInteger},
			{Name: "ref", Kind: schema.KindString, Format: schema.FormatUUID},
			{Name: "since", Kind: schema.KindString, Format: schema.FormatDateTime},
			{Name: "status", Kind: schema.KindEnum,
				Enum: []string{"pending", "shipped", "delivered"}},
		},
	})
	if err != nil {
		b.Fatal(err)
	}

	args := [][2]string{
		{"id", "12345"},
		{"qty", "7"},
		{"ref", "550e8400-e29b-41d4-a716-446655440000"},
		{"since", "2026-08-05T07:38:00Z"},
		{"status", "shipped"},
	}

	for _, tc := range []struct {
		name string
		opts []gwaf.Option
	}{
		{"with_schema", []gwaf.Option{gwaf.WithSchema(s)}},
		{"without_schema", nil},
	} {
		b.Run(tc.name, func(b *testing.B) {
			w := mustWAF(b, tc.opts...)
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				tx := w.NewTransaction()
				tx.SetRequestLine("GET", "/api/v1/orders", "HTTP/1.1")
				for _, a := range args {
					tx.AddArgument(a[0], a[1])
				}
				tx.ProcessRequestHeaders()
				tx.Close()
			}
		})
	}
}

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

var _ = fmt.Sprintf
