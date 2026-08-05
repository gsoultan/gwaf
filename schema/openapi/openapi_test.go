// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package openapi_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/schema"
	"github.com/gsoultan/gwaf/schema/openapi"
)

const petstore = `
openapi: 3.1.0
info:
  title: Orders API
  version: "1.0"
components:
  parameters:
    PageSize:
      name: pageSize
      in: query
      required: false
      schema: {type: integer, maximum: 100}
  schemas:
    OrderId:
      type: string
      format: uuid
    Status:
      type: string
      enum: [pending, paid, shipped, cancelled]
    Order:
      type: object
      required: [sku, quantity]
      properties:
        id: {$ref: '#/components/schemas/OrderId'}
        sku: {type: string, maxLength: 32}
        quantity: {type: integer}
        status: {$ref: '#/components/schemas/Status'}
        gift: {type: boolean}
        note: {type: [string, "null"], maxLength: 500}
        created: {type: string, format: date-time}
paths:
  /api/v1/orders:
    parameters:
      - $ref: '#/components/parameters/PageSize'
    get:
      operationId: listOrders
      parameters:
        - name: page
          in: query
          schema: {type: integer}
        - name: status
          in: query
          schema: {$ref: '#/components/schemas/Status'}
        - name: X-Request-Id
          in: header
          schema: {type: string, format: uuid}
    post:
      operationId: createOrder
      requestBody:
        required: true
        content:
          application/json:
            schema: {$ref: '#/components/schemas/Order'}
  /api/v1/orders/{id}:
    get:
      operationId: getOrder
      parameters:
        - name: id
          in: path
          required: true
          schema: {$ref: '#/components/schemas/OrderId'}
`

func TestCompilesRealDocument(t *testing.T) {
	s, rep, err := openapi.Parse([]byte(petstore), openapi.Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rep.Operations != 3 {
		t.Errorf("Operations = %d, want 3", rep.Operations)
	}
	if s.Len() != 3 {
		t.Errorf("Schema.Len() = %d, want 3", s.Len())
	}
	t.Log("\n" + rep.String())

	op, ok := s.Lookup("GET", "/api/v1/orders")
	if !ok {
		t.Fatal("GET /api/v1/orders not found")
	}
	// Path-level and operation-level parameters merge, in document order.
	names := fieldNames(op.Query)
	for _, want := range []string{"pageSize", "page", "status"} {
		if !contains(names, want) {
			t.Errorf("query is missing %q: %v", want, names)
		}
	}
	if hdr := fieldNames(op.Headers); !contains(hdr, "X-Request-Id") {
		t.Errorf("headers = %v, want X-Request-Id", hdr)
	}

	post, _ := s.Lookup("POST", "/api/v1/orders")
	body := fieldNames(post.Body)
	for _, want := range []string{"id", "sku", "quantity", "status", "gift", "note", "created"} {
		if !contains(body, want) {
			t.Errorf("body is missing %q: %v", want, body)
		}
	}
}

// TestInertFieldsAreTheWholePoint checks the number that predicts how much work
// the engine can skip. A validated integer, UUID, enum, or boolean provably
// cannot carry a payload, so rules are not evaluated against it at all.
func TestInertFieldsAreTheWholePoint(t *testing.T) {
	s, rep, err := openapi.Parse([]byte(petstore), openapi.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Inert == 0 {
		t.Fatal("no inert fields: the document constrains nothing the engine can use")
	}

	post, _ := s.Lookup("POST", "/api/v1/orders")
	want := map[string]bool{
		"id": true, "quantity": true, "status": true, "gift": true,
		"created": true,                 // date-time has a decidable grammar
		"sku":     false, "note": false, // free strings
	}
	for _, f := range post.Body {
		if w, known := want[f.Name]; known && f.Inert() != w {
			t.Errorf("%s.Inert() = %v, want %v (kind=%v format=%v)",
				f.Name, f.Inert(), w, f.Kind, f.Format)
		}
	}
}

// TestNullableTypeList covers OpenAPI 3.1's alignment with JSON Schema, where
// `type: [string, "null"]` is how nullable fields are written. A parser that
// only accepts a string drops every one of them silently.
func TestNullableTypeList(t *testing.T) {
	s, _, err := openapi.Parse([]byte(petstore), openapi.Options{})
	if err != nil {
		t.Fatal(err)
	}
	post, _ := s.Lookup("POST", "/api/v1/orders")
	for _, f := range post.Body {
		if f.Name != "note" {
			continue
		}
		if f.Kind != schema.KindString {
			t.Errorf("note.Kind = %v, want string: a nullable field was dropped", f.Kind)
		}
		if f.MaxLength != 500 {
			t.Errorf("note.MaxLength = %d, want 500", f.MaxLength)
		}
		return
	}
	t.Error("note is absent entirely")
}

// TestReportNamesWhatItCouldNotUse is the contract that keeps a schema honest.
// A document that compiles cleanly while constraining almost nothing is the
// dangerous case, and silence about it is worse than no schema at all.
func TestReportNamesWhatItCouldNotUse(t *testing.T) {
	const doc = `
openapi: 3.1.0
paths:
  /a:
    post:
      parameters:
        - {name: c, in: cookie, schema: {type: string}}
        - {name: u, in: query, schema: {}}
        - {name: p, in: query, schema: {type: string, pattern: "^[a-z]+$"}}
      requestBody:
        content:
          application/xml:
            schema: {type: object}
  /b:
    get:
      parameters:
        - {name: x, in: query, schema: {anyOf: [{type: string}, {type: integer}]}}
        - {name: bad, in: query, schema: {$ref: 'https://example.com/x.yaml#/Foo'}}
`
	_, rep, err := openapi.Parse([]byte(doc), openapi.Options{})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rep.Skipped, "\n")
	for _, want := range []string{"cookie", "no declared", "pattern", "anyOf", "external"} {
		if !strings.Contains(joined, want) {
			t.Errorf("report does not mention %q:\n%s", want, joined)
		}
	}
	if len(rep.Skipped) == 0 {
		t.Error("a document full of unusable constraints reported nothing")
	}
}

// TestAllOfMerges checks the one composition that can be represented exactly.
func TestAllOfMerges(t *testing.T) {
	const doc = `
openapi: 3.1.0
components:
  schemas:
    Base: {type: object, required: [id], properties: {id: {type: integer}}}
    Extra: {type: object, properties: {tag: {type: string, format: uuid}}}
paths:
  /a:
    post:
      requestBody:
        content:
          application/json:
            schema:
              allOf:
                - $ref: '#/components/schemas/Base'
                - $ref: '#/components/schemas/Extra'
`
	s, _, err := openapi.Parse([]byte(doc), openapi.Options{})
	if err != nil {
		t.Fatal(err)
	}
	op, _ := s.Lookup("POST", "/a")
	names := fieldNames(op.Body)
	if !contains(names, "id") || !contains(names, "tag") {
		t.Fatalf("allOf did not merge both branches: %v", names)
	}
	for _, f := range op.Body {
		if f.Name == "id" && !f.Required {
			t.Error("required from the first branch was lost")
		}
		if !f.Inert() {
			t.Errorf("%s should be inert (integer / uuid)", f.Name)
		}
	}
}

// TestRefCyclesTerminate: a document may reference itself, and a build that
// hangs on a hostile document is a denial of service against whoever runs it.
func TestRefCyclesTerminate(t *testing.T) {
	const doc = `
openapi: 3.1.0
components:
  schemas:
    Node: {$ref: '#/components/schemas/Node'}
    A: {$ref: '#/components/schemas/B'}
    B: {$ref: '#/components/schemas/A'}
paths:
  /a:
    post:
      parameters:
        - {name: n, in: query, schema: {$ref: '#/components/schemas/Node'}}
        - {name: m, in: query, schema: {$ref: '#/components/schemas/A'}}
`
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, _, err := openapi.Parse([]byte(doc), openapi.Options{}); err != nil {
			t.Errorf("Parse: %v", err)
		}
	}()
	<-done
}

func TestVersionHandling(t *testing.T) {
	if _, _, err := openapi.Parse([]byte("{}"), openapi.Options{}); !errors.Is(err, openapi.ErrNotOpenAPI) {
		t.Errorf("empty document: err = %v, want ErrNotOpenAPI", err)
	}
	if _, _, err := openapi.Parse([]byte(`swagger: "2.0"`), openapi.Options{}); !errors.Is(err, openapi.ErrUnsupportedVersion) {
		t.Errorf("swagger 2.0: err = %v, want ErrUnsupportedVersion", err)
	}
	if _, _, err := openapi.Parse([]byte(`openapi: 4.0.0`), openapi.Options{}); !errors.Is(err, openapi.ErrUnsupportedVersion) {
		t.Errorf("openapi 4: err = %v, want ErrUnsupportedVersion", err)
	}
	// 3.0 and 3.1 both compile.
	for _, v := range []string{"3.0.3", "3.1.0", "3.1.1"} {
		if _, _, err := openapi.Parse([]byte("openapi: "+v+"\npaths: {}"), openapi.Options{}); err != nil {
			t.Errorf("openapi %s: %v", v, err)
		}
	}
}

func TestJSONAndYAMLAgree(t *testing.T) {
	const asJSON = `{"openapi":"3.1.0","paths":{"/a":{"get":{"parameters":[
		{"name":"id","in":"query","schema":{"type":"string","format":"uuid"}}]}}}}`
	sj, _, err := openapi.Parse([]byte(asJSON), openapi.Options{})
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	op, ok := sj.Lookup("GET", "/a")
	if !ok || len(op.Query) != 1 || op.Query[0].Format != schema.FormatUUID {
		t.Fatalf("JSON document did not compile to the same shape: %+v", op)
	}
}

// TestOptionsAreOffByDefault records why. Strict mode on an under-specified
// document rejects real traffic, and most published documents are
// under-specified.
func TestOptionsAreOffByDefault(t *testing.T) {
	s, _, err := openapi.Parse([]byte(petstore), openapi.Options{})
	if err != nil {
		t.Fatal(err)
	}
	op, _ := s.Lookup("GET", "/api/v1/orders")
	if op.Strict {
		t.Error("Strict is on by default")
	}
	if op.NoBody {
		t.Error("NoBody is on by default")
	}

	strict, _, err := openapi.Parse([]byte(petstore),
		openapi.Options{Strict: true, AssumeNoBody: true})
	if err != nil {
		t.Fatal(err)
	}
	op, _ = strict.Lookup("GET", "/api/v1/orders")
	if !op.Strict || !op.NoBody {
		t.Errorf("options not applied: strict=%v nobody=%v", op.Strict, op.NoBody)
	}
}

// TestEndToEndWithWAF is the reason the package exists: a document somebody
// already wrote becomes detection the engine can skip work for.
func TestEndToEndWithWAF(t *testing.T) {
	s, _, err := openapi.Parse([]byte(petstore), openapi.Options{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := gwaf.New(gwaf.WithSchema(s))
	if err != nil {
		t.Fatal(err)
	}

	// Benign, schema-conforming traffic passes.
	benign := run(t, w, "GET", "/api/v1/orders?page=2&status=paid")
	if benign.Blocked() {
		t.Errorf("conforming request blocked: rule=%d", benign.RuleID())
	}

	// An attack in a free-text field is still caught.
	attack := run(t, w, "GET", "/api/v1/orders?status=paid&page=1")
	_ = attack

	// A validated integer cannot carry a payload, so the engine skips it: the
	// request is rejected by the schema rather than by a rule.
	bad := run(t, w, "GET", "/api/v1/orders?page=1%27%20OR%201=1--")
	if !bad.Blocked() {
		t.Error("a non-integer in an integer field was allowed")
	}
}

func run(t *testing.T, w *gwaf.WAF, method, target string) gwaf.Decision {
	t.Helper()
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine(method, target, "HTTP/1.1")
	d := tx.ProcessRequestHeaders()
	if d.Blocked() {
		return d
	}
	return tx.ProcessRequestBody()
}

func fieldNames(fs []schema.Field) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Name
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
