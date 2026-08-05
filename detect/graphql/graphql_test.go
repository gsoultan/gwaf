// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package graphql

import (
	"fmt"
	"strings"
	"testing"
)

func TestStructuralAbuseIsDetected(t *testing.T) {
	d := New(Limits{})

	deep := "query{" + strings.Repeat("a{", 200) + "id" + strings.Repeat("}", 200) + "}"

	var aliases strings.Builder
	aliases.WriteString("query{")
	for i := range 2000 {
		fmt.Fprintf(&aliases, "a%d:expensiveField(id:1){x} ", i)
	}
	aliases.WriteString("}")

	var wide strings.Builder
	wide.WriteString("query{")
	for i := range 1500 {
		fmt.Fprintf(&wide, "field%d ", i)
	}
	wide.WriteString("}")

	cases := []struct {
		name string
		doc  string
		want Signal
	}{
		{"depth bomb", deep, SignalExcessiveDepth},
		{"alias amplification", aliases.String(), SignalAliasAmplification},
		{"field count", wide.String(), SignalExcessiveComplexity},
		{"introspection", `{__schema{types{name fields{name}}}}`, SignalIntrospection},
		{"introspection by type", `{__type(name:"User"){fields{name}}}`, SignalIntrospection},
		{"direct fragment cycle", `{...A} fragment A on Q{...A}`, SignalFragmentCycle},
		{"indirect fragment cycle", `{...A} fragment A on Q{...B} fragment B on Q{...A}`, SignalFragmentCycle},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := d.Analyze([]byte(c.doc))
			if !v.Detected() {
				t.Fatalf("not detected: depth=%d fields=%d maxAlias=%d",
					v.Depth, v.Fields, v.MaxAlias)
			}
			if v.Signals&c.want == 0 {
				t.Errorf("signals = %v, want %v set", v.Signals, c.want)
			}
		})
	}
}

// TestRealQueriesPass is the counterweight, and it is the table that decides
// whether these limits can ship enabled.
func TestRealQueriesPass(t *testing.T) {
	d := New(Limits{})

	docs := []string{
		`query GetUser($id: ID!) { user(id: $id) { id name email } }`,
		`query ListOrders($first: Int!, $after: String) { orders(first: $first, after: $after) { edges { node { id total status } } pageInfo { hasNextPage endCursor } } }`,
		`mutation CreateOrder($input: OrderInput!) { createOrder(input: $input) { id status } }`,
		`query Search($term: String!) { search(term: $term) { __typename ... on Product { sku price } ... on Article { title } } }`,
		`query { viewer { id permissions roles { name scopes } } }`,
		`subscription OnOrderUpdate($id: ID!) { orderUpdated(orderId: $id) { id status updatedAt } }`,
		`query WithFragment { orders { ...OrderFields } } fragment OrderFields on Order { id total customer { name } }`,
		`query Aliased { a: user(id: "1") { name } b: user(id: "2") { name } }`,
		`query Deep { org { teams { members { user { profile { avatar { url } } } } } } }`,
		`query WithDirective($e: Boolean!) { user(id: "1") { name email @include(if: $e) } }`,
		`{ __typename }`,
		`mutation { deleteSession(id: "sess-abc") { success } }`,

		// Arguments containing braces and quotes, which a naive brace counter
		// reads as nesting.
		`query { search(filter: "{\"a\":1}") { id } }`,
		`query { create(input: {name: "x", meta: "}}}}"}) { id } }`,

		// Comments, which a scanner that does not skip them mis-tokenises.
		"query {\n  # a comment with { braces }\n  user { id }\n}",

		// A fragment chain that is deep but acyclic.
		`{...A} fragment A on Q{...B} fragment B on Q{...C} fragment C on Q{id}`,

		"",
	}

	for _, doc := range docs {
		t.Run(truncate(doc), func(t *testing.T) {
			if v := d.Analyze([]byte(doc)); v.Detected() {
				t.Errorf("false positive: signals=%v depth=%d fields=%d maxAlias=%d",
					v.Signals, v.Depth, v.Fields, v.MaxAlias)
			}
		})
	}
}

// TestStringsAndCommentsDoNotCountAsStructure is the discrimination a brace
// counter cannot make: one argument value would otherwise register as nesting.
func TestStringsAndCommentsDoNotCountAsStructure(t *testing.T) {
	d := New(Limits{MaxDepth: 3})

	for _, doc := range []string{
		`query { f(a: "{{{{{{{{{{{{{{{{{{{{") { id } }`,
		`query { f(a: """{{{{{{{{{{{{{{{{""") { id } }`,
		"query {\n# {{{{{{{{{{{{{{{{{{{{\n  f { id }\n}",
	} {
		if v := d.Analyze([]byte(doc)); v.Signals&SignalExcessiveDepth != 0 {
			t.Errorf("braces inside a string or comment counted as depth: %q → %d", doc, v.Depth)
		}
	}
}

// TestArgumentsAreNotFields: "first: 10" is an argument, and counting it as a
// selection would make every paginated query look complex.
func TestArgumentsAreNotFields(t *testing.T) {
	d := New(Limits{})
	v := d.Analyze([]byte(`query { orders(first: 10, after: "abc", filter: {status: ACTIVE}) { id } }`))
	if v.Detected() {
		t.Errorf("a paginated query was reported: %v", v.Signals)
	}
	// orders and id, not the argument names.
	if v.Fields > 4 {
		t.Errorf("Fields = %d; argument names are being counted as selections", v.Fields)
	}
}

// TestTypenameIsNotIntrospection: __typename is legal on every selection set and
// every GraphQL client sends it, so treating it as introspection would report
// most real traffic.
func TestTypenameIsNotIntrospection(t *testing.T) {
	d := New(Limits{})
	if v := d.Analyze([]byte(`{ user { __typename id } }`)); v.Signals&SignalIntrospection != 0 {
		t.Error("__typename reported as introspection")
	}
}

func TestLimitsAreConfigurable(t *testing.T) {
	doc := `{a{b{c{d{e{f}}}}}}`

	if v := New(Limits{MaxDepth: 3}).Analyze([]byte(doc)); v.Signals&SignalExcessiveDepth == 0 {
		t.Errorf("depth %d not reported at a limit of 3", v.Depth)
	}
	if v := New(Limits{MaxDepth: 50}).Analyze([]byte(doc)); v.Detected() {
		t.Errorf("reported at a limit of 50: %v", v.Signals)
	}
}

func TestBounds(t *testing.T) {
	d := New(Limits{})

	if d.Analyze(nil).Detected() {
		t.Error("nil detected")
	}
	// A document past the scan bound must terminate and stay bounded.
	long := strings.Repeat("{", maxScan*2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.Analyze([]byte(long))
	}()
	<-done

	// Thousands of fragments, all cyclic: the cycle detector must not be the
	// thing that fails to terminate.
	var frags strings.Builder
	frags.WriteString("{...F0}")
	for i := range 5000 {
		fmt.Fprintf(&frags, " fragment F%d on Q{...F%d}", i, (i+1)%5000)
	}
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		d.Analyze([]byte(frags.String()))
	}()
	<-done2
}

func FuzzAnalyze(f *testing.F) {
	f.Add(`query GetUser($id: ID!) { user(id: $id) { id name } }`)
	f.Add(`{__schema{types{name}}}`)
	f.Add(`{...A} fragment A on Q{...A}`)
	f.Add(`query { f(a: "{{{{") { id } }`)
	f.Add("{")
	f.Add("}")
	f.Add(`"""`)
	f.Add("...")
	f.Add("")

	d := New(Limits{})
	f.Fuzz(func(t *testing.T, doc string) {
		// A build-time-safe contract: never panic, and never report a depth
		// larger than the document could express.
		v := d.Analyze([]byte(doc))
		if v.Depth > len(doc)+1 {
			t.Fatalf("depth %d from a %d-byte document", v.Depth, len(doc))
		}
		if v.Fields > len(doc)+1 {
			t.Fatalf("fields %d from a %d-byte document", v.Fields, len(doc))
		}
	})
}

func BenchmarkAnalyzeBenign(b *testing.B) {
	d := New(Limits{})
	doc := []byte(`query ListOrders($first: Int!, $after: String) { orders(first: $first, after: $after) { edges { node { id total status } } pageInfo { hasNextPage endCursor } } }`)
	b.ReportAllocs()
	for b.Loop() {
		d.Analyze(doc)
	}
}

func truncate(s string) string {
	if s == "" {
		return "empty"
	}
	if len(s) > 40 {
		return s[:40]
	}
	return s
}
