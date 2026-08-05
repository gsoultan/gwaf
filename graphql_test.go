// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/detect/graphql"
	"github.com/gsoultan/gwaf/rules"
)

// GraphQL abuse has no payload. The document is valid, the field names are real,
// and the damage is done by its shape — so nothing a string matcher could object
// to, and all four of these passed gwaf untouched before detect/graphql existed.

func gqlBody(q string) string { return fmt.Sprintf(`{"query":%q,"variables":{}}`, q) }

func depthBomb(n int) string {
	return "query{" + strings.Repeat("a{", n) + "id" + strings.Repeat("}", n) + "}"
}

func aliasBomb(n int) string {
	var b strings.Builder
	b.WriteString("query{")
	for i := range n {
		fmt.Fprintf(&b, "a%d:expensiveField(id:1){x} ", i)
	}
	b.WriteString("}")
	return b.String()
}

func TestGraphQLAbuseIsDetected(t *testing.T) {
	w := newWAF(t)

	cases := []struct{ name, query string }{
		{"depth bomb", depthBomb(200)},
		{"alias amplification", aliasBomb(2000)},
		{"direct fragment cycle", `{...A} fragment A on Q{...A}`},
		{"indirect fragment cycle", `{...A} fragment A on Q{...B} fragment B on Q{...A}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := run(t, w, req{method: "POST", target: "/graphql", body: gqlBody(c.query),
				headers: map[string]string{"Content-Type": "application/json"}})
			if !d.Blocked() {
				t.Error("not detected")
			}
		})
	}
}

// TestIntrospectionIsOptIn is the contract, and the reason for it.
//
// Introspection is how GraphiQL, Apollo Studio, and every code generator
// discover a schema. Blocking it by default would break them on the day somebody
// adopted gwaf, which is exactly how a firewall gets switched off in week one.
// Disabling it in production is a defensible posture and it is the operator's
// posture to choose.
func TestIntrospectionIsOptIn(t *testing.T) {
	const query = `{__schema{types{name fields{name type{name}}}}}`

	// Not in the core ruleset.
	if d := run(t, newWAF(t), req{method: "POST", target: "/graphql", body: gqlBody(query),
		headers: map[string]string{"Content-Type": "application/json"}}); d.Blocked() {
		t.Errorf("introspection blocked by the default ruleset: rule=%d", d.RuleID())
	}

	// One line to opt in.
	tuned := newWAF(t, gwaf.WithRuleset(rules.Set{graphql.IntrospectionRule(10002)}))
	if d := run(t, tuned, req{method: "POST", target: "/graphql", body: gqlBody(query),
		headers: map[string]string{"Content-Type": "application/json"}}); !d.Blocked() {
		t.Error("introspection not detected with the opt-in rule loaded")
	}
	if d := run(t, tuned, req{method: "POST", target: "/graphql",
		body:    gqlBody(`query GetUser($id: ID!){user(id:$id){id name}}`),
		headers: map[string]string{"Content-Type": "application/json"}}); d.Blocked() {
		t.Errorf("an ordinary query was blocked by the introspection rule: rule=%d", d.RuleID())
	}
}

// TestGraphQLOverGET covers the form the GraphQL-over-HTTP specification defines
// for queries, where the whole document rides in the query string and arrives
// percent-encoded. A rule with no transform chain reads it as one long
// identifier and every structural count comes back zero — which is what happened
// until the chain was added, and it only showed up over GET because a POST body
// is already decoded.
func TestGraphQLOverGET(t *testing.T) {
	tuned := newWAF(t, gwaf.WithRuleset(rules.Set{graphql.IntrospectionRule(10002)}))

	if d := run(t, tuned, req{target: "/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D"}); !d.Blocked() {
		t.Error("percent-encoded introspection not detected over GET")
	}
	if d := run(t, tuned, req{target: "/graphql?query=%7Buser%7Bid%20name%7D%7D"}); d.Blocked() {
		t.Errorf("a benign GET query was blocked: rule=%d", d.RuleID())
	}

	// A depth bomb over GET is caught by the core ruleset, which needs no
	// opt-in: a document past its depth limit is abusive whoever sent it.
	deep := url.QueryEscape(depthBomb(200))
	if d := run(t, newWAF(t), req{target: "/graphql?query=" + deep}); !d.Blocked() {
		t.Error("percent-encoded depth bomb not detected over GET")
	}
}

// TestRealGraphQLTrafficPasses is the counterweight that decides whether these
// limits can ship enabled. The corpus carries 572 more of these.
func TestRealGraphQLTrafficPasses(t *testing.T) {
	w := newWAF(t)

	queries := []string{
		`query GetUser($id: ID!) { user(id: $id) { id name email } }`,
		`query ListOrders($first: Int!, $after: String) { orders(first: $first, after: $after) { edges { node { id total status } } pageInfo { hasNextPage endCursor } } }`,
		`mutation CreateOrder($input: OrderInput!) { createOrder(input: $input) { id status } }`,
		`query Deep { org { teams { members { user { profile { avatar { url } } } } } } }`,
		`query Aliased { a: user(id: "1") { name } b: user(id: "2") { name } }`,
		`query WithFragment { orders { ...OrderFields } } fragment OrderFields on Order { id total customer { name } }`,
		`query Search($t: String!) { search(term: $t) { __typename ... on Product { sku } } }`,
		`subscription OnOrderUpdate($id: ID!) { orderUpdated(orderId: $id) { id status } }`,
		`{ __typename }`,
	}
	for _, q := range queries {
		t.Run(q[:min(38, len(q))], func(t *testing.T) {
			d := run(t, w, req{method: "POST", target: "/graphql", body: gqlBody(q),
				headers: map[string]string{"Content-Type": "application/json"}})
			if d.Blocked() {
				t.Errorf("false positive: rule=%d msg=%q", d.RuleID(), d.Message())
			}
		})
	}
}

// TestGraphQLLimitsAreJustUnderTheEdge checks the boundary rather than only the
// extremes, since a limit nobody has tested at its edge is a limit nobody knows.
func TestGraphQLLimitsAreJustUnderTheEdge(t *testing.T) {
	w := newWAF(t)

	// The default depth limit is 15; the wrapper adds one level.
	if d := run(t, w, req{method: "POST", target: "/graphql", body: gqlBody(depthBomb(13)),
		headers: map[string]string{"Content-Type": "application/json"}}); d.Blocked() {
		t.Errorf("a document within the depth limit was blocked: rule=%d", d.RuleID())
	}
	if d := run(t, w, req{method: "POST", target: "/graphql", body: gqlBody(depthBomb(40)),
		headers: map[string]string{"Content-Type": "application/json"}}); !d.Blocked() {
		t.Error("a document past the depth limit was allowed")
	}

	// The default alias limit is 20.
	if d := run(t, w, req{method: "POST", target: "/graphql", body: gqlBody(aliasBomb(10)),
		headers: map[string]string{"Content-Type": "application/json"}}); d.Blocked() {
		t.Errorf("ten aliases were blocked: rule=%d", d.RuleID())
	}
}

// TestGraphQLRulesDoNotTouchOtherTraffic: the rules are scoped to the argument
// that carries a document, because the only byte every abusive document must
// contain is "{" — which is in every JSON body ever sent.
func TestGraphQLRulesDoNotTouchOtherTraffic(t *testing.T) {
	w := newWAF(t)

	for _, c := range []struct{ name, body string }{
		{"deeply nested json", `{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":{"n":{"o":{"p":1}}}}}}}}}}}}}}}}`},
		{"many json fields", `{"note":"x","sku":"y","qty":1,"gift":true,"ref":"z"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := run(t, w, req{method: "POST", target: "/api/v1/orders", body: c.body,
				headers: map[string]string{"Content-Type": "application/json"}})
			if d.Blocked() {
				t.Errorf("ordinary JSON blocked by a GraphQL rule: rule=%d", d.RuleID())
			}
		})
	}
}
