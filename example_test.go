// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"fmt"
	"iter"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/schema"
	"github.com/gsoultan/gwaf/types"
)

// A working, blocking firewall in one line and no configuration.
//
// The core ruleset ships Certain and High confidence rules only, which is what
// makes blocking safe by default: a WAF that ships in detection-only mode
// protects nothing while telling the operator they are covered.
func ExampleNew() {
	waf, err := gwaf.New()
	if err != nil {
		panic(err)
	}

	tx := waf.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", "/products?id=1", "HTTP/1.1")
	tx.AddArgument("id", "1' OR 1=1--")

	d := tx.ProcessRequestHeaders()
	fmt.Println("blocked:", d.Blocked())
	fmt.Println("rule:", d.RuleID())
	// Output:
	// blocked: true
	// rule: 2010
}

// Ordinary traffic costs almost nothing: the prefilter decides what to evaluate
// before any rule runs, so the count is a small constant that does not grow with
// the ruleset. Ten rules and ten thousand rules evaluate the same number.
//
// The two requests below show the shape of it. A path with no attack vocabulary
// reaches zero rules; adding a query string makes exactly one rule a candidate,
// whatever the query says. That constant is the honest number — "zero rules on
// benign traffic" is true of the no-query case and rounds the other one down.
func ExampleTransaction_RulesEvaluated() {
	waf, _ := gwaf.New()

	for _, target := range []string{"/products", "/products?id=42"} {
		tx := waf.NewTransaction()
		// SetRequestLine parses the query string itself, so query parameters
		// need no AddArgument -- that is for values the caller has already
		// decoded, such as form fields.
		tx.SetRequestLine("GET", target, "HTTP/1.1")
		tx.ProcessRequestHeaders()
		fmt.Printf("%-18s rules evaluated: %d\n", target, tx.RulesEvaluated())
		tx.Close()
	}
	// Output:
	// /products          rules evaluated: 0
	// /products?id=42    rules evaluated: 1
}

// Every block is explainable. Explain returns the matched span, the transform
// chain that produced it, and the narrowest exception that would suppress this
// exact finding without weakening the rule anywhere else.
func ExampleDecision_Explain() {
	waf, _ := gwaf.New()
	tx := waf.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", "/search", "HTTP/1.1")
	tx.AddArgument("q", "<script>alert(1)</script>")
	d := tx.ProcessRequestHeaders()

	e := d.Explain()
	fmt.Println("rule:", e.RuleID())
	fmt.Println("matched:", string(e.MatchedBytes()))

	if x, ok := e.NarrowestException(); ok {
		fmt.Printf("exception: rule %d on %s:%s\n", x.RuleID, x.Target, x.Key)
	}
	// Output:
	// rule: 3010
	// matched: <script>alert(1)</script>
	// exception: rule 3010 on ARGS:q
}

// Detection-only is the rollout path: rules are evaluated and reported, and
// nothing is blocked. Run it against real traffic, read the decisions, then
// switch to blocking once the log is clean.
func ExampleWithMode() {
	waf, _ := gwaf.New(gwaf.WithMode(gwaf.DetectionOnly))
	tx := waf.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", "/search", "HTTP/1.1")
	tx.AddArgument("q", "1' OR 1=1--")
	d := tx.ProcessRequestHeaders()

	fmt.Println("blocked:", d.Blocked())
	fmt.Println("would have matched rule:", d.RuleID())
	// Output:
	// blocked: false
	// would have matched rule: 2010
}

// Describing the API is the highest-value thing an embedder can do. A field
// declared an integer that validates as one cannot contain "UNION SELECT", so
// those rules are skipped soundly rather than heuristically — the schema makes
// gwaf both faster and stricter at once.
func ExampleWithSchema() {
	api, err := schema.New(schema.Operation{
		Method: "POST",
		Path:   "/api/v1/bets",
		Strict: true,
		Body: []schema.Field{
			{Name: "stake", Kind: schema.KindNumber, Required: true,
				Min: schema.Bound(0.01), Max: schema.Bound(10_000)},
			{Name: "currency", Kind: schema.KindEnum, Enum: []string{"USD", "EUR"}},
		},
	})
	if err != nil {
		panic(err)
	}

	waf, _ := gwaf.New(gwaf.WithSchema(api))
	tx := waf.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("POST", "/api/v1/bets", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "application/json")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte(`{"stake":-5000,"currency":"USD"}`))
	d := tx.ProcessRequestBody()

	// A negative stake is a perfectly good number and no signature describes it.
	fmt.Println("blocked:", d.Blocked())
	fmt.Println("reason:", d.Reason())
	// Output:
	// blocked: true
	// reason: schema_violation
}

// Rules are Go values, so a typo in a target name is a build failure rather than
// a rule that silently never fires at three in the morning.
func ExampleWithRuleset() {
	waf, err := gwaf.New(gwaf.WithRuleset(rules.Set{{
		ID:         1_000_001,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetRequestPath}},
		Op:         op.HasPrefix("/internal/"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "internal-only path reached from outside",
	}}))
	if err != nil {
		panic(err)
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/internal/metrics", "HTTP/1.1")
	d := tx.ProcessRequestHeaders()

	fmt.Println("blocked by:", d.RuleID())
	// Output:
	// blocked by: 1000001
}

// An exception suppresses one finding on one route without weakening the rule
// anywhere else. Prefer this to deleting a rule: the narrow form is the short
// one, and Explain hands you exactly this struct.
func ExampleWithException() {
	waf, _ := gwaf.New(gwaf.WithException(rules.Exception{
		RuleID: 2010,
		Path:   "/admin/query-console",
		Target: types.TargetArgs,
		Key:    "sql",
	}))

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("POST", "/admin/query-console", "HTTP/1.1")
	tx.AddArgument("sql", "SELECT * FROM users WHERE id = 1 OR 1=1")
	d := tx.ProcessRequestHeaders()

	fmt.Println("blocked on the excepted route:", d.Blocked())

	// The same payload anywhere else is still blocked.
	tx2 := waf.NewTransaction()
	defer tx2.Close()
	tx2.SetRequestLine("GET", "/search", "HTTP/1.1")
	tx2.AddArgument("sql", "SELECT * FROM users WHERE id = 1 OR 1=1")
	fmt.Println("blocked elsewhere:", tx2.ProcessRequestHeaders().Blocked())
	// Output:
	// blocked on the excepted route: false
	// blocked elsewhere: true
}

// A Resolver is how a signal gwaf deliberately does not compute — reputation, a
// bot score, a tenant — reaches a rule. gwaf consumes the score; it never
// maintains one, because that would be state across requests.
func ExampleTransaction_AddResolver() {
	waf, _ := gwaf.New(gwaf.WithRuleset(rules.Set{{
		ID:         1_000_002,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetResolved, Name: "reputation.score"}},
		Op:         op.Equals("hostile"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "request from a client the embedder scored hostile",
	}}))

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.AddResolver(reputationResolver{score: "hostile"})
	tx.SetRequestLine("GET", "/", "HTTP/1.1")

	fmt.Println("blocked:", tx.ProcessRequestHeaders().Blocked())
	// Output:
	// blocked: true
}

// Discovering shadow endpoints: gwaf reports that one request went somewhere the
// schema does not describe, and the embedder keeps the inventory. Aggregating is
// memory, and memory belongs to the embedder.
func ExampleTransaction_UndeclaredRoute() {
	api, _ := schema.New(schema.Operation{Method: "GET", Path: "/api/v1/orders", NoBody: true})
	waf, _ := gwaf.New(gwaf.WithSchema(api))

	inventory := map[string]int{}
	for _, path := range []string{"/api/v1/orders", "/internal/debug/config"} {
		tx := waf.NewTransaction()
		tx.SetRequestLine("GET", path, "HTTP/1.1")
		if tx.UndeclaredRoute() {
			inventory[path]++
		}
		tx.Close()
	}

	fmt.Println("shadow endpoints found:", len(inventory))
	fmt.Println("which:", inventory)
	// Output:
	// shadow endpoints found: 1
	// which: map[/internal/debug/config:1]
}

// reputationResolver is the embedder's own store, seen from gwaf's side. The
// work happens inside Resolve and only when a rule in the phase actually reads
// the collection, so registering one costs nothing on requests that never
// consult it.
type reputationResolver struct{ score string }

func (reputationResolver) Name() string { return "reputation" }

func (r reputationResolver) Resolve() iter.Seq2[string, []byte] {
	return func(yield func(string, []byte) bool) {
		yield("score", []byte(r.score))
	}
}
