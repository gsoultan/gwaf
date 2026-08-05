// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

/*
Package gwaf is an embeddable, Go-native web application firewall.

gwaf is a library. It is imported into an application, runs on that
application's goroutines, and holds no global state. There is no daemon, no
admin server, and no user interface: gwaf decides whether a request is an
attack and reports why, and the embedder decides what to do about it.

# Getting started

New with no options returns a working, blocking firewall with the first-party
ruleset loaded:

	waf, err := gwaf.New()
	if err != nil {
		return err
	}

	tx := waf.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine(r.Method, r.RequestURI, r.Proto)
	tx.SetRemoteAddr(r.RemoteAddr)
	for name, values := range r.Header {
		for _, v := range values {
			tx.AddRequestHeader(name, v)
		}
	}

	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		http.Error(w, "forbidden", d.Status())
		return
	}

Blocking at the header phase means the body is never read from the client,
never parsed, and never transformed.

# How it works

A conventional WAF walks its ruleset per request: for every rule, resolve its
targets, transform each value, run its operator. That is O(rules × values)
transform-and-match operations, and it is why WAF latency scales with ruleset
size.

gwaf compiles instead. Rules, their transform chains, and their required
literals are inputs to a compiler that emits an execution plan: rules are
grouped by transform chain, each chain's literals are compiled into one
Aho-Corasick automaton, and at request time each value is normalized once per
chain and scanned once. Only rules whose literals actually appeared are
evaluated. On benign traffic the candidate set is empty and no operator runs at
all — a ruleset of ten rules and one of ten thousand cost the same.

# Guarantees

  - Benign traffic evaluates zero rules and performs zero allocations. Both are
    asserted by tests, not just measured by benchmarks.
  - Work is metered in deterministic fuel rather than wall-clock time, so the
    denial-of-service bound is provable and a budget violation reproduces in a
    unit test.
  - Every decision is explainable: it carries the rule, the matched byte span,
    and the score that produced it.
  - Rules evaluate in (phase, ID) order regardless of how the ruleset was
    assembled, so the same request always produces the same decision.

# Scope

gwaf analyses one request in isolation, with no memory of any other. Anything
requiring state, identity, time, or infrastructure — rate limiting, IP
reputation, bot scoring, packet filtering — belongs to the embedder and reaches
gwaf as an input rather than being maintained by it.

# Concurrency

A [WAF] is safe for concurrent use by any number of goroutines. A [Transaction]
is not: each is owned by exactly one goroutine for its lifetime. This is the
most common misuse of every WAF library.

Any number of independent WAF instances may coexist in one process with
different rulesets, which is what makes multi-tenant embedding and parallel
tests work.

# Rules

The first-party ruleset in ruleset/core contains only Certain and High
confidence rules, which is what makes blocking by default defensible. Rules are
plain struct literals:

	rules.Rule{
		ID:         1_000_001,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetRequestHeaders, Name: "User-Agent"}},
		Transforms: []rules.Transform{transform.Lowercase},
		Op:         op.ContainsAny("sqlmap", "nikto"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "Known vulnerability scanner",
	}

Confidence is not an opinion about a rule; it is a measured property, and the
tier a rule declares bounds the false-positive rate it is allowed to exhibit
against the benign corpus.

Five interfaces are the extension surface: [rules.Operator], [rules.Transform],
[rules.Action], and — once implemented — Resolver and Detector. Custom
operators that can honestly declare their required literals are prefiltered
exactly like built-in ones; those that cannot are reported as unconditional at
compile time, so their cost is visible before deployment rather than after.

See the docs directory for the architecture (CONCEPT.md), rule authoring
(RULES.md), integration profiles (INTEGRATION.md), and the performance model
(PERFORMANCE.md).
*/
package gwaf
