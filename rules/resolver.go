// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package rules

import "iter"

// Resolver supplies the values of a TargetResolved collection.
//
// It is how a signal gwaf deliberately does not compute reaches a rule that
// wants to match on it: an IP reputation score, a JA4 fingerprint, a bot score,
// a tenant identifier, an authentication outcome.
//
// # Why this exists at all
//
// CLAUDE.md §1 draws the scope line at "one request, no memory": anything
// needing state across requests, identity, privilege, or a network call belongs
// to the embedder. That line only works if the *results* of the embedder's work
// have a way in. Without a Resolver, an embedder computing a bot score has
// nowhere to put it, and the documented boundary has no implementation — rules
// can only ever see bytes gwaf read off the wire.
//
// gwaf consumes a reputation score. It never maintains one, never fetches one,
// and never caches one. The Resolver is called; it does not call back.
//
// # Registered per transaction, not per WAF
//
// A resolver almost always closes over data specific to one request — the
// score *this* client got, the tenant *this* token belongs to. A WAF is shared
// by every goroutine, so a per-WAF resolver would either need locking or be
// wrong. `Transaction.AddResolver` takes it for the request it belongs to.
//
// # Called only when a rule needs it
//
// The engine asks the compiled plan whether any rule in the phase reads this
// resolver's name, and skips the call entirely when none does. That matters
// because the whole reason a signal is out of scope is usually that it is
// expensive: a reputation lookup, a fingerprint computation, a database read.
// Paying for it on every request when three prefiltered rules use it would
// undo the point.
//
// A Resolver is therefore permitted to be slow, and is expected to be lazy —
// do the work inside Resolve, not before registering.
type Resolver interface {
	// Name identifies the collection. A rule reads it with
	// types.Target{Kind: types.TargetResolved, Name: "bot_score"}.
	//
	// It must be stable: it appears in compile reports, in audit records, and in
	// any exception written against a rule that reads it.
	Name() string

	// Resolve yields the values, keyed within the collection.
	//
	// Several values may share a collection the way headers do — a "reputation"
	// resolver might yield "score", "asn", and "categories" — and a rule can
	// select one by setting Target.Name to the resolver and matching on the key,
	// or read them all.
	//
	// The values are copied into the transaction as they are yielded, so an
	// implementation may reuse its buffers between them. Stopping early is
	// honoured: yield returning false means the engine has what it needs.
	Resolve() iter.Seq2[string, []byte]
}
