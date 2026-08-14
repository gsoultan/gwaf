// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/rules/transform"
	"github.com/gsoultan/gwaf/types"
)

// addressContains matches needles against a value and against the value's
// numeric-host canonicalisation.
//
// # Why this is an operator and not a transform
//
// The first version of this put transform.NumericHost in a chain of its own, and
// it worked: every inet_aton spelling of the metadata address was canonicalised
// and matched. It also cost 22% on the benign GET benchmark, which is four times
// the budget a change is allowed, and TestTransformChainInventory says why in
// advance -- a chain is materialised once per value per phase, so a seventh
// chain is paid for by every value in the phase for the benefit of two rules.
//
// The canonicalisation belongs where only those two rules pay for it. Eval runs
// only after the prefilter nominates the rule, so a request with no address in
// it does no work at all, and the measured cost of this version is nil.
//
// # What keeps the prefilter honest
//
// Moving work into Eval is only sound if the automaton still nominates the rule,
// and the encoded spellings share no bytes with the canonical needle:
// "0xa9.0xfe.0xa9.0xfe" contains no "169.254.169.254". So the leads of every
// spelling are declared as literals too, and they are *derived* from the needles
// rather than written out -- the first part of an address has exactly three
// spellings, and a list nobody has to maintain is a list that cannot drift.
func addressContains(needles ...string) rules.Operator {
	inner := op.ContainsAny(needles...)
	lits, _ := inner.Literals()
	out := make([]string, 0, len(lits)+4*len(needles))
	out = append(out, lits...)
	for _, n := range needles {
		out = append(out, addressLeads(n)...)
	}
	return &addressOp{inner: inner, literals: out}
}

type addressOp struct {
	inner    rules.Operator
	literals []string
}

func (o *addressOp) Name() string { return "address_contains" }

func (o *addressOp) Literals() ([]string, bool) { return o.literals, true }

// Cost is the inner match plus one canonicalisation pass.
func (o *addressOp) Cost() types.Fuel { return types.CostLiteralMatch * 3 }

func (o *addressOp) Eval(ctx *rules.EvalContext, value []byte) (rules.Match, bool) {
	if m, ok := o.inner.Eval(ctx, value); ok {
		return m, true
	}
	// A nil destination is deliberate: Apply returns the input untouched when the
	// value carries no numeric host, so the ordinary case allocates nothing and
	// only a value actually spelling an address pays for the rewrite.
	canon, changed := transform.NumericHost.Apply(nil, value)
	if !changed {
		return rules.Match{}, false
	}
	return o.inner.Eval(ctx, canon)
}

// addressLeads returns the byte sequences any inet_aton spelling of the address
// in needle must begin with.
//
// The first part of a dotted quad is written in decimal, octal or hexadecimal,
// and the whole address collapses to a single part written the same three ways.
// Six leads therefore cover every spelling of one address, however its remaining
// parts are written -- which is what lets the canonicaliser handle the
// combinatorial tail without the prefilter having to know about it.
//
// A needle that is not an address yields nothing, so a hostname needle such as
// "metadata.google.internal" simply keeps the literal it already had.
func addressLeads(needle string) []string {
	a, ok := parseDottedQuad(needle)
	if !ok {
		return nil
	}
	first := uint64(a >> 24)
	return []string{
		// The first part, in the three bases, with the dot that must follow it
		// so "169." does not also nominate on "1699".
		itoaBase(first, 10) + ".",
		"0x" + itoaBase(first, 16),
		"0" + itoaBase(first, 8) + ".",
		// The whole address as one part.
		itoaBase(uint64(a), 10),
		"0x" + itoaBase(uint64(a), 16),
		"0" + itoaBase(uint64(a), 8),
	}
}

// parseDottedQuad reads a plain "a.b.c.d" out of s, which is the only form the
// needles are written in.
func parseDottedQuad(s string) (uint32, bool) {
	var out uint32
	part, digits, seen := 0, 0, 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if digits == 0 || part > 0xff {
				return 0, false
			}
			out = out<<8 | uint32(part)
			seen++
			part, digits = 0, 0
			continue
		}
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		part = part*10 + int(s[i]-'0')
		digits++
	}
	return out, seen == 4
}

func itoaBase(v uint64, base uint64) string {
	if v == 0 {
		return "0"
	}
	const digits = "0123456789abcdef"
	var buf [24]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v%base]
		v /= base
	}
	return string(buf[i:])
}
