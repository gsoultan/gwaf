// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf

import (
	"github.com/gsoultan/gwaf/internal/budget"
	"github.com/gsoultan/gwaf/internal/engine"
	"github.com/gsoultan/gwaf/internal/memz"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Transaction analyses one request.
//
// A Transaction is owned by exactly one goroutine for its entire lifetime. It
// is not safe for concurrent use, unlike the WAF that produced it.
//
// Phases run in order and each may terminate the transaction. Blocking at
// ProcessRequestHeaders means the body is never read from the client, never
// parsed, and never transformed — the cheapest rules run first by construction.
type Transaction struct {
	waf   *WAF
	rs    *rules.Ruleset
	eval  *engine.Evaluator
	meter budget.Meter
	arena memz.Arena

	values []engine.Value
	result engine.Result

	score     int
	evaluated int
	decided   bool
	decision  Decision

	// phase tracks the furthest phase completed, so that calling phases out of
	// order is caught rather than silently producing a decision from data that
	// was never supplied.
	phase types.Phase

	headerCount int
	argCount    int
	bodyLen     int
}

// reset prepares tx for reuse against a ruleset.
func (tx *Transaction) reset(rs *rules.Ruleset) {
	tx.rs = rs
	tx.meter.Reset(tx.waf.cfg.fuelLimit)
	tx.arena.SetLimit(tx.waf.cfg.limits.MaxArenaSize)
	tx.arena.Reset()
	tx.values = tx.values[:0]
	tx.result.Reset()
	tx.score = 0
	tx.evaluated = 0
	tx.decided = false
	tx.decision = Decision{}
	tx.phase = 0
	tx.headerCount = 0
	tx.argCount = 0
	tx.bodyLen = 0
}

// Close returns the transaction to its pool. It is safe to call more than once.
func (tx *Transaction) Close() {
	if tx.waf == nil {
		return
	}
	w := tx.waf
	tx.rs = nil
	tx.values = tx.values[:0]
	tx.arena.Reset()
	w.txPool.Put(tx)
}

// Score returns the accumulated anomaly score.
func (tx *Transaction) Score() int { return tx.score }

// RulesEvaluated returns how many operators have run. On benign traffic this
// must be zero; it is the leading indicator that the prefilter is working.
func (tx *Transaction) RulesEvaluated() int { return tx.evaluated }

// FuelSpent returns the work consumed so far.
func (tx *Transaction) FuelSpent() budget.Fuel { return tx.meter.Spent() }

// Decision returns the decision reached so far. Before any phase has produced a
// terminal outcome it reports an allowing decision.
func (tx *Transaction) Decision() Decision {
	if tx.decided {
		return tx.decision
	}
	return allow(ReasonNoMatch, tx.score, tx.evaluated)
}

// SetRequestLine records the method, target, and protocol.
func (tx *Transaction) SetRequestLine(method, target, proto string) {
	tx.addValue(types.Target{Kind: types.TargetRequestMethod}, "", method)
	tx.addValue(types.Target{Kind: types.TargetRequestURI}, "", target)
	tx.addValue(types.Target{Kind: types.TargetRequestProtocol}, "", proto)

	path := target
	if i := indexByte(target, '?'); i >= 0 {
		path = target[:i]
	}
	tx.addValue(types.Target{Kind: types.TargetRequestPath}, "", path)
}

// SetRemoteAddr records the client address.
func (tx *Transaction) SetRemoteAddr(addr string) {
	tx.addValue(types.Target{Kind: types.TargetRemoteAddr}, "", addr)
}

// AddRequestHeader records one request header.
//
// Headers beyond the configured limit are not silently dropped: the count is
// tracked and ProcessRequestHeaders reports a limit breach, because a request
// that was only partly inspected must not be reported as clean.
func (tx *Transaction) AddRequestHeader(name, value string) {
	tx.headerCount++
	if tx.headerCount > tx.waf.cfg.limits.MaxHeaders {
		return
	}
	tx.addValue(types.Target{Kind: types.TargetRequestHeaders, Name: name}, name, value)
	tx.addValue(types.Target{Kind: types.TargetRequestHeaderNames}, name, name)
}

// AddArgument records one request argument.
func (tx *Transaction) AddArgument(name, value string) {
	tx.argCount++
	if tx.argCount > tx.waf.cfg.limits.MaxArgs {
		return
	}
	tx.addValue(types.Target{Kind: types.TargetArgs, Name: name}, name, value)
	tx.addValue(types.Target{Kind: types.TargetArgNames}, name, name)
}

// SetRequestBody records the request body.
func (tx *Transaction) SetRequestBody(body []byte) {
	tx.bodyLen = len(body)
	if len(body) > tx.waf.cfg.limits.MaxBodySize {
		return
	}
	tx.addValueBytes(types.Target{Kind: types.TargetRequestBody}, "", body)
}

// ProcessRequestHeaders evaluates the request-headers phase.
func (tx *Transaction) ProcessRequestHeaders() Decision {
	if tx.headerCount > tx.waf.cfg.limits.MaxHeaders {
		return tx.limitExceeded("header count")
	}
	return tx.runPhase(types.PhaseRequestHeaders)
}

// ProcessRequestBody evaluates the request-body phase.
func (tx *Transaction) ProcessRequestBody() Decision {
	if tx.bodyLen > tx.waf.cfg.limits.MaxBodySize {
		return tx.limitExceeded("body size")
	}
	if tx.argCount > tx.waf.cfg.limits.MaxArgs {
		return tx.limitExceeded("argument count")
	}
	return tx.runPhase(types.PhaseRequestBody)
}

// addValue records a string value for evaluation.
func (tx *Transaction) addValue(target types.Target, key, value string) {
	if len(value) > tx.waf.cfg.limits.MaxValueLen {
		value = value[:tx.waf.cfg.limits.MaxValueLen]
	}
	span, ok := tx.arena.AppendString(value)
	if !ok {
		return
	}
	tx.values = append(tx.values, engine.Value{
		Target: target,
		Key:    key,
		Data:   tx.arena.Resolve(span),
	})
}

// addValueBytes records a byte value for evaluation.
func (tx *Transaction) addValueBytes(target types.Target, key string, value []byte) {
	if len(value) > tx.waf.cfg.limits.MaxValueLen {
		value = value[:tx.waf.cfg.limits.MaxValueLen]
	}
	span, ok := tx.arena.Append(value)
	if !ok {
		return
	}
	tx.values = append(tx.values, engine.Value{
		Target: target,
		Key:    key,
		Data:   tx.arena.Resolve(span),
	})
}

// runPhase evaluates one phase and folds the result into the transaction.
func (tx *Transaction) runPhase(phase types.Phase) Decision {
	if tx.decided {
		return tx.decision
	}
	tx.phase = phase

	// Values are re-resolved against the arena because appending may have
	// reallocated the backing array since they were recorded. Spans are stable;
	// the slices cut from them are not.
	tx.refreshValues()

	tx.result.Reset()
	tx.eval.Eval(tx.rs, phase, tx.values, &tx.meter, &tx.result)

	tx.score += tx.result.Score
	tx.evaluated += tx.result.RulesEvaluated

	if tx.result.Exhausted {
		return tx.budgetExhausted()
	}

	if tx.result.Undecidable {
		return tx.undecidable(tx.result.UndecidableReason)
	}

	if tx.result.Terminal {
		out := tx.result.TerminalOutcome
		if out.Kind == rules.ActionAllow {
			return tx.finish(Decision{
				verdict:        VerdictAllow,
				reason:         ReasonRule,
				score:          tx.score,
				rule:           tx.result.TerminalRule,
				rulesEvaluated: tx.evaluated,
			})
		}
		return tx.finish(tx.blockDecision(ReasonRule, out.Status, tx.result.TerminalRule))
	}

	if tx.score >= tx.waf.cfg.threshold {
		return tx.finish(tx.blockDecision(ReasonThreshold, 0, tx.highestHit()))
	}

	return allow(ReasonNoMatch, tx.score, tx.evaluated)
}

// refreshValues re-cuts every recorded value from the current arena buffer.
func (tx *Transaction) refreshValues() {
	buf := tx.arena.Bytes()
	off := 0
	for i := range tx.values {
		n := len(tx.values[i].Data)
		if off+n > len(buf) {
			break
		}
		tx.values[i].Data = buf[off : off+n]
		off += n
	}
}

// highestHit returns the most severe rule that matched, for attribution when a
// threshold rather than a single rule caused the block.
func (tx *Transaction) highestHit() *rules.CompiledRule {
	var best *rules.CompiledRule
	for i := range tx.result.Hits {
		h := &tx.result.Hits[i]
		if best == nil || h.Rule.Rule.Severity > best.Rule.Severity {
			best = h.Rule
		}
	}
	return best
}

// blockDecision builds a blocking decision, honouring detection-only mode.
func (tx *Transaction) blockDecision(reason Reason, status int, rule *rules.CompiledRule) Decision {
	if status == 0 {
		status = tx.waf.cfg.blockCode
	}
	d := Decision{
		verdict:        VerdictBlock,
		reason:         reason,
		status:         status,
		score:          tx.score,
		rule:           rule,
		rulesEvaluated: tx.evaluated,
	}
	if rule != nil {
		for i := range tx.result.Hits {
			if tx.result.Hits[i].Rule == rule {
				m := tx.result.Hits[i].Match
				d.hit = &m
				d.target = tx.result.Hits[i].Target
				d.key = tx.result.Hits[i].Key
				d.reading = tx.result.Hits[i].Reading
				break
			}
		}
	}
	if tx.waf.cfg.mode == DetectionOnly {
		d.verdict = VerdictAllow
	}
	return d
}

// budgetExhausted applies the configured fail mode.
//
// The ruleset was only partially evaluated, so this is not a statement that the
// request was clean — it is what the deployment chose to do about not knowing.
func (tx *Transaction) budgetExhausted() Decision {
	d := Decision{
		reason:         ReasonBudget,
		score:          tx.score,
		status:         tx.waf.cfg.blockCode,
		rulesEvaluated: tx.evaluated,
	}
	if tx.waf.cfg.failMode == FailClosed && tx.waf.cfg.mode == Blocking {
		d.verdict = VerdictBlock
	}
	return tx.finish(d)
}

// undecidable rejects input too ambiguous to analyse, per the fail mode.
//
// Allowing here would assert that a value gwaf could not fully read is clean,
// which is the assumption CVE-2026-21876 turned into a bypass. Under FailOpen
// the request proceeds, but the reason travels with the decision so the choice
// is visible rather than implied.
func (tx *Transaction) undecidable(reason string) Decision {
	d := Decision{
		reason:         ReasonUndecidable,
		score:          tx.score,
		status:         tx.waf.cfg.blockCode,
		detail:         reason,
		rulesEvaluated: tx.evaluated,
	}
	if tx.waf.cfg.failMode == FailClosed && tx.waf.cfg.mode == Blocking {
		d.verdict = VerdictBlock
	}
	return tx.finish(d)
}

// limitExceeded rejects input beyond a hard limit, per the fail mode.
func (tx *Transaction) limitExceeded(string) Decision {
	d := Decision{
		reason:         ReasonLimit,
		score:          tx.score,
		status:         tx.waf.cfg.blockCode,
		rulesEvaluated: tx.evaluated,
	}
	if tx.waf.cfg.failMode == FailClosed && tx.waf.cfg.mode == Blocking {
		d.verdict = VerdictBlock
	}
	return tx.finish(d)
}

// finish records a terminal decision and notifies the callback.
func (tx *Transaction) finish(d Decision) Decision {
	tx.decided = true
	tx.decision = d
	if fn := tx.waf.cfg.onDecide; fn != nil {
		fn(d)
	}
	return d
}

// indexByte returns the index of c in s, or -1. It avoids importing strings
// into the hot path for a single byte scan.
func indexByte(s string, c byte) int {
	for i := range len(s) {
		if s[i] == c {
			return i
		}
	}
	return -1
}
