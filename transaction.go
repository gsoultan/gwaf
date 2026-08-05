// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf

import (
	"fmt"

	"github.com/gsoultan/gwaf/internal/body"
	"github.com/gsoultan/gwaf/internal/budget"
	"github.com/gsoultan/gwaf/internal/engine"
	"github.com/gsoultan/gwaf/internal/memz"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/schema"
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

	// spans records where each value's key and data live in the arena, so both
	// can be re-cut after a growth reallocates the backing array. Slices are
	// not stable across arena growth; offsets are.
	spans  []valueSpan
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
	contentType string

	// op is the schema operation matched for this request, or nil when no
	// schema is configured or the route is not described.
	op *schema.Operation

	// bodyParser extracts fields from structured bodies. It owns reusable
	// buffers and is reset per body.
	bodyParser body.Parser

	// bodyErr records why a structured body could not be fully parsed.
	bodyErr error

	// bodyParseFailed carries that reason into the decision.
	bodyParseFailed string

	// matches is the reusable buffer behind Matches.
	matches []Match

	// decodeBuf backs base64 decoding, reused across values.
	decodeBuf []byte

	// oversizeKey and oversizeLen record the first value that exceeded the
	// per-value ceiling and was therefore not inspected at all.
	oversizeKey string
	oversizeLen int

	// violation records the first schema violation seen, so the request is
	// rejected with the reason rather than merely failing to match a rule.
	violation  schema.Violation
	violatedAt string
}

// valueSpan locates one recorded value inside the transaction arena.
type valueSpan struct{ key, data types.Span }

// reset prepares tx for reuse against a ruleset.
func (tx *Transaction) reset(rs *rules.Ruleset) {
	tx.rs = rs
	tx.meter.Reset(tx.waf.cfg.fuelLimit)
	tx.arena.SetLimit(tx.waf.cfg.limits.MaxArenaSize)
	tx.arena.Reset()
	tx.values = tx.values[:0]
	tx.spans = tx.spans[:0]
	tx.result.Reset()
	tx.score = 0
	tx.evaluated = 0
	tx.decided = false
	tx.decision = Decision{}
	tx.phase = 0
	tx.headerCount = 0
	tx.argCount = 0
	tx.bodyLen = 0
	tx.op = nil
	tx.violation = schema.ViolationNone
	tx.violatedAt = ""
	tx.bodyErr = nil
	tx.bodyParseFailed = ""
	tx.contentType = ""
	tx.oversizeKey = ""
	tx.oversizeLen = 0
}

// Close returns the transaction to its pool. It is safe to call more than once.
func (tx *Transaction) Close() {
	if tx.waf == nil {
		return
	}
	w := tx.waf
	tx.rs = nil
	tx.values = tx.values[:0]
	tx.spans = tx.spans[:0]
	tx.arena.Reset()
	w.txPool.Put(tx)
}

// Match is one rule that fired during a transaction.
//
// Decisions report the rule responsible for the outcome; this reports every
// rule that matched, including scoring rules that did not block on their own.
// Calibration needs the full set — a rule's false-positive rate is how often it
// matches benign traffic, whether or not that match decided anything — and so
// does any control plane explaining a decision to an operator.
type Match struct {
	RuleID     types.RuleID
	Msg        string
	Severity   types.Severity
	Confidence types.Confidence
	Target     types.Target
	Key        string
	Span       types.Span

	// Interpretation names the alternative decoding that revealed the payload,
	// or "none" when it matched the bytes as sent.
	Interpretation string

	// Score is this match's contribution to the anomaly total.
	Score int
}

// Matches returns every rule that fired in the phase most recently evaluated.
//
// The slice is owned by the transaction and is invalidated by the next phase or
// by Close. Callers that retain matches must copy them.
func (tx *Transaction) Matches() []Match {
	if cap(tx.matches) < len(tx.result.Hits) {
		tx.matches = make([]Match, 0, len(tx.result.Hits))
	}
	tx.matches = tx.matches[:0]

	for i := range tx.result.Hits {
		h := &tx.result.Hits[i]
		score := h.Outcome.Score
		if h.Outcome.Kind == rules.ActionScore && score == 0 {
			score = h.Rule.Rule.Severity.Score()
		}
		tx.matches = append(tx.matches, Match{
			RuleID:         h.Rule.Rule.ID,
			Msg:            h.Rule.Rule.Msg,
			Severity:       h.Rule.Rule.Severity,
			Confidence:     h.Rule.Rule.Confidence,
			Target:         h.Target,
			Key:            h.Key,
			Span:           h.Match.Span,
			Interpretation: h.Reading.String(),
			Score:          score,
		})
	}
	return tx.matches
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

	// Resolve the schema operation now, so that arguments recorded afterwards
	// can be validated and marked as they arrive rather than in a second pass.
	if s := tx.waf.cfg.schema; s != nil {
		if op, ok := s.Lookup(method, path); ok {
			tx.op = op
		}
	}
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
	if len(tx.contentType) == 0 && equalFoldASCII(name, "content-type") {
		tx.contentType = value
	}
	tx.addValue(types.Target{Kind: types.TargetRequestHeaders, Name: name}, name, value)
	tx.addValue(types.Target{Kind: types.TargetRequestHeaderNames}, name, name)
}

// equalFoldASCII compares two ASCII strings case-insensitively without
// importing strings into the hot path for a single header-name check.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		c := a[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != b[i] {
			return false
		}
	}
	return true
}

// AddArgument records one request argument.
func (tx *Transaction) AddArgument(name, value string) {
	tx.argCount++
	if tx.argCount > tx.waf.cfg.limits.MaxArgs {
		return
	}

	inert := tx.checkSchema(name, value)
	tx.addValueInert(types.Target{Kind: types.TargetArgs, Name: name}, name, value, inert)

	// The parameter *name* is attacker-controlled even when its value is
	// schema-constrained, so it is always inspected.
	tx.addValue(types.Target{Kind: types.TargetArgNames}, name, name)
}

// checkSchema validates one argument against the matched operation and reports
// whether the value is provably incapable of carrying a payload.
//
// A violation is recorded rather than acted on immediately: the request is
// rejected at the next phase boundary so that the decision carries the phase
// and the accumulated context, like every other decision.
func (tx *Transaction) checkSchema(name, value string) bool {
	if tx.op == nil {
		return false
	}

	f, ok := schema.FieldFor(tx.op.Query, name)
	if !ok {
		// An undeclared parameter under a strict operation is either a client
		// bug or an attacker probing, and neither should reach the origin.
		if tx.op.Strict && tx.violation == schema.ViolationNone {
			tx.violation = schema.ViolationUndeclared
			tx.violatedAt = name
		}
		return false
	}

	if v := schema.Validate(f, []byte(value)); v != schema.ViolationNone {
		if tx.violation == schema.ViolationNone {
			tx.violation = v
			tx.violatedAt = name
		}
		// A value that failed validation is emphatically not inert: it is the
		// most suspicious value in the request and gets full inspection.
		return false
	}
	return f.Inert()
}

// SetRequestBody records the request body.
//
// A body whose Content-Type gwaf can structure is parsed into fields, and each
// field is recorded separately. That is both faster and more accurate than
// inspecting the document whole:
//
//   - Faster, because detectors run over leaf values rather than the entire
//     document, and because a field the schema constrains can be skipped.
//   - More accurate, because a JSON string is not its bytes.
//     `{"c":"\u003cscript\u003e"}` contains no angle bracket on the wire and
//     the origin's parser hands the application `<script>`.
//
// A body gwaf cannot structure — or one that fails to parse — is recorded whole
// instead. That is slower and less precise but never less safe, and a parse
// failure is surfaced at the phase boundary rather than silently ignored.
func (tx *Transaction) SetRequestBody(b []byte) {
	tx.bodyLen = len(b)
	if len(b) > tx.waf.cfg.limits.MaxBodySize {
		return
	}

	// A multipart body is checked first, because its Content-Type carries the
	// boundary rather than naming a structure.
	if boundary, isMultipart := body.Boundary(tx.contentType); isMultipart {
		if len(boundary) > 0 && tx.parseMultipartBody(b, boundary) {
			return
		}
		// A multipart type with no boundary, or one that will not split, is
		// malformed rather than merely unstructured: the origin cannot parse it
		// either. Record why, then inspect it whole.
		if len(boundary) == 0 && tx.bodyErr == nil {
			tx.bodyErr = body.ErrNoBoundary
		}
		tx.addValueBytes(types.Target{Kind: types.TargetRequestBody}, "", b)
		return
	}

	switch body.DetectContent(tx.contentType) {
	case body.ContentJSON:
		if tx.parseStructuredBody(b, true) {
			return
		}
	case body.ContentForm:
		if tx.parseStructuredBody(b, false) {
			return
		}
	}

	tx.recordBody(b)
}

// parseStructuredBody extracts fields, reporting whether parsing succeeded.
//
// On failure the caller falls back to recording the raw body: a document gwaf
// could not read is not a document it may ignore, and inspecting it whole is
// the safe direction.
func (tx *Transaction) parseStructuredBody(b []byte, isJSON bool) bool {
	limits := body.Limits{
		MaxFields:    tx.waf.cfg.limits.MaxArgs,
		MaxValueLen:  tx.waf.cfg.limits.MaxValueLen,
		MaxTotalSize: tx.waf.cfg.limits.MaxBodySize,
	}
	tx.bodyParser.Reset(limits)

	// Fields are copied into the arena as they arrive, because the parser's
	// buffers are only valid for the duration of the callback.
	emit := func(name, value []byte, kind body.Kind) bool {
		if kind == body.KindKey {
			// A member name is attacker-controlled and is inspected in its own
			// right; a payload placed there would otherwise be invisible.
			tx.recordFieldBytes(types.TargetArgNames, name, value, false)
			return true
		}

		inert := tx.checkBodySchema(name, value)
		tx.recordValueBytes(types.TargetArgs, name, value, inert)
		return true
	}

	var err error
	if isJSON {
		err = tx.bodyParser.ParseJSON(b, emit)
	} else {
		err = tx.bodyParser.ParseForm(b, emit)
	}
	if err != nil {
		tx.bodyErr = err
		return false
	}
	return true
}

// recordBody records an unstructured body for inspection.
//
// Binary content is not handed to text detectors as one value. Doing so
// produces matches by chance: the shell rule's "$(" is two bytes, and in a few
// hundred random bytes it turns up about one time in a hundred. Measured
// against random protobuf payloads that was 1.2% of gRPC requests blocked with
// no attacker involved.
//
// Instead the printable runs are extracted and inspected individually — a
// protobuf string field, a filename inside an archive, a comment in an image —
// while the framing bytes between them are never presented as if they were
// text. See internal/body/binary.go.
func (tx *Transaction) recordBody(b []byte) {
	if !body.IsBinary(b) {
		tx.addValueBytes(types.Target{Kind: types.TargetRequestBody}, "", b)
		return
	}

	tx.bodyParser.Reset(body.Limits{
		MaxFields:    tx.waf.cfg.limits.MaxArgs,
		MaxValueLen:  tx.waf.cfg.limits.MaxValueLen,
		MaxTotalSize: tx.waf.cfg.limits.MaxBodySize,
	})
	tx.bodyParser.ExtractText([]byte("body"), b, func(name, value []byte, _ body.Kind) bool {
		tx.recordValueBytes(types.TargetRequestBody, name, value, false)
		return true
	})
}

// parseMultipartBody extracts every part of a multipart body.
//
// Every part is emitted, not merely the first or the last. That is the whole
// defence against the CVE-2026-21876 class, in which the Core Rule Set checked
// only the final part's charset and a payload in any earlier one passed
// unexamined.
func (tx *Transaction) parseMultipartBody(b, boundary []byte) bool {
	tx.bodyParser.Reset(body.Limits{
		MaxFields:    tx.waf.cfg.limits.MaxArgs,
		MaxValueLen:  tx.waf.cfg.limits.MaxValueLen,
		MaxTotalSize: tx.waf.cfg.limits.MaxBodySize,
	})

	onPart := func(info body.PartInfo) bool {
		// A part's declared Content-Type and charset are attacker-controlled
		// and are inspected in their own right. A charset that re-interprets
		// content -- UTF-7 above all -- is the CVE-2026-21876 vector, and the
		// value itself goes through the same multi-interpretation pipeline as
		// everything else.
		if len(info.ContentType) > 0 {
			tx.recordFieldBytes(types.TargetRequestHeaders,
				[]byte("content-type"), info.ContentType, false)
		}
		if len(info.Charset) > 0 {
			tx.recordFieldBytes(types.TargetRequestHeaders,
				[]byte("charset"), info.Charset, false)
		}
		return true
	}

	emit := func(name, value []byte, kind body.Kind) bool {
		if kind == body.KindKey {
			tx.recordFieldBytes(types.TargetArgNames, name, value, false)
			return true
		}
		// An uploaded file is binary for the same reason a protobuf frame is,
		// and 8 KiB of JPEG is 8 KiB of chances for a short literal to appear.
		if body.IsBinary(value) {
			tx.bodyParser.ExtractText(name, value, func(n, v []byte, _ body.Kind) bool {
				tx.recordFieldBytes(types.TargetArgs, n, v, false)
				return true
			})
			return true
		}

		inert := tx.checkBodySchema(name, value)
		tx.recordFieldBytes(types.TargetArgs, name, value, inert)
		return true
	}

	if err := tx.bodyParser.ParseMultipart(b, boundary, onPart, emit); err != nil {
		tx.bodyErr = err
		return false
	}
	return true
}

// checkBodySchema validates one body field, mirroring checkSchema for query
// arguments.
func (tx *Transaction) checkBodySchema(name, value []byte) bool {
	if tx.op == nil || len(tx.op.Body) == 0 {
		return false
	}
	// The lookup takes a string, but Go compiles a map/slice lookup keyed by
	// string(bytes) without a copy when the result does not escape.
	f, ok := schema.FieldFor(tx.op.Body, string(name))
	if !ok {
		if tx.op.Strict && tx.violation == schema.ViolationNone {
			tx.violation = schema.ViolationUndeclared
			tx.violatedAt = string(name)
		}
		return false
	}
	if v := schema.Validate(f, value); v != schema.ViolationNone {
		if tx.violation == schema.ViolationNone {
			tx.violation = v
			tx.violatedAt = string(name)
		}
		return false
	}
	return f.Inert()
}

// ProcessRequestHeaders evaluates the request-headers phase.
func (tx *Transaction) ProcessRequestHeaders() Decision {
	if tx.headerCount > tx.waf.cfg.limits.MaxHeaders {
		return tx.limitExceeded("header count")
	}
	if tx.oversizeKey != "" {
		return tx.oversizeExceeded()
	}
	if d, rejected := tx.schemaViolation(); rejected {
		return d
	}
	return tx.runPhase(types.PhaseRequestHeaders)
}

// schemaViolation rejects a request that fell outside its declared schema.
//
// This is positive security: rather than asking whether the input looks like a
// known attack, it asks whether the input is something the API accepts at all.
// It runs before rule evaluation because a request the origin would reject is
// not worth inspecting.
func (tx *Transaction) schemaViolation() (Decision, bool) {
	if tx.violation == schema.ViolationNone {
		return Decision{}, false
	}
	d := Decision{
		verdict:        VerdictBlock,
		reason:         ReasonSchema,
		status:         tx.waf.cfg.blockCode,
		score:          tx.score,
		detail:         tx.violation.String() + ": " + tx.violatedAt,
		rulesEvaluated: tx.evaluated,
	}
	if tx.waf.cfg.mode == DetectionOnly {
		d.verdict = VerdictAllow
	}
	return tx.finish(d), true
}

// ProcessRequestBody evaluates the request-body phase.
func (tx *Transaction) ProcessRequestBody() Decision {
	if tx.bodyLen > tx.waf.cfg.limits.MaxBodySize {
		return tx.limitExceeded("body size")
	}
	// A route declaring no body must not receive one; the origin has no code
	// path for it, so anything sent is probing.
	if tx.op != nil && tx.op.NoBody && tx.bodyLen > 0 {
		return tx.finish(Decision{
			verdict:        VerdictBlock,
			reason:         ReasonSchema,
			status:         tx.waf.cfg.blockCode,
			detail:         "body sent to an operation that declares none",
			rulesEvaluated: tx.evaluated,
		})
	}
	if d, rejected := tx.schemaViolation(); rejected {
		return d
	}
	if tx.argCount > tx.waf.cfg.limits.MaxArgs {
		return tx.limitExceeded("argument count")
	}
	if tx.oversizeKey != "" {
		return tx.oversizeExceeded()
	}
	// A structured body that failed to parse was inspected whole as a fallback,
	// which is safe but imprecise: schema validation cannot apply to fields that
	// were never extracted. The reason travels with the decision so an operator
	// can distinguish "analysed and clean" from "could not be structured",
	// rather than the difference being invisible.
	if tx.bodyErr != nil {
		tx.bodyParseFailed = tx.bodyErr.Error()
	}
	return tx.runPhase(types.PhaseRequestBody)
}

// addValueInert records a string value, marking whether it is schema-inert.
func (tx *Transaction) addValueInert(target types.Target, key, value string, inert bool) {
	tx.recordString(target, key, value, inert)
}

// addValue records a string value for evaluation.
func (tx *Transaction) addValue(target types.Target, key, value string) {
	tx.recordString(target, key, value, false)
}

// addValueBytes records a byte value for evaluation.
func (tx *Transaction) addValueBytes(target types.Target, key string, value []byte) {
	tx.recordBytes(target, key, value, false)
}

// recordString and recordBytes copy a key and value into the arena.
//
// They are separate rather than one function taking []byte because converting a
// string to a byte slice allocates, and doing that per field per request is
// precisely the cost the arena exists to remove. Each path appends in the
// representation it already has.
func (tx *Transaction) recordString(target types.Target, key, value string, inert bool) {
	if len(value) > tx.waf.cfg.limits.MaxValueLen {
		tx.noteOversize(key, len(value))
		return
	}
	keySpan, ok := tx.arena.AppendString(key)
	if !ok {
		return
	}
	dataSpan, ok := tx.arena.AppendString(value)
	if !ok {
		return
	}
	tx.appendValue(target, keySpan, dataSpan, inert)
}

func (tx *Transaction) recordBytes(target types.Target, key string, value []byte, inert bool) {
	if len(value) > tx.waf.cfg.limits.MaxValueLen {
		tx.noteOversize(key, len(value))
		return
	}
	keySpan, ok := tx.arena.AppendString(key)
	if !ok {
		return
	}
	dataSpan, ok := tx.arena.Append(value)
	if !ok {
		return
	}
	tx.appendValue(target, keySpan, dataSpan, inert)
}

// recordFieldBytes records a value whose key is also bytes, which is how the
// body parser supplies fields.
//
// The target carries no Name: rule matching compares the *rule's* target name
// against the value's key, so a per-value name is never read. Omitting it avoids
// converting every field name to a string.
func (tx *Transaction) recordFieldBytes(kind types.TargetKind, key, value []byte, inert bool) {
	if len(value) > tx.waf.cfg.limits.MaxValueLen {
		tx.noteOversize(string(key), len(value))
		return
	}
	keySpan, ok := tx.arena.Append(key)
	if !ok {
		return
	}
	dataSpan, ok := tx.arena.Append(value)
	if !ok {
		return
	}
	tx.appendValue(types.Target{Kind: kind}, keySpan, dataSpan, inert)
}

// recordValueBytes records a value, decoding it first when it is base64.
//
// Base64 is encoded binary that happens to be printable, so a text detector run
// over it costs real time and finds nothing: a 700 KiB base64 field burned 20
// million fuel and 20ms, 62% of the default budget for one upload. Skipping it
// would be a coverage hole, because the origin decodes it and a base64-encoded
// web shell is a real technique.
//
// So it is decoded and the decoded content is inspected — as text if it is
// text, as printable runs if it is binary. The application acts on the decoded
// form, so that is the form worth inspecting.
func (tx *Transaction) recordValueBytes(kind types.TargetKind, key, value []byte, inert bool) {
	if !body.IsBase64(value) {
		tx.recordFieldBytes(kind, key, value, inert)
		return
	}

	decoded, ok := body.DecodeBase64(tx.decodeBuf[:0], value)
	if !ok {
		tx.recordFieldBytes(kind, key, value, inert)
		return
	}
	tx.decodeBuf = decoded

	if body.IsBinary(decoded) {
		tx.bodyParser.ExtractText(key, decoded, func(n, v []byte, _ body.Kind) bool {
			tx.recordFieldBytes(kind, n, v, false)
			return true
		})
		return
	}
	tx.recordFieldBytes(kind, key, decoded, false)
}

// noteOversize records that a value exceeded the per-value ceiling.
//
// It is deliberately *not* a truncation. Inspecting the first 64 KiB of a value
// and reporting the request as clean is a bypass with a padding step: an
// attacker prepends filler, puts the payload past the cut, and the firewall
// says no_match while the origin reads the whole thing. That is precisely what
// docs/PERFORMANCE.md §4 forbids, and it was doing it.
//
// The value is dropped and the breach is raised at the next phase boundary, so
// the deployment's fail mode decides rather than the outcome being silently
// "clean".
func (tx *Transaction) noteOversize(key string, size int) {
	if tx.oversizeKey == "" {
		tx.oversizeKey = key
		tx.oversizeLen = size
	}
}

// appendValue registers a recorded key/value pair.
func (tx *Transaction) appendValue(target types.Target, keySpan, dataSpan types.Span, inert bool) {
	tx.spans = append(tx.spans, valueSpan{key: keySpan, data: dataSpan})
	tx.values = append(tx.values, engine.Value{
		Target: target,
		Key:    tx.arena.Resolve(keySpan),
		Data:   tx.arena.Resolve(dataSpan),
		Inert:  inert,
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

// refreshValues re-cuts every recorded key and value from the current arena.
//
// Appending may have reallocated the backing array since a value was recorded,
// which invalidates any slice cut from the old one. The spans are offsets and
// stay correct across growth, which is the reason they are kept.
func (tx *Transaction) refreshValues() {
	buf := tx.arena.Bytes()
	for i := range tx.values {
		sp := tx.spans[i]
		tx.values[i].Key = sp.key.Bytes(buf)
		tx.values[i].Data = sp.data.Bytes(buf)
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
	if d.detail == "" && tx.bodyParseFailed != "" {
		d.detail = "body not structured: " + tx.bodyParseFailed
	}
	if tx.waf.cfg.mode == DetectionOnly {
		d.verdict = VerdictAllow
	}
	return d
}

// BodyParseError returns why a structured body could not be parsed, or empty.
//
// A body that fell back to whole-document inspection is still analysed, but
// less precisely — schema validation cannot apply to fields that were never
// extracted. Surfacing it lets an operator notice a client sending malformed
// JSON rather than discovering it as a coverage gap later.
func (tx *Transaction) BodyParseError() string { return tx.bodyParseFailed }

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

// oversizeExceeded rejects a request carrying a value too large to inspect.
//
// A deployment that legitimately receives values this large -- a base64 file in
// a JSON field, a long bearer token in a query parameter, since browsers cannot
// set headers on WebSocket or EventSource -- should raise MaxValueLen rather
// than accept an uninspected value. Fuel remains the bound on total work, so a
// larger ceiling costs latency on large requests, not unbounded latency.
func (tx *Transaction) oversizeExceeded() Decision {
	d := Decision{
		reason: ReasonLimit,
		score:  tx.score,
		status: tx.waf.cfg.blockCode,
		detail: fmt.Sprintf("value %q is %d bytes, over the %d-byte inspection limit; "+
			"it was not inspected", tx.oversizeKey, tx.oversizeLen,
			tx.waf.cfg.limits.MaxValueLen),
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
