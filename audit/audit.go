// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package audit turns a gwaf decision into a record something else can store.
//
// # Why this is not in core
//
// gwaf writes nothing anywhere. It hands back a Decision and the embedder owns
// what happens next, because where an audit record goes — a file, a socket, a
// log pipeline, an object store — is a deployment question and gwaf has no
// business having an opinion about it.
//
// What gwaf does owe is the *shape*: a record complete enough that an operator
// can answer "why was this blocked, and what do I do about it?" without
// replaying the request. That is the binding half of the "no UI" rule in
// CLAUDE.md §2b — no dashboard, but every datum a dashboard would need has to be
// reachable. This package is that shape, plus the two sinks that need no
// dependency to write it.
//
// # Zero dependencies, on purpose
//
// JSON and syslog are here because encoding/json and net are standard library.
// OpenTelemetry is not, and it never will be in this package: an OTel exporter
// is a dependency an embedder did not choose, which is the fifth ownership test
// (CLAUDE.md §1). A consumer who wants OTel implements Sink over their own
// exporter — the interface is one method precisely so that is a small thing to
// do.
//
// # Concurrency
//
// A Sink must be safe for concurrent use: gwaf is, and a decision can be
// recorded from any goroutine serving a request. Both sinks here are.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/types"
)

// Record is one auditable decision.
//
// It deliberately records no request *values* beyond the matched span: an audit
// log is read by humans and shipped to systems that index it, and copying
// attacker-controlled bytes into both is how a log becomes an attack surface of
// its own. The matched span is bounded for the same reason.
type Record struct {
	Time    time.Time `json:"time"`
	Blocked bool      `json:"blocked"`
	Status  int       `json:"status,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	Score   int       `json:"score"`

	RuleID     uint32 `json:"rule_id,omitempty"`
	Message    string `json:"message,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Confidence string `json:"confidence,omitempty"`

	Target string `json:"target,omitempty"`
	Key    string `json:"key,omitempty"`

	// Interpretation names which alternative decoding found the payload, or is
	// empty when it was visible in the bytes as sent. It is the difference
	// between "this was an attack" and "this was an attack once double-decoded",
	// which is what tells an operator their origin decodes twice.
	Interpretation string `json:"interpretation,omitempty"`

	// MatchedBytes is the span that matched, truncated to MaxMatchedBytes.
	MatchedBytes string `json:"matched_bytes,omitempty"`

	// TransformChain is what was applied before matching. A block that only
	// makes sense after url_decode+lowercase is not obvious from the raw
	// request; this is what explains it.
	TransformChain []string `json:"transform_chain,omitempty"`

	// SuggestedException is the narrowest suppression that stops this exact
	// finding without weakening the rule anywhere else. It is what turns a false
	// positive into a scoped fix rather than a rule somebody disables wholesale.
	SuggestedException *Exception `json:"suggested_exception,omitempty"`

	// Request identifies what was inspected. Populated by the caller, because
	// gwaf sees a transaction and not an *http.Request.
	Method   string `json:"method,omitempty"`
	Path     string `json:"path,omitempty"`
	ClientIP string `json:"client_ip,omitempty"`
	Route    string `json:"route,omitempty"`
}

// Exception is a narrowest-scope suppression rendered as data.
type Exception struct {
	RuleID uint32 `json:"rule_id"`
	Path   string `json:"path,omitempty"`
	Target string `json:"target,omitempty"`
	Key    string `json:"key,omitempty"`
}

// MaxMatchedBytes bounds what a record copies out of a request.
const MaxMatchedBytes = 256

// Context is what the caller knows and gwaf does not.
type Context struct {
	Method   string
	Path     string
	ClientIP string
	Route    string
}

// NewRecord builds a Record from a decision.
//
// The matched bytes are copied rather than aliased: an Explanation points into
// the transaction's arena, which is pooled and handed to the next request, so a
// record holding a reference would show one request's bytes in another's entry.
func NewRecord(d gwaf.Decision, ctx Context, now time.Time) Record {
	rec := Record{
		Time:           now.UTC(),
		Blocked:        d.Blocked(),
		Status:         d.Status(),
		Reason:         d.Reason().String(),
		Score:          d.Score(),
		Message:        d.Message(),
		Interpretation: d.Interpretation(),
		Method:         ctx.Method,
		Path:           ctx.Path,
		ClientIP:       ctx.ClientIP,
		Route:          ctx.Route,
	}
	if d.RuleID() == 0 {
		return rec
	}

	rec.RuleID = uint32(d.RuleID())
	rec.Severity = d.Severity().String()
	rec.Confidence = d.Confidence().String()
	rec.Target = d.Target().String()
	rec.Key = d.Key()

	e := d.Explain()
	if b := e.MatchedBytes(); len(b) > 0 {
		if len(b) > MaxMatchedBytes {
			b = b[:MaxMatchedBytes]
		}
		rec.MatchedBytes = string(b)
	}
	if chain := e.TransformChain(); len(chain) > 0 {
		rec.TransformChain = append(rec.TransformChain, chain...)
	}
	if x, ok := e.NarrowestException(); ok {
		rec.SuggestedException = &Exception{
			RuleID: uint32(x.RuleID),
			Path:   x.Path,
			Target: x.Target.String(),
			Key:    x.Key,
		}
	}
	return rec
}

// Sink receives records.
//
// One method, because the point is that implementing it over a queue, an
// exporter, or an object store should be small. Implementations must be safe for
// concurrent use.
type Sink interface {
	Write(Record) error
}

// JSON writes one JSON object per line to w.
//
// Line-delimited rather than an array so the output is appendable, tailable, and
// shippable without a parser that understands the whole file — a log that has to
// be closed to be valid is a log that is invalid whenever it matters.
type JSON struct {
	mu sync.Mutex
	w  io.Writer

	// RelevantOnly drops records for requests that were neither blocked nor
	// scored. Off by default: an operator turning this on is choosing volume
	// over completeness, and that should be a decision rather than a default.
	RelevantOnly bool
}

// NewJSON returns a JSON sink writing to w.
func NewJSON(w io.Writer) *JSON { return &JSON{w: w} }

// Write implements Sink.
func (j *JSON) Write(r Record) error {
	if j.RelevantOnly && !r.Blocked && r.RuleID == 0 {
		return nil
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')

	// Serialised through a mutex rather than a channel: the volume is bounded by
	// requests that actually match, which on ordinary traffic is a rounding
	// error, and a channel would add a goroutine and an overflow policy that
	// would then have to be designed.
	j.mu.Lock()
	defer j.mu.Unlock()
	_, err = j.w.Write(b)
	return err
}

// Multi fans a record out to several sinks.
//
// Every sink is attempted even if an earlier one fails, and the first error is
// returned. A file that filled up must not stop the record reaching the SIEM.
type Multi []Sink

// Write implements Sink.
func (m Multi) Write(r Record) error {
	var first error
	for _, s := range m {
		if s == nil {
			continue
		}
		if err := s.Write(r); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Discard is a Sink that drops everything. Useful as a default so callers need
// no nil checks.
var Discard Sink = discard{}

type discard struct{}

func (discard) Write(Record) error { return nil }

// SeverityAtLeast wraps a sink so only records at or above min reach it.
//
// Filtering here rather than inside a sink keeps the sinks dumb, and makes the
// policy visible at the point where it is chosen.
func SeverityAtLeast(min types.Severity, s Sink) Sink {
	return &severityFilter{min: min, next: s}
}

type severityFilter struct {
	min  types.Severity
	next Sink
}

func (f *severityFilter) Write(r Record) error {
	// An unmatched record carries no severity; it is passed through so a
	// filtered sink still sees the traffic shape rather than only its worst.
	if r.RuleID != 0 && severityRank(r.Severity) < severityRank(f.min.String()) {
		return nil
	}
	return f.next.Write(r)
}

// severityRank orders severities by name, so the filter does not depend on the
// numeric values of a type it does not own.
func severityRank(name string) int {
	switch name {
	case "notice":
		return 1
	case "warning":
		return 2
	case "error":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}
