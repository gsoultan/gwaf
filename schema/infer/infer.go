// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package infer drafts a schema from requests an embedder has seen.
//
// Positive security needs a description of the API, and most APIs have none
// that is accurate. This package builds a first draft from traffic: shown the
// method, path and query parameters of requests the origin accepted, a Learner
// records what shape each parameter took and Draft returns operations that
// describe it.
//
// # What it keeps
//
// Shapes, never values. For each parameter a Learner holds a count, the
// longest value's length and which grammars every value so far has satisfied.
// It does not hold a value, a hash of one, or an enumeration of them, so there
// is nothing in it to leak: a Learner fed a million requests carrying session
// tokens can be dumped to a log without disclosing one. The names it holds
// (parameter names and literal path segments) are the client's bytes, bounded
// in length and number, and are data for a reviewer, never markup.
//
// # What it is not
//
// It is not part of request evaluation and holds no state gwaf's engine reads.
// The embedder owns the Learner, decides which requests to show it and when to
// throw it away, the same way it owns a calibration corpus. A draft is a
// suggestion for a person to review: it describes the traffic that was shown,
// which is a statement about the past and about whoever was sending it.
//
// # Choosing what to show it
//
// Show it only requests the origin answered successfully. A Learner widens a
// parameter when it sees a value outside the shape so far, so one request with
// id=abc turns a drafted integer into a string for good; that direction is
// safe. The other is not: a parameter only an attacker has ever sent is
// drafted from the attacker's values. MinSamples keeps a handful of requests
// from drafting anything, and review is what catches the rest.
//
// A Learner is safe for concurrent use. Observe takes one lock, so an embedder
// with heavy traffic should show it a sample rather than every request.
package infer

import (
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/gsoultan/gwaf/schema"
)

// Limits bounds what a Learner holds. Every one is a count of things named by
// a client, so every one needs a ceiling.
type Limits struct {
	// MaxOperations is the most method-and-path pairs remembered. A request
	// to a pair past it is counted in Stats.DroppedOperations and ignored.
	MaxOperations int
	// MaxFields is the most parameters remembered for one operation.
	MaxFields int
	// MaxNameLength is the longest parameter name or path remembered, in
	// bytes.
	MaxNameLength int
	// MinSamples is how many times an operation, and separately a parameter,
	// must have been seen before Draft describes it.
	MinSamples int
}

// DefaultLimits returns the limits New applies to a zero field.
func DefaultLimits() Limits {
	return Limits{MaxOperations: 256, MaxFields: 32, MaxNameLength: 128, MinSamples: 20}
}

// Pair is one query parameter.
type Pair struct {
	Name, Value string
}

// Stats counts what a Learner has seen and what its limits turned away.
type Stats struct {
	// Observed is the number of requests recorded.
	Observed uint64
	// DroppedOperations is the number of requests ignored because their
	// method or path was unusable or MaxOperations was reached.
	DroppedOperations uint64
	// DroppedFields is the number of parameters ignored because their name
	// was unusable or MaxFields was reached.
	DroppedFields uint64
}

// Learner accumulates the shape of requests. The zero value is not usable;
// call New.
type Learner struct {
	limits Limits

	mu    sync.Mutex
	ops   map[string]*operation
	stats Stats
}

type operation struct {
	method, path string
	seen         uint64
	fields       map[string]*shape
}

// shape is everything remembered about one parameter. No field of it can
// reconstruct a value.
type shape struct {
	seen   uint64
	maxLen int
	// still holds a bit for each grammar every value so far has satisfied.
	still grammar
}

type grammar uint8

const (
	isInteger grammar = 1 << iota
	isNumber
	isBoolean
	isUUID
	isDateTime
	isDate

	allGrammars = isInteger | isNumber | isBoolean | isUUID | isDateTime | isDate
)

// probes pairs each grammar with the field whose validation defines it, so
// what is drafted is by construction what the engine will accept.
var probes = [...]struct {
	bit   grammar
	field schema.Field
}{
	{isInteger, schema.Field{Kind: schema.KindInteger}},
	{isNumber, schema.Field{Kind: schema.KindNumber}},
	{isBoolean, schema.Field{Kind: schema.KindBoolean}},
	{isUUID, schema.Field{Kind: schema.KindString, Format: schema.FormatUUID}},
	{isDateTime, schema.Field{Kind: schema.KindString, Format: schema.FormatDateTime}},
	{isDate, schema.Field{Kind: schema.KindString, Format: schema.FormatDate}},
}

// New returns an empty Learner. A zero or negative limit takes its default.
func New(limits Limits) *Learner {
	d := DefaultLimits()
	if limits.MaxOperations <= 0 {
		limits.MaxOperations = d.MaxOperations
	}
	if limits.MaxFields <= 0 {
		limits.MaxFields = d.MaxFields
	}
	if limits.MaxNameLength <= 0 {
		limits.MaxNameLength = d.MaxNameLength
	}
	if limits.MinSamples <= 0 {
		limits.MinSamples = d.MinSamples
	}
	return &Learner{limits: limits, ops: make(map[string]*operation)}
}

// Observe records one request: its method, its path without the query string,
// and its query parameters. Nothing of a value is kept beyond its length and
// which grammars it satisfied.
func (l *Learner) Observe(method, path string, query []Pair) {
	method = strings.ToUpper(method)
	template, ok := Template(path)
	if !ok || !knownMethod(method) || len(template) > l.limits.MaxNameLength {
		l.mu.Lock()
		l.stats.DroppedOperations++
		l.mu.Unlock()
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	key := method + " " + template
	op := l.ops[key]
	if op == nil {
		if len(l.ops) >= l.limits.MaxOperations {
			l.stats.DroppedOperations++
			return
		}
		op = &operation{method: method, path: template, fields: make(map[string]*shape)}
		l.ops[key] = op
	}
	op.seen++
	l.stats.Observed++
	for _, p := range query {
		l.observeField(op, p)
	}
}

func (l *Learner) observeField(op *operation, p Pair) {
	s := op.fields[p.Name]
	if s == nil {
		if !usableName(p.Name, l.limits.MaxNameLength) || len(op.fields) >= l.limits.MaxFields {
			l.stats.DroppedFields++
			return
		}
		s = &shape{still: allGrammars}
		op.fields[p.Name] = s
	}
	s.seen++
	s.maxLen = max(s.maxLen, len(p.Value))
	if s.still == 0 {
		return
	}
	value := []byte(p.Value)
	for _, probe := range probes {
		if s.still&probe.bit != 0 && schema.Validate(probe.field, value) != schema.ViolationNone {
			s.still &^= probe.bit
		}
	}
}

// Stats returns the counts so far.
func (l *Learner) Stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stats
}

// Draft returns one operation for each method and path seen at least
// MinSamples times, describing each query parameter seen at least MinSamples
// times, sorted by path and then method.
//
// The draft is deliberately loose. It declares a type where every value seen
// fit one, and a maximum length with room above the longest seen. It declares
// nothing as required, no numeric range and no enumeration: each of those
// turns "we have not seen it yet" into "refuse it", and an enumeration would
// mean keeping values. An operation is never Strict, so a parameter the draft
// does not mention is not refused.
func (l *Learner) Draft() []schema.Operation {
	l.mu.Lock()
	defer l.mu.Unlock()

	minSeen := uint64(l.limits.MinSamples)
	out := make([]schema.Operation, 0, len(l.ops))
	for _, op := range l.ops {
		if op.seen < minSeen {
			continue
		}
		drafted := schema.Operation{Method: op.method, Path: op.path}
		for name, s := range op.fields {
			if s.seen >= minSeen {
				drafted.Query = append(drafted.Query, s.field(name))
			}
		}
		sort.Slice(drafted.Query, func(i, j int) bool { return drafted.Query[i].Name < drafted.Query[j].Name })
		out = append(out, drafted)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// field turns a shape into the loosest field that still says something.
func (s *shape) field(name string) schema.Field {
	f := schema.Field{Name: name, Kind: schema.KindString}
	switch {
	case s.still&isInteger != 0:
		f.Kind = schema.KindInteger
	case s.still&isNumber != 0:
		f.Kind = schema.KindNumber
	case s.still&isBoolean != 0:
		f.Kind = schema.KindBoolean
	case s.still&isUUID != 0:
		f.Format = schema.FormatUUID
	case s.still&isDateTime != 0:
		f.Format = schema.FormatDateTime
	case s.still&isDate != 0:
		f.Format = schema.FormatDate
	}
	if f.Kind == schema.KindString {
		f.MaxLength = headroom(s.maxLen)
	}
	return f
}

// minMaxLength is the smallest length bound a draft declares. A bound learned
// from short values must not refuse the first long one.
const minMaxLength = 64

// headroom returns a length bound with room above the longest value seen: the
// next power of two at or above twice it, and never less than minMaxLength.
func headroom(longest int) int {
	bound := minMaxLength
	for bound < 2*longest {
		bound *= 2
	}
	return bound
}

// maxSegments is the deepest path a Learner templates.
const maxSegments = 16

// Template replaces the segments of path that look like identifiers with
// template parameters, so that /orders/17 and /orders/18 are one operation:
// "/orders/{id}". A segment is an identifier when it is an integer, a UUID, or
// sixteen or more hexadecimal digits. ok is false for a path that does not
// start with "/", is deeper than sixteen segments, or holds a byte outside
// printable ASCII.
//
// It is exported so an embedder can key its own bookkeeping the way a Learner
// keys its operations.
func Template(path string) (template string, ok bool) {
	if path == "" || path[0] != '/' || !printable(path) {
		return "", false
	}
	segments := strings.Split(path[1:], "/")
	if len(segments) > maxSegments {
		return "", false
	}
	params := 0
	for i, seg := range segments {
		if !identifier(seg) {
			continue
		}
		params++
		segments[i] = "{id}"
		if params > 1 {
			segments[i] = "{id" + strconv.Itoa(params) + "}"
		}
	}
	return "/" + strings.Join(segments, "/"), true
}

var (
	integerField = schema.Field{Kind: schema.KindInteger}
	uuidField    = schema.Field{Kind: schema.KindString, Format: schema.FormatUUID}
	hexField     = schema.Field{Kind: schema.KindString, Format: schema.FormatHexadecimal}
)

// minHexIdentifier is the shortest run of hexadecimal digits taken for an
// identifier. Shorter ones are words: "cafe", "added", "decade".
const minHexIdentifier = 16

func identifier(segment string) bool {
	if segment == "" {
		return false
	}
	v := []byte(segment)
	if schema.Validate(integerField, v) == schema.ViolationNone ||
		schema.Validate(uuidField, v) == schema.ViolationNone {
		return true
	}
	return len(v) >= minHexIdentifier && schema.Validate(hexField, v) == schema.ViolationNone
}

func knownMethod(m string) bool {
	switch m {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return true
	}
	return false
}

func usableName(name string, maxLen int) bool {
	return name != "" && len(name) <= maxLen && printable(name)
}

func printable(s string) bool {
	for i := range len(s) {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}
