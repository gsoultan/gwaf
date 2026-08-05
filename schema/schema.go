// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package schema turns a description of an API into both a validator and a
// compiler input.
//
// # Positive security is also a performance optimization
//
// Most firewalls treat a schema as one more check to run: validate the request,
// then run the rules. That misses what a schema actually tells you.
//
// If a field is declared an integer and the value in hand really is an integer,
// then it contains only digits and a sign. It cannot contain "UNION SELECT". It
// cannot contain "<script". It cannot contain "../". Running injection rules
// against it is not merely unlikely to match — it is provably incapable of
// matching. The rules can be skipped, and skipping them is sound rather than a
// heuristic.
//
// So the same artifact buys three things at once:
//
//   - Security: input outside the schema is rejected before any rule runs.
//   - Speed: input inside the schema skips the rules it cannot trigger.
//   - Precision: a payload in a field that renders as HTML is treated
//     differently from the same bytes in a field that is never interpreted.
//
// The better an API is specified, the faster and the safer gwaf gets. See
// docs/CONCEPT.md §6 and §9.
//
// # Why this package has no OpenAPI parser
//
// The core module carries no third-party dependencies, and parsing OpenAPI YAML
// needs one. The types here are the compiler's input format; frontends that read
// OpenAPI, Swagger, or a protobuf descriptor live in their own modules and
// compile down to these, exactly as the rule frontends compile to one IR.
package schema

import (
	"fmt"
	"strings"
)

// Kind is the value type a field is declared to hold.
type Kind uint8

// Kinds. The zero value is Unknown, which asserts nothing and therefore
// disables both validation and pruning for that field — an unspecified field
// must never be treated as safe.
const (
	KindUnknown Kind = iota
	KindString
	KindInteger
	KindNumber
	KindBoolean
	KindEnum
	KindArray
	KindObject
)

// String implements fmt.Stringer.
func (k Kind) String() string {
	switch k {
	case KindString:
		return "string"
	case KindInteger:
		return "integer"
	case KindNumber:
		return "number"
	case KindBoolean:
		return "boolean"
	case KindEnum:
		return "enum"
	case KindArray:
		return "array"
	case KindObject:
		return "object"
	default:
		return "unknown"
	}
}

// Format narrows a string field to a shape with a known character set.
type Format uint8

// Formats.
const (
	FormatNone Format = iota
	FormatUUID
	FormatDateTime
	FormatDate
	FormatEmail
	FormatHexadecimal
	FormatBase64
	FormatIPv4
)

// String implements fmt.Stringer.
func (f Format) String() string {
	switch f {
	case FormatUUID:
		return "uuid"
	case FormatDateTime:
		return "date-time"
	case FormatDate:
		return "date"
	case FormatEmail:
		return "email"
	case FormatHexadecimal:
		return "hex"
	case FormatBase64:
		return "base64"
	case FormatIPv4:
		return "ipv4"
	default:
		return "none"
	}
}

// Context describes how the origin uses a value, which decides whether a given
// payload in it is dangerous at all.
//
// The same bytes are an attack in one field and a user's own words in another:
// "'; DROP TABLE users--" is an injection attempt in an identifier and is a
// perfectly ordinary bug report in a free-text field. Signature firewalls cannot
// tell those apart, and that inability is a large share of real-world false
// positives. See docs/CONCEPT.md §9.
type Context uint8

// Contexts.
const (
	// ContextUnknown asserts nothing; every rule applies.
	ContextUnknown Context = iota

	// ContextOpaque is never interpreted by the origin — an identifier, a
	// token, a correlation header. Content rules do not apply once the value
	// has been validated.
	ContextOpaque

	// ContextText is stored and rendered as plain text, escaped. Injection
	// rules still apply, since the value may reach a query or a shell, but
	// markup rules are advisory.
	ContextText

	// ContextHTML is rendered as markup. XSS rules matter most here.
	ContextHTML

	// ContextPath is used to build a filesystem path. Traversal rules matter
	// most here.
	ContextPath

	// ContextQuery is interpolated into a database query. Injection rules
	// matter most here, and this context should be rare — a schema declaring it
	// is describing a design problem.
	ContextQuery
)

// String implements fmt.Stringer.
func (c Context) String() string {
	switch c {
	case ContextOpaque:
		return "opaque"
	case ContextText:
		return "text"
	case ContextHTML:
		return "html"
	case ContextPath:
		return "path"
	case ContextQuery:
		return "query"
	default:
		return "unknown"
	}
}

// Field describes one parameter, header, or body member.
type Field struct {
	// Name is the parameter or member name. Empty matches any name, which is
	// how a body of uniform values is described.
	Name string

	// Kind is the declared value type.
	Kind Kind

	// Format narrows a string field further.
	Format Format

	// Enum lists the permitted values for KindEnum.
	Enum []string

	// Required rejects the request when the field is absent.
	Required bool

	// MaxLength bounds the value, in bytes. Zero means unbounded.
	MaxLength int

	// Context describes how the origin uses the value.
	Context Context
}

// Inert reports whether a value that has passed validation for this field is
// provably incapable of carrying an injection payload.
//
// This is the claim the whole optimization rests on, so it is deliberately
// conservative. It holds only where validation constrains the character set to
// one that cannot spell an attack:
//
//   - integers, numbers, and booleans admit digits, sign, and a decimal point;
//   - UUID, date, date-time, hex, and IPv4 admit hex digits and separators;
//   - an enum admits exactly the values the schema listed.
//
// It is false for every string field, including short ones and including
// base64: base64 admits '+' and '/', and a Context the schema did not state
// cannot be assumed benign. When in doubt this returns false, because the cost
// of being wrong is a bypass and the cost of being conservative is some work.
func (f Field) Inert() bool {
	switch f.Kind {
	case KindInteger, KindNumber, KindBoolean:
		return true
	case KindEnum:
		// The value is one of a fixed list the schema author wrote. If that
		// list contains an attack, the schema is the problem.
		return len(f.Enum) > 0
	case KindString:
		switch f.Format {
		case FormatUUID, FormatDateTime, FormatDate, FormatHexadecimal, FormatIPv4:
			return true
		}
		return false
	default:
		return false
	}
}

// Operation describes one route.
type Operation struct {
	// Method is the HTTP method. Empty matches any.
	Method string

	// Path is the route template, for example "/api/v1/orders/{id}".
	Path string

	// Query, Headers, and Body describe the parameters of each kind.
	Query   []Field
	Headers []Field
	Body    []Field

	// Strict rejects parameters the schema does not describe.
	//
	// This is where positive security earns its name: an undeclared parameter
	// is either a client bug or an attacker probing, and neither should reach
	// the origin. It is opt-in because switching it on for an
	// under-specified API rejects real traffic.
	Strict bool

	// NoBody rejects any request body, which lets the engine compile out body
	// handling for this route entirely.
	NoBody bool
}

// Schema is a set of operations.
//
// A Schema is immutable once compiled and is shared by every transaction, so it
// and everything reachable from it must be safe for concurrent use.
type Schema struct {
	ops []Operation

	// byMethodPath indexes literal (non-templated) routes for O(1) lookup.
	// Templated routes fall back to a linear segment match, which is fine
	// because they are a minority and the comparison is cheap.
	literal   map[string]*Operation
	templated []*Operation
}

// New compiles operations into a Schema.
func New(ops ...Operation) (*Schema, error) {
	s := &Schema{
		ops:     make([]Operation, len(ops)),
		literal: make(map[string]*Operation, len(ops)),
	}
	copy(s.ops, ops)

	for i := range s.ops {
		op := &s.ops[i]
		if op.Path == "" {
			return nil, fmt.Errorf("schema: operation %d has no path", i)
		}
		if err := validateFields(op); err != nil {
			return nil, fmt.Errorf("schema: %s %s: %w", op.Method, op.Path, err)
		}

		if strings.ContainsAny(op.Path, "{*") {
			s.templated = append(s.templated, op)
			continue
		}
		s.literal[routeKey(op.Method, op.Path)] = op
	}
	return s, nil
}

// validateFields rejects field declarations that would silently do nothing.
func validateFields(op *Operation) error {
	for _, group := range [][]Field{op.Query, op.Headers, op.Body} {
		for _, f := range group {
			if f.Kind == KindEnum && len(f.Enum) == 0 {
				return fmt.Errorf("field %q is an enum with no values", f.Name)
			}
			if f.Format != FormatNone && f.Kind != KindString && f.Kind != KindUnknown {
				return fmt.Errorf("field %q declares format %s on a %s",
					f.Name, f.Format, f.Kind)
			}
		}
	}
	return nil
}

// Len returns the number of operations.
func (s *Schema) Len() int { return len(s.ops) }

// Lookup returns the operation describing a request, if the schema has one.
func (s *Schema) Lookup(method, path string) (*Operation, bool) {
	if s == nil {
		return nil, false
	}
	if op, ok := s.literal[routeKey(method, path)]; ok {
		return op, true
	}
	if op, ok := s.literal[routeKey("", path)]; ok {
		return op, true
	}
	for _, op := range s.templated {
		if matchTemplate(op, method, path) {
			return op, true
		}
	}
	return nil, false
}

func routeKey(method, path string) string { return method + " " + path }

// matchTemplate reports whether a templated route matches a concrete path.
func matchTemplate(op *Operation, method, path string) bool {
	if op.Method != "" && op.Method != method {
		return false
	}

	tpl, p := op.Path, path
	for {
		if tpl == "" || p == "" {
			return tpl == p
		}

		ts, trest := nextSegment(tpl)
		ps, prest := nextSegment(p)

		switch {
		case ts == "*":
			// A wildcard segment consumes the rest of the path.
			return true
		case len(ts) >= 2 && ts[0] == '{' && ts[len(ts)-1] == '}':
			// A template parameter matches exactly one non-empty segment.
			if ps == "" {
				return false
			}
		case ts != ps:
			return false
		}
		tpl, p = trest, prest
	}
}

// nextSegment splits a leading "/" and the first path segment from s.
func nextSegment(s string) (seg, rest string) {
	s = strings.TrimPrefix(s, "/")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

// FieldFor returns the declaration of a named parameter within a group.
//
// A field with an empty Name acts as the fallback for the group, which is how a
// body of uniform values is described.
func FieldFor(fields []Field, name string) (Field, bool) {
	var fallback Field
	haveFallback := false

	for _, f := range fields {
		if f.Name == name {
			return f, true
		}
		if f.Name == "" {
			fallback, haveFallback = f, true
		}
	}
	return fallback, haveFallback
}
