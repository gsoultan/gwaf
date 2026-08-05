// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package openapi

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/gsoultan/gwaf/schema"
)

// Errors a caller may want to distinguish.
var (
	// ErrNotOpenAPI reports input that is not an OpenAPI document at all.
	ErrNotOpenAPI = errors.New("openapi: no openapi version field")

	// ErrUnsupportedVersion reports Swagger 2.0 or a future major version.
	ErrUnsupportedVersion = errors.New("openapi: unsupported version")
)

var (
	errNotOpenAPI         = ErrNotOpenAPI
	errUnsupportedVersion = ErrUnsupportedVersion
)

// maxRefDepth bounds $ref following.
//
// A document may reference itself — a Node with a list of Nodes is the ordinary
// case — and a compiler that follows references without a ceiling does not
// terminate. This is a build-time tool, but a build that hangs on a hostile
// document is still a denial of service against whoever runs it.
const maxRefDepth = 32

type compiler struct {
	doc    *document
	opts   Options
	report Report
}

func (c *compiler) run() ([]schema.Operation, Report, error) {
	paths := make([]string, 0, len(c.doc.Paths)+len(c.doc.Webhooks))
	for p := range c.doc.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var ops []schema.Operation
	for _, path := range paths {
		item := c.doc.Paths[path]
		for _, m := range item.byMethod() {
			if m.op == nil {
				continue
			}
			ops = append(ops, c.operation(path, m.method, item, m.op))
		}
	}

	// Webhooks describe requests an *origin* sends outward, so they constrain
	// nothing an attacker sends to the protected service. Reported rather than
	// dropped in silence.
	if n := len(c.doc.Webhooks); n > 0 {
		c.skip(fmt.Sprintf("%d webhook definition(s): describe outbound requests, "+
			"not traffic reaching this service", n))
	}

	c.report.Operations = len(ops)
	return ops, c.report, nil
}

func (c *compiler) skip(reason string) {
	if !slices.Contains(c.report.Skipped, reason) {
		c.report.Skipped = append(c.report.Skipped, reason)
	}
}

// operation compiles one method on one path.
func (c *compiler) operation(path, method string, item pathItem, op *operation) schema.Operation {
	out := schema.Operation{
		Method: method,
		Path:   normalizePath(path),
		Strict: c.opts.Strict,
	}

	// Path-level parameters apply to every method, and the method may override
	// one by name; the operation's own list wins.
	params := append(slices.Clone(item.Parameters), op.Parameters...)
	seen := map[string]bool{}
	for i := len(params) - 1; i >= 0; i-- {
		p := c.resolveParameter(params[i], 0)
		if p.Name == "" {
			continue
		}
		key := p.In + "\x00" + p.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		f, ok := c.field(p)
		if !ok {
			continue
		}
		switch strings.ToLower(p.In) {
		case "query":
			out.Query = append(out.Query, f)
		case "header":
			out.Headers = append(out.Headers, f)
		case "path":
			// A path parameter is already constrained by the route template,
			// and gwaf matches routes rather than extracting segments, so the
			// declaration adds nothing it can enforce.
			c.skip("path parameters: constrained by the route template itself")
		case "cookie":
			c.skip("cookie parameters: not yet a schema target")
		default:
			c.skip(fmt.Sprintf("parameter in %q: unknown location", p.In))
		}
	}
	// Restore document order after the reverse walk above.
	slices.Reverse(out.Query)
	slices.Reverse(out.Headers)

	body := c.resolveBody(op.RequestBody, 0)
	switch {
	case body == nil:
		if c.opts.AssumeNoBody {
			out.NoBody = true
		}
	default:
		out.Body = c.bodyFields(body)
	}

	c.report.Fields += len(out.Query) + len(out.Headers) + len(out.Body)
	for _, f := range [][]schema.Field{out.Query, out.Headers, out.Body} {
		for _, x := range f {
			if x.Inert() {
				c.report.Inert++
			}
		}
	}
	return out
}

// bodyFields flattens the request body's top-level properties.
//
// Only JSON-ish media types are read: gwaf's body parser emits fields from JSON
// and form encodings, so a constraint on anything else could never be checked.
func (c *compiler) bodyFields(b *requestBody) []schema.Field {
	var chosen *schemaObject
	for _, ct := range []string{
		"application/json", "application/x-www-form-urlencoded",
		"application/vnd.api+json", "text/json",
	} {
		if mt, ok := b.Content[ct]; ok && mt.Schema != nil {
			chosen = mt.Schema
			break
		}
	}
	if chosen == nil {
		for ct, mt := range b.Content {
			if strings.HasSuffix(ct, "+json") && mt.Schema != nil {
				chosen = mt.Schema
				break
			}
		}
	}
	if chosen == nil {
		if len(b.Content) > 0 {
			types := make([]string, 0, len(b.Content))
			for ct := range b.Content {
				types = append(types, ct)
			}
			sort.Strings(types)
			c.skip(fmt.Sprintf("request bodies of type %s: gwaf inspects JSON and "+
				"form encodings as fields, so nothing else can be constrained",
				strings.Join(types, ", ")))
		}
		return nil
	}

	obj := c.resolveSchema(chosen, 0)
	if obj == nil {
		return nil
	}
	obj = c.flatten(obj, 0)

	if obj.Type.primary() != "object" && len(obj.Properties) == 0 {
		c.skip("request bodies that are not objects: gwaf constrains named fields")
		return nil
	}

	names := make([]string, 0, len(obj.Properties))
	for n := range obj.Properties {
		names = append(names, n)
	}
	sort.Strings(names)

	required := map[string]bool{}
	for _, r := range obj.Required {
		required[r] = true
	}

	out := make([]schema.Field, 0, len(names))
	for _, n := range names {
		p := obj.Properties[n]
		f, ok := c.fieldFromSchema(n, &p, required[n])
		if !ok {
			continue
		}
		out = append(out, f)
	}
	return out
}

// field compiles a parameter into a schema.Field.
func (c *compiler) field(p parameter) (schema.Field, bool) {
	if p.Schema == nil {
		if len(p.Content) > 0 {
			c.skip(fmt.Sprintf("parameter %q uses `content`: only `schema` is compiled", p.Name))
		}
		return schema.Field{}, false
	}
	return c.fieldFromSchema(p.Name, p.Schema, p.Required)
}

// fieldFromSchema is where an OpenAPI type becomes something the engine can
// use, and where the value of the whole package is decided.
//
// A field compiled to KindInteger, KindBoolean, an enum, or a UUID is provably
// inert once validated: no sequence of digits is a SQL injection. The engine
// then skips rule evaluation for it entirely, which is why the Report counts
// inert fields separately — that count, not the field count, predicts how much
// work disappears.
func (c *compiler) fieldFromSchema(name string, s *schemaObject, required bool) (schema.Field, bool) {
	s = c.resolveSchema(s, 0)
	if s == nil {
		return schema.Field{}, false
	}
	s = c.flatten(s, 0)

	f := schema.Field{Name: name, Required: required}
	if s.MaxLength != nil && *s.MaxLength > 0 {
		f.MaxLength = *s.MaxLength
	}

	if len(s.Enum) > 0 {
		f.Kind = schema.KindEnum
		f.Enum = make([]string, 0, len(s.Enum))
		for _, v := range s.Enum {
			if v == nil {
				continue
			}
			f.Enum = append(f.Enum, fmt.Sprint(v))
		}
		if len(f.Enum) == 0 {
			return schema.Field{}, false
		}
		return f, true
	}

	switch s.Type.primary() {
	case "integer":
		f.Kind = schema.KindInteger
	case "number":
		f.Kind = schema.KindNumber
	case "boolean":
		f.Kind = schema.KindBoolean
	case "array":
		f.Kind = schema.KindArray
	case "object":
		f.Kind = schema.KindObject
	case "string":
		f.Kind = schema.KindString
		f.Format = formatOf(s.Format)
	case "":
		// A property with no declared type constrains nothing. Common in real
		// documents and worth reporting once rather than per field.
		c.skip("properties with no declared `type`: nothing to constrain")
		return schema.Field{}, false
	default:
		c.skip(fmt.Sprintf("type %q: not a JSON Schema type gwaf models", s.Type.primary()))
		return schema.Field{}, false
	}

	// A `pattern` is a constraint gwaf could enforce and deliberately does not:
	// compiling attacker-adjacent regexes out of a document is how a schema
	// frontend becomes a ReDoS surface, and RE2 would change the semantics the
	// document's author tested against.
	if s.Pattern != "" && f.Format == schema.FormatNone {
		c.skip("`pattern` constraints: not compiled, since importing regexes " +
			"from a document is a denial-of-service surface")
	}
	return f, true
}

// formatOf maps an OpenAPI format onto a gwaf format.
//
// Only formats with a decidable grammar are mapped. "password" and "binary"
// describe intent rather than shape and constrain nothing.
func formatOf(s string) schema.Format {
	switch strings.ToLower(s) {
	case "uuid":
		return schema.FormatUUID
	case "date-time":
		return schema.FormatDateTime
	case "date":
		return schema.FormatDate
	case "email", "idn-email":
		return schema.FormatEmail
	case "byte", "base64":
		return schema.FormatBase64
	case "ipv4":
		return schema.FormatIPv4
	default:
		return schema.FormatNone
	}
}

// flatten merges allOf, and takes the first branch of anyOf/oneOf.
//
// allOf is a conjunction, so merging is exact. anyOf and oneOf are disjunctions
// and cannot be represented by one field; taking a branch would *narrow* the
// schema and reject valid traffic, so the type is dropped instead and the field
// carries only what every branch agrees on. Wrong in the safe direction.
func (c *compiler) flatten(s *schemaObject, depth int) *schemaObject {
	if depth > maxRefDepth {
		return s
	}
	if len(s.AllOf) > 0 {
		merged := *s
		for i := range s.AllOf {
			part := c.flatten(c.resolveSchema(&s.AllOf[i], depth+1), depth+1)
			if part == nil {
				continue
			}
			if merged.Type.primary() == "" {
				merged.Type = part.Type
			}
			if merged.Format == "" {
				merged.Format = part.Format
			}
			if len(merged.Enum) == 0 {
				merged.Enum = part.Enum
			}
			if merged.MaxLength == nil {
				merged.MaxLength = part.MaxLength
			}
			if merged.Properties == nil {
				merged.Properties = map[string]schemaObject{}
			}
			for k, v := range part.Properties {
				if _, ok := merged.Properties[k]; !ok {
					merged.Properties[k] = v
				}
			}
			merged.Required = append(merged.Required, part.Required...)
		}
		merged.AllOf = nil
		return &merged
	}
	if len(s.AnyOf) > 0 || len(s.OneOf) > 0 {
		c.skip("anyOf/oneOf: a disjunction cannot narrow to one field type, " +
			"so the constraint is dropped rather than guessed")
		relaxed := *s
		relaxed.AnyOf, relaxed.OneOf = nil, nil
		relaxed.Type = typeField{}
		return &relaxed
	}
	return s
}

// resolveSchema follows a local $ref into components/schemas.
func (c *compiler) resolveSchema(s *schemaObject, depth int) *schemaObject {
	if s == nil || depth > maxRefDepth {
		return s
	}
	if s.Ref == "" {
		return s
	}
	name, ok := refName(s.Ref, "schemas")
	if !ok {
		c.skip(fmt.Sprintf("external or unrecognised $ref %q: only local "+
			"#/components refs are resolved", s.Ref))
		return nil
	}
	next, ok := c.doc.Components.Schemas[name]
	if !ok {
		c.skip(fmt.Sprintf("$ref %q: not present in components/schemas", s.Ref))
		return nil
	}
	return c.resolveSchema(&next, depth+1)
}

func (c *compiler) resolveParameter(p parameter, depth int) parameter {
	if p.Ref == "" || depth > maxRefDepth {
		return p
	}
	name, ok := refName(p.Ref, "parameters")
	if !ok {
		c.skip(fmt.Sprintf("external or unrecognised $ref %q", p.Ref))
		return parameter{}
	}
	next, ok := c.doc.Components.Parameters[name]
	if !ok {
		c.skip(fmt.Sprintf("$ref %q: not present in components/parameters", p.Ref))
		return parameter{}
	}
	return c.resolveParameter(next, depth+1)
}

func (c *compiler) resolveBody(b *requestBody, depth int) *requestBody {
	if b == nil || b.Ref == "" || depth > maxRefDepth {
		return b
	}
	name, ok := refName(b.Ref, "requestBodies")
	if !ok {
		c.skip(fmt.Sprintf("external or unrecognised $ref %q", b.Ref))
		return nil
	}
	next, ok := c.doc.Components.Bodies[name]
	if !ok {
		c.skip(fmt.Sprintf("$ref %q: not present in components/requestBodies", b.Ref))
		return nil
	}
	return c.resolveBody(&next, depth+1)
}

// refName extracts the component name from "#/components/<section>/<name>".
func refName(ref, section string) (string, bool) {
	prefix := "#/components/" + section + "/"
	if !strings.HasPrefix(ref, prefix) {
		return "", false
	}
	name := ref[len(prefix):]
	if name == "" || strings.Contains(name, "/") {
		return "", false
	}
	return name, true
}

// normalizePath converts an OpenAPI template to gwaf's, which is the same
// syntax, and guarantees a leading slash.
func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		return "/" + p
	}
	return p
}
