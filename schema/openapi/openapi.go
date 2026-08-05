// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package openapi compiles an OpenAPI 3.x document into a gwaf schema.
//
// # Why this is a separate module
//
// YAML needs a third-party parser, and the fifth ownership test in CLAUDE.md §1
// is decisive: everything in the core module is a dependency an embedder
// inherits without consent. Somebody protecting a gRPC service should not
// acquire a YAML parser because a different user wanted OpenAPI. So this lives
// here, and importing gwaf does not pull it in.
//
// # It is a frontend, not a second schema
//
// This package compiles down to []schema.Operation and stops. It contains no
// validation, no matching, and no detection — exactly as a rule frontend
// compiles to the rules IR rather than growing its own evaluator. Everything
// downstream is the typed core, which is what keeps one set of semantics.
//
// The direction matters: an OpenAPI document is *input to an optimiser*, not a
// configuration file the library interprets at request time. A field declared
// `format: uuid` becomes a schema.Field whose validated values are provably
// inert, so the engine skips rule evaluation for them entirely. That is the
// compiler thesis applied to a spec somebody already wrote.
//
// # What it deliberately does not do
//
// OpenAPI describes far more than a firewall can use. Response schemas,
// examples, links, callbacks, security schemes, and server variables are all
// read and ignored, because none of them constrains what an attacker may send.
// A document using features gwaf cannot express still compiles; the unusable
// parts simply produce no constraint, and Report says which.
//
// Silence would be the failure here. A schema that quietly describes less than
// the operator believes is worse than no schema at all, so anything dropped is
// reported rather than assumed.
package openapi

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gsoultan/gwaf/schema"
	"gopkg.in/yaml.v3"
)

// Options control how a document is compiled.
type Options struct {
	// Strict marks every compiled operation as rejecting undeclared
	// parameters. Off by default: switching it on for an under-specified
	// document rejects real traffic, and most published documents are
	// under-specified.
	Strict bool

	// AssumeNoBody marks operations with no requestBody as rejecting one.
	//
	// Off by default for the same reason, and it is worth more than it looks:
	// an operation that provably takes no body lets the engine compile out body
	// parsing for that route entirely.
	AssumeNoBody bool
}

// Report describes what a document contributed and what it could not.
//
// Returned even on success, because the interesting case is a document that
// compiled cleanly and constrains almost nothing.
type Report struct {
	// Operations is how many routes were compiled.
	Operations int

	// Fields is how many parameters carry a usable constraint.
	Fields int

	// Inert is how many fields are provably incapable of carrying a payload —
	// validated integers, UUIDs, enums, booleans. This is the number that
	// predicts how much work the engine can skip.
	Inert int

	// Skipped lists what the document declared and gwaf could not use, each
	// with the reason. An empty document and a fully unusable one both compile
	// without error, and this is how they are told apart.
	Skipped []string
}

// String renders the report for a build log.
func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d operations, %d fields (%d provably inert)",
		r.Operations, r.Fields, r.Inert)
	if len(r.Skipped) > 0 {
		fmt.Fprintf(&b, "\nnot usable as a constraint:")
		for _, s := range r.Skipped {
			fmt.Fprintf(&b, "\n  %s", s)
		}
	}
	return b.String()
}

// Parse compiles an OpenAPI document into a schema.
//
// The input may be JSON or YAML; JSON is a subset of YAML, so one parser reads
// both and no sniffing is needed.
func Parse(doc []byte, opts Options) (*schema.Schema, Report, error) {
	ops, report, err := Compile(doc, opts)
	if err != nil {
		return nil, report, err
	}
	s, err := schema.New(ops...)
	if err != nil {
		return nil, report, fmt.Errorf("openapi: %w", err)
	}
	return s, report, nil
}

// Compile produces the operations without building a Schema, for a caller that
// wants to merge several documents or adjust the result first.
func Compile(doc []byte, opts Options) ([]schema.Operation, Report, error) {
	var d document
	if err := yaml.Unmarshal(doc, &d); err != nil {
		return nil, Report{}, fmt.Errorf("openapi: parse: %w", err)
	}
	if d.OpenAPI == "" && d.Swagger == "" {
		return nil, Report{}, errNotOpenAPI
	}
	if d.Swagger != "" {
		return nil, Report{}, fmt.Errorf("openapi: %w: found swagger %q",
			errUnsupportedVersion, d.Swagger)
	}
	if !strings.HasPrefix(d.OpenAPI, "3.") {
		return nil, Report{}, fmt.Errorf("openapi: %w: found %q",
			errUnsupportedVersion, d.OpenAPI)
	}

	c := &compiler{doc: &d, opts: opts}
	return c.run()
}

// ---- the subset of OpenAPI that constrains a request ------------------------

type document struct {
	OpenAPI    string                     `yaml:"openapi"`
	Swagger    string                     `yaml:"swagger"`
	Paths      map[string]pathItem        `yaml:"paths"`
	Components components                 `yaml:"components"`
	Webhooks   map[string]pathItem        `yaml:"webhooks"`
	Servers    []struct{ URL string }     `yaml:"servers"`
	Extra      map[string]json.RawMessage `yaml:"-"`
}

type components struct {
	Schemas    map[string]schemaObject `yaml:"schemas"`
	Parameters map[string]parameter    `yaml:"parameters"`
	Bodies     map[string]requestBody  `yaml:"requestBodies"`
}

type pathItem struct {
	Parameters []parameter          `yaml:"parameters"`
	Get        *operation           `yaml:"get"`
	Put        *operation           `yaml:"put"`
	Post       *operation           `yaml:"post"`
	Delete     *operation           `yaml:"delete"`
	Options    *operation           `yaml:"options"`
	Head       *operation           `yaml:"head"`
	Patch      *operation           `yaml:"patch"`
	Trace      *operation           `yaml:"trace"`
	Ref        string               `yaml:"$ref"`
	Servers    []struct{ URL any }  `yaml:"servers"`
	Extensions map[string]yaml.Node `yaml:",inline"`
}

// byMethod returns the operations in a stable order, so a compiled schema is
// byte-identical between runs.
func (p pathItem) byMethod() []struct {
	method string
	op     *operation
} {
	return []struct {
		method string
		op     *operation
	}{
		{"GET", p.Get}, {"PUT", p.Put}, {"POST", p.Post},
		{"DELETE", p.Delete}, {"OPTIONS", p.Options}, {"HEAD", p.Head},
		{"PATCH", p.Patch}, {"TRACE", p.Trace},
	}
}

type operation struct {
	OperationID string       `yaml:"operationId"`
	Parameters  []parameter  `yaml:"parameters"`
	RequestBody *requestBody `yaml:"requestBody"`
	Deprecated  bool         `yaml:"deprecated"`
}

type parameter struct {
	Ref      string        `yaml:"$ref"`
	Name     string        `yaml:"name"`
	In       string        `yaml:"in"`
	Required bool          `yaml:"required"`
	Schema   *schemaObject `yaml:"schema"`
	Content  mediaTypes    `yaml:"content"`
}

type requestBody struct {
	Ref      string     `yaml:"$ref"`
	Required bool       `yaml:"required"`
	Content  mediaTypes `yaml:"content"`
}

type mediaTypes map[string]struct {
	Schema *schemaObject `yaml:"schema"`
}

type schemaObject struct {
	Ref        string                  `yaml:"$ref"`
	Type       typeField               `yaml:"type"`
	Format     string                  `yaml:"format"`
	Enum       []any                   `yaml:"enum"`
	MaxLength  *int                    `yaml:"maxLength"`
	Properties map[string]schemaObject `yaml:"properties"`
	Required   []string                `yaml:"required"`
	Items      *schemaObject           `yaml:"items"`
	AllOf      []schemaObject          `yaml:"allOf"`
	AnyOf      []schemaObject          `yaml:"anyOf"`
	OneOf      []schemaObject          `yaml:"oneOf"`
	Pattern    string                  `yaml:"pattern"`
	Nullable   bool                    `yaml:"nullable"`
}

// typeField reads OpenAPI 3.1's `type`, which may be a string or a list.
//
// 3.1 aligned with JSON Schema, where `type: [string, "null"]` is how a
// nullable field is written. A parser that only accepts a string silently drops
// every nullable field in a 3.1 document — which is a large fraction of them.
type typeField struct {
	values []string
}

func (t *typeField) UnmarshalYAML(n *yaml.Node) error {
	var one string
	if err := n.Decode(&one); err == nil {
		t.values = []string{one}
		return nil
	}
	var many []string
	if err := n.Decode(&many); err != nil {
		return fmt.Errorf("type must be a string or a list of strings: %w", err)
	}
	t.values = many
	return nil
}

// primary returns the type ignoring "null", which describes absence rather than
// content and constrains nothing an attacker sends.
func (t typeField) primary() string {
	for _, v := range t.values {
		if v != "null" && v != "" {
			return v
		}
	}
	return ""
}
