// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package infer

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/gsoultan/gwaf/schema"
)

// WriteOpenAPI writes ops as an OpenAPI 3.0 document in JSON, which is what a
// reviewer edits and what schema/openapi compiles back.
//
// JSON rather than YAML because every name in a draft was written by a client:
// encoding/json escapes whatever it is given, and a hand-assembled YAML
// document is one unquoted colon away from meaning something else. Keys are
// sorted, so two drafts of the same traffic are byte-identical and a diff
// between two shows only what changed.
//
// Only what Draft produces is written: methods, paths, query parameters with
// their type, format and maximum length, and a path parameter for each
// template segment. An operation's headers and body are not.
func WriteOpenAPI(w io.Writer, title string, ops []schema.Operation) error {
	paths := make(map[string]map[string]openAPIOperation, len(ops))
	for i := range ops {
		op := &ops[i]
		if paths[op.Path] == nil {
			paths[op.Path] = make(map[string]openAPIOperation)
		}
		paths[op.Path][strings.ToLower(op.Method)] = openAPIOperation{
			Parameters: parameters(op),
			Responses:  map[string]openAPIResponse{"default": {Description: "Not described by this draft."}},
		}
	}
	doc := openAPIDocument{
		OpenAPI: "3.0.3",
		Info:    openAPIInfo{Title: title, Version: "draft"},
		Paths:   paths,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

type openAPIDocument struct {
	OpenAPI string                                 `json:"openapi"`
	Info    openAPIInfo                            `json:"info"`
	Paths   map[string]map[string]openAPIOperation `json:"paths"`
}

type openAPIInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type openAPIOperation struct {
	Parameters []openAPIParameter         `json:"parameters,omitempty"`
	Responses  map[string]openAPIResponse `json:"responses"`
}

type openAPIResponse struct {
	Description string `json:"description"`
}

type openAPIParameter struct {
	Name     string        `json:"name"`
	In       string        `json:"in"`
	Required bool          `json:"required,omitempty"`
	Schema   openAPISchema `json:"schema"`
}

type openAPISchema struct {
	Type      string `json:"type"`
	Format    string `json:"format,omitempty"`
	MaxLength int    `json:"maxLength,omitempty"`
}

func parameters(op *schema.Operation) []openAPIParameter {
	var out []openAPIParameter
	// A template segment is a parameter OpenAPI requires to be declared. It
	// is declared as a string, which asserts nothing: Template already
	// decided what the segment looks like, and the path is matched, not
	// validated.
	for _, seg := range strings.Split(op.Path, "/") {
		if len(seg) > 2 && seg[0] == '{' && seg[len(seg)-1] == '}' {
			out = append(out, openAPIParameter{
				Name: seg[1 : len(seg)-1], In: "path", Required: true,
				Schema: openAPISchema{Type: "string"},
			})
		}
	}
	for i := range op.Query {
		f := &op.Query[i]
		s := openAPISchema{Type: f.Kind.String(), MaxLength: f.MaxLength}
		if f.Format != schema.FormatNone {
			s.Format = f.Format.String()
		}
		out = append(out, openAPIParameter{Name: f.Name, In: "query", Schema: s})
	}
	return out
}
