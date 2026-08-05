// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package grpc compiles protobuf descriptors into a gwaf schema.
//
// It gives gRPC what schema/openapi gives REST: the types an API declared, used
// as input to an optimiser rather than as a config file read at request time.
//
// # What a descriptor buys
//
// gwaf parses the protobuf wire format without any descriptor — the format is
// self-describing enough to walk — and emits each length-delimited field under
// its number path: "3", "4.1". What it cannot know unaided is what those fields
// *are*.
//
// A descriptor says. Field 3 is an int32, field 7 is an enum, field 2 is a
// string. The first two are provably inert once validated: no sequence of digits
// is a SQL injection, and no member of a closed enum is a script tag. The engine
// skips rule evaluation for them entirely, which on a well-specified service is
// most of the per-request work — and it skips them *soundly* rather than
// probabilistically.
//
// The remaining string fields still get the full pipeline. Positive security
// narrows what has to be inspected; it does not replace inspecting it.
//
// # Routes are the other half
//
// A gRPC path is "/package.Service/Method", which is exactly a route. A
// descriptor enumerates every method a service exposes, so a call to a method
// that does not exist is a schema violation rather than a rule miss — and that
// is most of what reconnaissance against a gRPC service looks like.
//
// # Separate module
//
// Reading a FileDescriptorSet needs google.golang.org/protobuf. The fifth
// ownership test in CLAUDE.md §1: everything in core is a dependency an embedder
// inherits without consent, and somebody protecting a REST API should not
// acquire a protobuf runtime because a different user speaks gRPC.
package grpc

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gsoultan/gwaf/schema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

// Options control compilation.
type Options struct {
	// Strict rejects request fields the descriptor does not declare.
	//
	// Worth more for protobuf than for JSON: proto3 keeps unknown fields by
	// design, so a service will happily accept and forward a field nobody
	// declared. Off by default all the same, because a deployment whose clients
	// run an older or newer schema sends undeclared fields as a matter of
	// course, and rejecting those is an outage rather than a defence.
	Strict bool

	// AssumeNoBody marks methods whose request message has no fields as
	// rejecting a body. An empty message is one byte on the wire, so a body
	// arriving for one is not a client gwaf needs to accommodate.
	AssumeNoBody bool

	// MaxDepth bounds how far nested message types are expanded into field
	// paths. Zero means the default.
	//
	// Descriptors are routinely recursive — a Node with a list of Nodes — so
	// expansion needs a ceiling that does not depend on the input.
	MaxDepth int
}

const defaultMaxDepth = 6

// Report describes what a descriptor set contributed and what it could not.
type Report struct {
	// Services and Methods compiled.
	Services int
	Methods  int

	// Fields is how many request fields carry a usable constraint.
	Fields int

	// Inert is how many are provably incapable of carrying a payload. This is
	// the number that predicts how much work the engine can skip.
	Inert int

	// Skipped lists what the descriptor declared and gwaf could not use.
	Skipped []string
}

// String renders the report for a build log.
func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d service(s), %d method(s), %d field(s) (%d provably inert)",
		r.Services, r.Methods, r.Fields, r.Inert)
	if len(r.Skipped) > 0 {
		b.WriteString("\nnot usable as a constraint:")
		for _, s := range r.Skipped {
			fmt.Fprintf(&b, "\n  %s", s)
		}
	}
	return b.String()
}

// Parse compiles a serialized FileDescriptorSet into a schema.
//
// The input is what `protoc --descriptor_set_out` produces, which is the
// artifact a build already has: no .proto parsing here, and no dependency on
// protoc at request time.
func Parse(descriptorSet []byte, opts Options) (*schema.Schema, Report, error) {
	ops, report, err := Compile(descriptorSet, opts)
	if err != nil {
		return nil, report, err
	}
	s, err := schema.New(ops...)
	if err != nil {
		return nil, report, fmt.Errorf("grpc: %w", err)
	}
	return s, report, nil
}

// Compile produces the operations without building a Schema, for a caller that
// wants to merge several descriptor sets or adjust the result first.
func Compile(descriptorSet []byte, opts Options) ([]schema.Operation, Report, error) {
	var fds descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(descriptorSet, &fds); err != nil {
		return nil, Report{}, fmt.Errorf("grpc: %w: %w", ErrNotDescriptorSet, err)
	}
	if len(fds.File) == 0 {
		return nil, Report{}, ErrNotDescriptorSet
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = defaultMaxDepth
	}

	c := &compiler{opts: opts, messages: map[string]*descriptorpb.DescriptorProto{}}
	for _, f := range fds.File {
		c.indexMessages(f.GetPackage(), f.MessageType)
	}
	return c.run(&fds)
}

type compiler struct {
	opts   Options
	report Report

	// messages indexes every message type by its fully qualified name, so a
	// field referring to ".pkg.Msg" can be expanded.
	messages map[string]*descriptorpb.DescriptorProto
}

// indexMessages records a file's messages, including nested ones.
func (c *compiler) indexMessages(pkg string, msgs []*descriptorpb.DescriptorProto) {
	for _, m := range msgs {
		name := "." + pkg + "." + m.GetName()
		if pkg == "" {
			name = "." + m.GetName()
		}
		c.messages[name] = m
		c.indexNested(name, m.NestedType)
	}
}

func (c *compiler) indexNested(prefix string, msgs []*descriptorpb.DescriptorProto) {
	for _, m := range msgs {
		name := prefix + "." + m.GetName()
		c.messages[name] = m
		c.indexNested(name, m.NestedType)
	}
}

func (c *compiler) run(fds *descriptorpb.FileDescriptorSet) ([]schema.Operation, Report, error) {
	var ops []schema.Operation

	for _, f := range fds.File {
		pkg := f.GetPackage()
		for _, svc := range f.Service {
			c.report.Services++
			svcName := svc.GetName()
			if pkg != "" {
				svcName = pkg + "." + svcName
			}

			for _, m := range svc.Method {
				c.report.Methods++
				ops = append(ops, c.method(svcName, m))
			}
		}
	}

	sort.Slice(ops, func(i, j int) bool { return ops[i].Path < ops[j].Path })
	return ops, c.report, nil
}

// method compiles one RPC into an operation.
func (c *compiler) method(service string, m *descriptorpb.MethodDescriptorProto) schema.Operation {
	op := schema.Operation{
		// gRPC is POST over HTTP/2 without exception; a call arriving by any
		// other method is not a client the service has.
		Method: "POST",
		Path:   "/" + service + "/" + m.GetName(),
		Strict: c.opts.Strict,
	}

	// Streaming is not a constraint gwaf can express, and it does not need to
	// be: every frame carries the same message type, so the field constraints
	// apply to each one unchanged.
	req := c.messages[m.GetInputType()]
	if req == nil {
		c.skip(fmt.Sprintf("%s: request type %q is not in the descriptor set",
			op.Path, m.GetInputType()))
		return op
	}

	op.Body = c.fields(req, "", 0)
	if len(op.Body) == 0 && c.opts.AssumeNoBody && len(req.Field) == 0 {
		op.NoBody = true
	}

	c.report.Fields += len(op.Body)
	for _, f := range op.Body {
		if f.Inert() {
			c.report.Inert++
		}
	}
	return op
}

// fields flattens a message into field-number paths, matching what the wire
// parser emits.
func (c *compiler) fields(msg *descriptorpb.DescriptorProto, prefix string, depth int) []schema.Field {
	if depth > c.opts.MaxDepth {
		return nil
	}

	var out []schema.Field
	for _, f := range msg.Field {
		name := prefix
		if name != "" {
			name += "."
		}
		name += fmt.Sprint(f.GetNumber())

		// A repeated field appears once per element on the wire, all under the
		// same number, so one declaration covers them all.
		switch f.GetType() {
		case descriptorpb.FieldDescriptorProto_TYPE_MESSAGE,
			descriptorpb.FieldDescriptorProto_TYPE_GROUP:
			nested := c.messages[f.GetTypeName()]
			if nested == nil {
				c.skip(fmt.Sprintf("field %s: message type %q is not in the "+
					"descriptor set", name, f.GetTypeName()))
				continue
			}
			out = append(out, c.fields(nested, name, depth+1)...)

			// The message itself is also emitted as a value by the wire parser,
			// because a string and a nested message are indistinguishable on the
			// wire. Declaring it as an object keeps a strict schema from calling
			// that value undeclared.
			out = append(out, schema.Field{Name: name, Kind: schema.KindObject})

		default:
			fl, ok := c.field(name, f)
			if !ok {
				continue
			}
			out = append(out, fl)
		}
	}
	return out
}

// field maps one scalar protobuf field onto a schema field.
//
// This is where the value of the whole package is decided. An int32 or a bool
// or a closed enum, once validated, provably cannot carry a payload — so the
// engine skips rule evaluation for it entirely, soundly rather than
// probabilistically.
func (c *compiler) field(name string, f *descriptorpb.FieldDescriptorProto) (schema.Field, bool) {
	out := schema.Field{
		Name: name,
		// proto3 has no required fields, and a proto2 "required" that a client
		// omits is the origin's problem rather than an attack. Marking fields
		// required here would reject partial updates a service accepts.
		Required: false,
	}

	switch f.GetType() {
	case descriptorpb.FieldDescriptorProto_TYPE_STRING:
		out.Kind = schema.KindString

	case descriptorpb.FieldDescriptorProto_TYPE_BYTES:
		// Bytes are not inert. The declared type says nothing about the
		// content: an upload, a serialized sub-document, and a base64 blob all
		// arrive as bytes, and every one of them is inspected.
		out.Kind = schema.KindString

	case descriptorpb.FieldDescriptorProto_TYPE_INT32,
		descriptorpb.FieldDescriptorProto_TYPE_INT64,
		descriptorpb.FieldDescriptorProto_TYPE_UINT32,
		descriptorpb.FieldDescriptorProto_TYPE_UINT64,
		descriptorpb.FieldDescriptorProto_TYPE_SINT32,
		descriptorpb.FieldDescriptorProto_TYPE_SINT64,
		descriptorpb.FieldDescriptorProto_TYPE_FIXED32,
		descriptorpb.FieldDescriptorProto_TYPE_FIXED64,
		descriptorpb.FieldDescriptorProto_TYPE_SFIXED32,
		descriptorpb.FieldDescriptorProto_TYPE_SFIXED64:
		out.Kind = schema.KindInteger

	case descriptorpb.FieldDescriptorProto_TYPE_DOUBLE,
		descriptorpb.FieldDescriptorProto_TYPE_FLOAT:
		out.Kind = schema.KindNumber

	case descriptorpb.FieldDescriptorProto_TYPE_BOOL:
		out.Kind = schema.KindBoolean

	case descriptorpb.FieldDescriptorProto_TYPE_ENUM:
		// An enum is a closed set, which is the strongest constraint a schema
		// can carry. The wire form is a varint, so it never reaches a detector
		// in the first place — but declaring it keeps a strict schema honest.
		out.Kind = schema.KindInteger

	default:
		c.skip(fmt.Sprintf("field %s: type %v has no gwaf equivalent", name, f.GetType()))
		return schema.Field{}, false
	}
	return out, true
}

func (c *compiler) skip(reason string) {
	for _, s := range c.report.Skipped {
		if s == reason {
			return
		}
	}
	c.report.Skipped = append(c.report.Skipped, reason)
}
