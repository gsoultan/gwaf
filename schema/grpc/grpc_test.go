// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package grpc_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/schema"
	gwafgrpc "github.com/gsoultan/gwaf/schema/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

// descriptorSet builds the artifact `protoc --descriptor_set_out` produces, so
// the tests exercise the real input shape rather than a convenient stand-in.
func descriptorSet() []byte {
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	i32 := descriptorpb.FieldDescriptorProto_TYPE_INT32
	bl := descriptorpb.FieldDescriptorProto_TYPE_BOOL
	byts := descriptorpb.FieldDescriptorProto_TYPE_BYTES
	enum := descriptorpb.FieldDescriptorProto_TYPE_ENUM
	msg := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE

	field := func(name string, num int32, t descriptorpb.FieldDescriptorProto_Type, typeName string) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{
			Name: proto.String(name), Number: proto.Int32(num), Type: t.Enum(),
		}
		if typeName != "" {
			f.TypeName = proto.String(typeName)
		}
		return f
	}

	address := &descriptorpb.DescriptorProto{
		Name: proto.String("Address"),
		Field: []*descriptorpb.FieldDescriptorProto{
			field("street", 1, str, ""),
			field("postcode", 2, str, ""),
			field("country_code", 3, i32, ""),
		},
	}
	order := &descriptorpb.DescriptorProto{
		Name: proto.String("CreateOrderRequest"),
		Field: []*descriptorpb.FieldDescriptorProto{
			field("id", 1, i32, ""),
			field("sku", 2, str, ""),
			field("note", 3, str, ""),
			field("gift", 4, bl, ""),
			field("status", 5, enum, ".shop.v1.Status"),
			field("attachment", 6, byts, ""),
			field("shipping", 7, msg, ".shop.v1.Address"),
		},
	}
	empty := &descriptorpb.DescriptorProto{Name: proto.String("Empty")}

	file := &descriptorpb.FileDescriptorProto{
		Name:        proto.String("shop/v1/shop.proto"),
		Package:     proto.String("shop.v1"),
		Syntax:      proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{order, address, empty},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("OrderService"),
			Method: []*descriptorpb.MethodDescriptorProto{
				{
					Name:       proto.String("CreateOrder"),
					InputType:  proto.String(".shop.v1.CreateOrderRequest"),
					OutputType: proto.String(".shop.v1.Empty"),
				},
				{
					Name:       proto.String("Ping"),
					InputType:  proto.String(".shop.v1.Empty"),
					OutputType: proto.String(".shop.v1.Empty"),
				},
			},
		}},
	}

	b, err := proto.Marshal(&descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{file},
	})
	if err != nil {
		panic(err)
	}
	return b
}

func TestCompilesRoutesAndFields(t *testing.T) {
	s, rep, err := gwafgrpc.Parse(descriptorSet(), gwafgrpc.Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	t.Log("\n" + rep.String())

	if rep.Services != 1 || rep.Methods != 2 {
		t.Errorf("services=%d methods=%d, want 1 and 2", rep.Services, rep.Methods)
	}

	op, ok := s.Lookup("POST", "/shop.v1.OrderService/CreateOrder")
	if !ok {
		t.Fatal("the RPC path did not compile to a route")
	}

	// Fields are named by number path, which is what the wire parser emits.
	got := map[string]schema.Field{}
	for _, f := range op.Body {
		got[f.Name] = f
	}
	for _, want := range []string{"1", "2", "3", "4", "5", "6", "7", "7.1", "7.2", "7.3"} {
		if _, ok := got[want]; !ok {
			t.Errorf("field %q missing: %v", want, keys(op.Body))
		}
	}
}

// TestInertFieldsAreTheWholePoint checks the number that predicts how much work
// the engine can skip. A validated integer, bool, or enum provably cannot carry
// a payload.
func TestInertFieldsAreTheWholePoint(t *testing.T) {
	s, rep, err := gwafgrpc.Parse(descriptorSet(), gwafgrpc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Inert == 0 {
		t.Fatal("no inert fields: the descriptor constrains nothing the engine can use")
	}

	op, _ := s.Lookup("POST", "/shop.v1.OrderService/CreateOrder")
	want := map[string]bool{
		"1": true, "4": true, "5": true, // int32, bool, enum
		"7.3": true,              // nested int32
		"2":   false, "3": false, // strings
		"6": false, // bytes: the declared type says nothing about the content
	}
	for _, f := range op.Body {
		if w, known := want[f.Name]; known && f.Inert() != w {
			t.Errorf("field %s Inert() = %v, want %v (kind=%v)", f.Name, f.Inert(), w, f.Kind)
		}
	}
}

// TestNestedMessagesFlattenToNumberPaths: a nested message is reached through
// its parent's number, and the wire parser names it the same way.
func TestNestedMessagesFlattenToNumberPaths(t *testing.T) {
	s, _, err := gwafgrpc.Parse(descriptorSet(), gwafgrpc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	op, _ := s.Lookup("POST", "/shop.v1.OrderService/CreateOrder")

	var street, code *schema.Field
	for i := range op.Body {
		switch op.Body[i].Name {
		case "7.1":
			street = &op.Body[i]
		case "7.3":
			code = &op.Body[i]
		}
	}
	if street == nil || street.Kind != schema.KindString {
		t.Errorf("7.1 (Address.street) = %+v, want a string", street)
	}
	if code == nil || code.Kind != schema.KindInteger {
		t.Errorf("7.3 (Address.country_code) = %+v, want an integer", code)
	}
}

func TestRecursiveDescriptorsTerminate(t *testing.T) {
	msg := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	node := &descriptorpb.DescriptorProto{
		Name: proto.String("Node"),
		Field: []*descriptorpb.FieldDescriptorProto{{
			Name: proto.String("child"), Number: proto.Int32(1),
			Type: msg.Enum(), TypeName: proto.String(".tree.Node"),
		}},
	}
	file := &descriptorpb.FileDescriptorProto{
		Name: proto.String("tree.proto"), Package: proto.String("tree"),
		MessageType: []*descriptorpb.DescriptorProto{node},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("TreeService"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name: proto.String("Walk"), InputType: proto.String(".tree.Node"),
				OutputType: proto.String(".tree.Node"),
			}},
		}},
	}
	b, _ := proto.Marshal(&descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{file},
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, _, err := gwafgrpc.Parse(b, gwafgrpc.Options{}); err != nil {
			t.Errorf("Parse: %v", err)
		}
	}()
	<-done
}

func TestBadInput(t *testing.T) {
	// Random bytes are not a descriptor set. proto.Unmarshal is permissive, so
	// the empty-file check is what actually catches this.
	for _, in := range [][]byte{nil, {}, []byte("not a descriptor at all")} {
		if _, _, err := gwafgrpc.Parse(in, gwafgrpc.Options{}); !errors.Is(err, gwafgrpc.ErrNotDescriptorSet) {
			t.Errorf("Parse(%q): err = %v, want ErrNotDescriptorSet", in, err)
		}
	}
}

func TestReportNamesWhatItCouldNotUse(t *testing.T) {
	msg := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	req := &descriptorpb.DescriptorProto{
		Name: proto.String("Req"),
		Field: []*descriptorpb.FieldDescriptorProto{{
			Name: proto.String("external"), Number: proto.Int32(1),
			Type: msg.Enum(), TypeName: proto.String(".not.In.This.Set"),
		}},
	}
	file := &descriptorpb.FileDescriptorProto{
		Name: proto.String("x.proto"), Package: proto.String("x"),
		MessageType: []*descriptorpb.DescriptorProto{req},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("S"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name: proto.String("M"), InputType: proto.String(".x.Req"),
				OutputType: proto.String(".x.Req"),
			}},
		}},
	}
	b, _ := proto.Marshal(&descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{file},
	})

	_, rep, err := gwafgrpc.Parse(b, gwafgrpc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep.String(), "not in the descriptor set") {
		t.Errorf("a missing type was not reported:\n%s", rep.String())
	}
}

// TestEndToEndWithWAF is the reason the package exists: a descriptor a build
// already produces becomes work the engine can skip, without losing detection.
func TestEndToEndWithWAF(t *testing.T) {
	s, _, err := gwafgrpc.Parse(descriptorSet(), gwafgrpc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := gwaf.New(gwaf.WithSchema(s))
	if err != nil {
		t.Fatal(err)
	}

	// Field 2 is a string: an injection in it is still caught.
	if d := call(t, w, "/shop.v1.OrderService/CreateOrder",
		pbField(2, "1' OR 1=1--")); !d.Blocked() {
		t.Error("an injection in a declared string field was not detected")
	}

	// A benign request passes.
	if d := call(t, w, "/shop.v1.OrderService/CreateOrder",
		pbField(2, "SKU-000042")); d.Blocked() {
		t.Errorf("benign request blocked: rule=%d msg=%q", d.RuleID(), d.Message())
	}
}

// TestStrictRejectsUndeclaredFields covers what proto3 makes possible and
// dangerous: unknown fields are preserved by design, so a service will accept
// and forward a field nobody declared.
func TestStrictRejectsUndeclaredFields(t *testing.T) {
	s, _, err := gwafgrpc.Parse(descriptorSet(), gwafgrpc.Options{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	w, err := gwaf.New(gwaf.WithSchema(s))
	if err != nil {
		t.Fatal(err)
	}

	// Field 99 is not in the descriptor.
	if d := call(t, w, "/shop.v1.OrderService/CreateOrder",
		pbField(99, "anything")); !d.Blocked() {
		t.Error("an undeclared field was accepted under a strict schema")
	}
	// A declared one still passes.
	if d := call(t, w, "/shop.v1.OrderService/CreateOrder",
		pbField(2, "SKU-1")); d.Blocked() {
		t.Errorf("a declared field was rejected: %v", d.Detail())
	}
}

// ---- helpers ----------------------------------------------------------------

// pbVarint appends a base-128 varint.
//
// The tag is a varint, not a byte. Field 99 has tag 794, which does not fit in
// one byte and silently encodes as field 3 if written as one -- which is how the
// first version of this helper made a strict-mode test pass a field the schema
// declares.
func pbVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// pbField encodes one length-delimited protobuf field, framed for gRPC.
func pbField(num int, s string) string {
	var pb []byte
	pb = pbVarint(pb, uint64(num)<<3|2)
	pb = pbVarint(pb, uint64(len(s)))
	pb = append(pb, s...)

	f := make([]byte, 5+len(pb))
	f[3] = byte(len(pb) >> 8)
	f[4] = byte(len(pb))
	copy(f[5:], pb)
	return string(f)
}

func call(t *testing.T, w *gwaf.WAF, path, body string) gwaf.Decision {
	t.Helper()
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("POST", path, "HTTP/2.0")
	tx.AddRequestHeader("Content-Type", "application/grpc")
	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		return d
	}
	tx.SetRequestBody([]byte(body))
	return tx.ProcessRequestBody()
}

func keys(fs []schema.Field) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Name
	}
	return out
}
