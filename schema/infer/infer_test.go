// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package infer_test

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf/schema"
	"github.com/gsoultan/gwaf/schema/infer"
)

// feed shows the learner n requests to GET path, each with the pairs build
// returns for its index.
func feed(l *infer.Learner, n int, path string, build func(i int) []infer.Pair) {
	for i := range n {
		l.Observe("GET", path, build(i))
	}
}

func queryOf(t *testing.T, ops []schema.Operation, path string) map[string]schema.Field {
	t.Helper()
	for _, op := range ops {
		if op.Path == path {
			out := make(map[string]schema.Field, len(op.Query))
			for _, f := range op.Query {
				out[f.Name] = f
			}
			return out
		}
	}
	t.Fatalf("no operation drafted for %s in %+v", path, ops)
	return nil
}

func TestDraftDeclaresTheTypeEveryValueFit(t *testing.T) {
	l := infer.New(infer.Limits{MinSamples: 5})
	feed(l, 10, "/api/orders", func(i int) []infer.Pair {
		return []infer.Pair{
			{Name: "page", Value: strconv.Itoa(i)},
			{Name: "price", Value: strconv.Itoa(i) + ".5"},
			{Name: "open", Value: []string{"true", "false"}[i%2]},
			{Name: "customer", Value: fmt.Sprintf("123e4567-e89b-12d3-a456-4266141740%02d", i)},
			{Name: "since", Value: fmt.Sprintf("2026-11-%02d", i+1)},
			{Name: "q", Value: strings.Repeat("shoes ", i)},
		}
	})

	got := queryOf(t, l.Draft(), "/api/orders")
	want := map[string]schema.Field{
		"page":     {Name: "page", Kind: schema.KindInteger},
		"price":    {Name: "price", Kind: schema.KindNumber},
		"open":     {Name: "open", Kind: schema.KindBoolean},
		"customer": {Name: "customer", Kind: schema.KindString, Format: schema.FormatUUID, MaxLength: 128},
		"since":    {Name: "since", Kind: schema.KindString, Format: schema.FormatDate, MaxLength: 64},
		"q":        {Name: "q", Kind: schema.KindString, MaxLength: 128},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("drafted\n %+v\nwant\n %+v", got, want)
	}
}

// What a draft is for: a value outside the learned shape is a violation, and
// every value that was seen is not.
func TestDraftedFieldRefusesWhatWasNeverSeen(t *testing.T) {
	l := infer.New(infer.Limits{MinSamples: 5})
	feed(l, 10, "/api/orders", func(i int) []infer.Pair {
		return []infer.Pair{{Name: "id", Value: strconv.Itoa(1000 + i)}}
	})
	id := queryOf(t, l.Draft(), "/api/orders")["id"]

	if v := schema.Validate(id, []byte("1007")); v != schema.ViolationNone {
		t.Errorf("a value like those seen is a violation: %v", v)
	}
	for _, attack := range []string{"1 OR 1=1", "../../etc/passwd", "1;id"} {
		if schema.Validate(id, []byte(attack)) == schema.ViolationNone {
			t.Errorf("%q passes a field learned from integers", attack)
		}
	}
}

// One value outside the shape widens the field for good. The safe direction:
// a draft never refuses something it was shown.
func TestOneOddValueWidensTheField(t *testing.T) {
	l := infer.New(infer.Limits{MinSamples: 5})
	feed(l, 50, "/api/orders", func(i int) []infer.Pair {
		v := strconv.Itoa(i)
		if i == 31 {
			v = "latest"
		}
		return []infer.Pair{{Name: "id", Value: v}}
	})
	if id := queryOf(t, l.Draft(), "/api/orders")["id"]; id.Kind != schema.KindString || id.Format != schema.FormatNone {
		t.Errorf("drafted %+v, want a plain string after one non-integer value", id)
	}
}

func TestTooFewSamplesDraftNothing(t *testing.T) {
	l := infer.New(infer.Limits{MinSamples: 20})
	feed(l, 19, "/rare", func(int) []infer.Pair { return []infer.Pair{{Name: "a", Value: "1"}} })
	feed(l, 30, "/common", func(i int) []infer.Pair {
		if i < 19 {
			return []infer.Pair{{Name: "seldom", Value: "1"}, {Name: "always", Value: "1"}}
		}
		return []infer.Pair{{Name: "always", Value: "1"}}
	})

	ops := l.Draft()
	if len(ops) != 1 || ops[0].Path != "/common" {
		t.Fatalf("drafted %+v, want only /common", ops)
	}
	if got := queryOf(t, ops, "/common"); len(got) != 1 || got["always"].Name == "" {
		t.Errorf("drafted %+v, want only the parameter seen often enough", got)
	}
}

func TestDraftIsLoose(t *testing.T) {
	l := infer.New(infer.Limits{MinSamples: 1})
	l.Observe("get", "/a", []infer.Pair{{Name: "n", Value: "5"}})
	for _, op := range l.Draft() {
		if op.Strict || op.NoBody {
			t.Errorf("%s %s is drafted strict or bodiless; a draft must not refuse what it has not seen", op.Method, op.Path)
		}
		if op.Method != "GET" {
			t.Errorf("method %q, want it upper-cased", op.Method)
		}
		for _, f := range op.Query {
			if f.Required || f.Min != nil || f.Max != nil || len(f.Enum) != 0 {
				t.Errorf("%s is drafted with a requirement, a range or an enumeration: %+v", f.Name, f)
			}
		}
	}
}

func TestTemplate(t *testing.T) {
	for path, want := range map[string]string{
		"/":                      "/",
		"/api/orders":            "/api/orders",
		"/api/orders/17":         "/api/orders/{id}",
		"/api/orders/17/items/3": "/api/orders/{id}/items/{id2}",
		"/u/123e4567-e89b-12d3-a456-426614174000/avatar": "/u/{id}/avatar",
		"/blob/0123456789abcdef0123":                     "/blob/{id}",
		"/cafe/decade/added":                             "/cafe/decade/added",
		"/v2/items":                                      "/v2/items",
	} {
		if got, ok := infer.Template(path); !ok || got != want {
			t.Errorf("Template(%q) = %q, %v; want %q", path, got, ok, want)
		}
	}
	for _, bad := range []string{"", "no-slash", "/a b", "/a\x00", "/é", "/" + strings.Repeat("a/", 17)} {
		if got, ok := infer.Template(bad); ok {
			t.Errorf("Template(%q) = %q, want it refused", bad, got)
		}
	}
}

// Every count a client can drive has a ceiling, and what is past it is
// counted rather than kept.
func TestLimitsHold(t *testing.T) {
	l := infer.New(infer.Limits{MaxOperations: 3, MaxFields: 2, MaxNameLength: 16, MinSamples: 1})
	for i := range 100 {
		l.Observe("GET", "/p"+strconv.Itoa(i)+"x", []infer.Pair{
			{Name: "a", Value: "1"}, {Name: "b", Value: "1"}, {Name: "c" + strconv.Itoa(i), Value: "1"},
			{Name: strings.Repeat("n", 17), Value: "1"}, {Name: "bad name", Value: "1"}, {Name: "", Value: "1"},
		})
	}
	l.Observe("BREW", "/pot", nil)
	l.Observe("GET", "/"+strings.Repeat("a", 32), nil)

	ops := l.Draft()
	if len(ops) != 3 {
		t.Errorf("%d operations kept, want 3", len(ops))
	}
	for _, op := range ops {
		if len(op.Query) != 2 {
			t.Errorf("%s keeps %d parameters, want 2", op.Path, len(op.Query))
		}
	}
	st := l.Stats()
	if st.Observed != 3 || st.DroppedOperations != 99 || st.DroppedFields != 12 {
		t.Errorf("stats %+v, want 3 observed, 99 operations and 12 parameters dropped", st)
	}
}

// The property the package is named for. The values below are secrets; after
// learning from them, nothing the learner can be made to produce contains one.
func TestNoValueIsKept(t *testing.T) {
	secrets := []string{"s3cr3t-session-token-AAAA", "alice@example.com", "hunter2hunter2"}
	l := infer.New(infer.Limits{MinSamples: 1})
	for range 50 {
		for _, s := range secrets {
			l.Observe("GET", "/login", []infer.Pair{{Name: "token", Value: s}})
		}
	}
	var doc bytes.Buffer
	if err := infer.WriteOpenAPI(&doc, "t", l.Draft()); err != nil {
		t.Fatal(err)
	}
	dump := doc.String() + fmt.Sprintf("%+v %+v", l.Draft(), l.Stats())
	for _, s := range secrets {
		if strings.Contains(dump, s) {
			t.Errorf("the draft contains a value it was shown: %q", s)
		}
	}
}

func TestWriteOpenAPIIsStableAndEscapes(t *testing.T) {
	l := infer.New(infer.Limits{MinSamples: 1})
	l.Observe("GET", "/orders/17", []infer.Pair{{Name: "page", Value: "2"}, {Name: `<script>"x"`, Value: "v"}})
	l.Observe("POST", "/orders/18", nil)

	var a, b bytes.Buffer
	if err := infer.WriteOpenAPI(&a, "Orders", l.Draft()); err != nil {
		t.Fatal(err)
	}
	_ = infer.WriteOpenAPI(&b, "Orders", l.Draft())
	if a.String() != b.String() {
		t.Error("two drafts of the same traffic differ")
	}
	out := a.String()
	if strings.Contains(out, "<script>") {
		t.Errorf("a parameter name was written unescaped:\n%s", out)
	}
	for _, want := range []string{`"/orders/{id}"`, `"get"`, `"post"`, `"in": "path"`, `"type": "integer"`} {
		if !strings.Contains(out, want) {
			t.Errorf("the document lacks %s:\n%s", want, out)
		}
	}
}

// FuzzObserve: whatever a client names, the limits hold and a draft can be
// written.
func FuzzObserve(f *testing.F) {
	f.Add("GET", "/api/orders/17", "id", "5")
	f.Add("post", "/\x00", "", "")
	f.Add("GET", "/a/{id}/b", "q", strings.Repeat("9", 400))
	f.Fuzz(func(t *testing.T, method, path, name, value string) {
		l := infer.New(infer.Limits{MaxOperations: 4, MaxFields: 4, MaxNameLength: 32, MinSamples: 1})
		for i := range 8 {
			l.Observe(method, path+strconv.Itoa(i)+"z", []infer.Pair{{Name: name, Value: value}, {Name: name + strconv.Itoa(i), Value: value}})
		}
		ops := l.Draft()
		if len(ops) > 4 {
			t.Fatalf("%d operations past a limit of 4", len(ops))
		}
		for _, op := range ops {
			if len(op.Query) > 4 || len(op.Path) > 32 {
				t.Fatalf("limits exceeded: %+v", op)
			}
			for _, fld := range op.Query {
				if fld.Kind != schema.KindString && schema.Validate(fld, []byte(value)) != schema.ViolationNone {
					t.Fatalf("drafted %+v refuses the value it was learned from: %q", fld, value)
				}
			}
		}
		if err := infer.WriteOpenAPI(&bytes.Buffer{}, "t", ops); err != nil {
			t.Fatalf("write: %v", err)
		}
	})
}

func ExampleLearner() {
	l := infer.New(infer.Limits{MinSamples: 3})
	for id := range 5 {
		l.Observe("GET", "/orders/"+strconv.Itoa(100+id), []infer.Pair{{Name: "page", Value: strconv.Itoa(id)}})
	}
	for _, op := range l.Draft() {
		fmt.Println(op.Method, op.Path, op.Query[0].Name, op.Query[0].Kind)
	}
	// Output: GET /orders/{id} page integer
}

func ExampleWriteOpenAPI() {
	l := infer.New(infer.Limits{MinSamples: 1})
	l.Observe("GET", "/ping", []infer.Pair{{Name: "n", Value: "1"}})
	_ = infer.WriteOpenAPI(os.Stdout, "Draft", l.Draft())
	// Output:
	// {
	//   "openapi": "3.0.3",
	//   "info": {
	//     "title": "Draft",
	//     "version": "draft"
	//   },
	//   "paths": {
	//     "/ping": {
	//       "get": {
	//         "parameters": [
	//           {
	//             "name": "n",
	//             "in": "query",
	//             "schema": {
	//               "type": "integer"
	//             }
	//           }
	//         ],
	//         "responses": {
	//           "default": {
	//             "description": "Not described by this draft."
	//           }
	//         }
	//       }
	//     }
	//   }
	// }
}

func ExampleTemplate() {
	fmt.Println(infer.Template("/users/42/orders/123e4567-e89b-12d3-a456-426614174000"))
	// Output: /users/{id}/orders/{id2} true
}
