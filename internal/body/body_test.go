// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type field struct {
	name, value string
	kind        Kind
}

func parseJSON(t testing.TB, src string, limits Limits) ([]field, error) {
	t.Helper()
	var p Parser
	p.Reset(limits)

	var out []field
	err := p.ParseJSON([]byte(src), func(name, value []byte, k Kind) bool {
		out = append(out, field{string(name), string(value), k})
		return true
	})
	return out, err
}

func parseForm(t testing.TB, src string, limits Limits) ([]field, error) {
	t.Helper()
	var p Parser
	p.Reset(limits)

	var out []field
	err := p.ParseForm([]byte(src), func(name, value []byte, k Kind) bool {
		out = append(out, field{string(name), string(value), k})
		return true
	})
	return out, err
}

// valuesOf returns only the leaf values, ignoring keys.
func valuesOf(fs []field) map[string]string {
	m := map[string]string{}
	for _, f := range fs {
		if f.kind != KindKey {
			m[f.name] = f.value
		}
	}
	return m
}

func TestParseJSONFlat(t *testing.T) {
	fs, err := parseJSON(t, `{"name":"Alice","qty":3,"active":true,"note":null}`, Limits{})
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	got := valuesOf(fs)
	want := map[string]string{"name": "Alice", "qty": "3", "active": "true", "note": "null"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseJSONNested(t *testing.T) {
	fs, err := parseJSON(t, `{"user":{"id":1,"prefs":{"theme":"dark"}}}`, Limits{})
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	got := valuesOf(fs)
	if got["user.id"] != "1" {
		t.Errorf("user.id = %q, want 1", got["user.id"])
	}
	if got["user.prefs.theme"] != "dark" {
		t.Errorf("user.prefs.theme = %q, want dark", got["user.prefs.theme"])
	}
}

func TestParseJSONArrays(t *testing.T) {
	fs, err := parseJSON(t, `{"ids":[10,20,30],"rows":[{"sku":"A"},{"sku":"B"}]}`, Limits{})
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	got := valuesOf(fs)
	for k, v := range map[string]string{
		"ids[0]": "10", "ids[1]": "20", "ids[2]": "30",
		"rows[0].sku": "A", "rows[1].sku": "B",
	} {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

// TestParseJSONUnescapes is the correctness half of this package. A payload
// hidden behind \u escapes contains no angle bracket on the wire, and the
// origin's parser hands the application the decoded form.
func TestParseJSONUnescapes(t *testing.T) {
	tests := []struct{ name, src, want string }{
		{"unicode escape", `{"c":"<script>"}`, "<script>"},
		{"quote", `{"c":"say \"hi\""}`, `say "hi"`},
		{"backslash", `{"c":"a\\b"}`, `a\b`},
		{"solidus", `{"c":"a\/b"}`, "a/b"},
		{"newline", `{"c":"a\nb"}`, "a\nb"},
		{"tab", `{"c":"a\tb"}`, "a\tb"},
		{"mixed", `{"c":"<img src=x onerror=alert(1)>"}`,
			"<img src=x onerror=alert(1)>"},
		{"surrogate pair", `{"c":"😀"}`, "\U0001F600"},
		{"unpaired high surrogate", `{"c":"\ud83d"}`, "�"},
		{"unpaired low surrogate", `{"c":"\udc00"}`, "�"},
		{"escaped key", `{"<key":"v"}`, "v"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, err := parseJSON(t, tt.src, Limits{})
			if err != nil {
				t.Fatalf("ParseJSON(%q): %v", tt.src, err)
			}
			found := false
			for _, f := range fs {
				if f.kind != KindKey && f.value == tt.want {
					found = true
				}
			}
			if !found {
				t.Errorf("no value equal to %q; got %+v", tt.want, fs)
			}
		})
	}
}

// TestParseJSONEmitsKeys covers the other attacker-controlled surface: a
// payload in a member name would be invisible if only values were inspected.
func TestParseJSONEmitsKeys(t *testing.T) {
	fs, err := parseJSON(t, `{"<script>":"x"}`, Limits{})
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	found := false
	for _, f := range fs {
		if f.kind == KindKey && f.value == "<script>" {
			found = true
		}
	}
	if !found {
		t.Errorf("object key was not emitted; got %+v", fs)
	}
}

func TestParseJSONMalformed(t *testing.T) {
	// A malformed document is an error, never a partial result: half a parse
	// says nothing about the half that was not read.
	bad := []string{
		"", "{", "}", "[", "]", `{"a"}`, `{"a":}`, `{a:1}`, `{'a':1}`,
		`{"a":1,}`, `[1,]`, `{"a":1}{"b":2}`, `{"a":"unterminated`,
		`{"a":01}`, `{"a":.5}`, `{"a":1e}`, `{"a":tru}`, `{"a":"\x"}`,
		`{"a":"\u00"}`, `nul`, `{"a":1} trailing`,
	}
	for _, src := range bad {
		t.Run(src, func(t *testing.T) {
			if _, err := parseJSON(t, src, Limits{}); err == nil {
				t.Errorf("ParseJSON(%q) accepted malformed input", src)
			}
		})
	}
}

func TestParseJSONValidDocuments(t *testing.T) {
	good := []string{
		`{}`, `[]`, `1`, `"x"`, `true`, `false`, `null`, `-1.5e10`,
		`{"a":{}}`, `[[]]`, `{"a":[{"b":[1,2]}]}`,
		`  {  "a"  :  1  }  `, `{"a":"日本語"}`, `{"a":""}`,
	}
	for _, src := range good {
		t.Run(src, func(t *testing.T) {
			if _, err := parseJSON(t, src, Limits{}); err != nil {
				t.Errorf("ParseJSON(%q) rejected valid JSON: %v", src, err)
			}
		})
	}
}

func TestParseJSONLimits(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		deep := strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40)
		if _, err := parseJSON(t, deep, Limits{MaxDepth: 8}); err != ErrTooDeep {
			t.Errorf("err = %v, want ErrTooDeep", err)
		}
	})

	t.Run("field count", func(t *testing.T) {
		var b strings.Builder
		b.WriteByte('{')
		for i := range 100 {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"k%d":%d`, i, i)
		}
		b.WriteByte('}')
		if _, err := parseJSON(t, b.String(), Limits{MaxFields: 10}); err != ErrTooManyFields {
			t.Errorf("err = %v, want ErrTooManyFields", err)
		}
	})

	t.Run("value length", func(t *testing.T) {
		src := `{"a":"` + strings.Repeat("x", 1000) + `"}`
		if _, err := parseJSON(t, src, Limits{MaxValueLen: 100}); err != ErrTooLarge {
			t.Errorf("err = %v, want ErrTooLarge", err)
		}
	})

	t.Run("total size", func(t *testing.T) {
		src := `{"a":"` + strings.Repeat("x", 1000) + `"}`
		if _, err := parseJSON(t, src, Limits{MaxTotalSize: 100}); err != ErrTooLarge {
			t.Errorf("err = %v, want ErrTooLarge", err)
		}
	})
}

func TestParseForm(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want map[string]string
	}{
		{"simple", "a=1&b=2", map[string]string{"a": "1", "b": "2"}},
		{"plus as space", "q=hello+world", map[string]string{"q": "hello world"}},
		{"percent decode", "q=hello%20world", map[string]string{"q": "hello world"}},
		{"encoded name", "a%2Eb=1", map[string]string{"a.b": "1"}},
		{"empty value", "a=&b=2", map[string]string{"a": "", "b": "2"}},
		{"no equals", "debug&b=2", map[string]string{"debug": "", "b": "2"}},
		{"encoded payload", "c=%3Cscript%3E", map[string]string{"c": "<script>"}},
		{"email", "e=user%40example.com", map[string]string{"e": "user@example.com"}},
		{"repeated key", "a=1&a=2", map[string]string{"a": "2"}},
		{"trailing amp", "a=1&", map[string]string{"a": "1"}},
		{"leading amp", "&a=1", map[string]string{"a": "1"}},
		{"malformed escape kept", "a=%zz", map[string]string{"a": "%zz"}},
		{"truncated escape kept", "a=%4", map[string]string{"a": "%4"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, err := parseForm(t, tt.src, Limits{})
			if err != nil {
				t.Fatalf("ParseForm: %v", err)
			}
			got := valuesOf(fs)
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestDetectContent(t *testing.T) {
	tests := []struct {
		ct   string
		want ContentKind
	}{
		{"application/json", ContentJSON},
		{"application/json; charset=utf-8", ContentJSON},
		{"APPLICATION/JSON", ContentJSON},
		{" application/json ", ContentJSON},
		{"text/json", ContentJSON},
		{"application/vnd.api+json", ContentJSON},
		{"application/problem+json", ContentJSON},
		{"application/x-www-form-urlencoded", ContentForm},
		{"application/x-www-form-urlencoded; charset=utf-8", ContentForm},
		{"multipart/form-data; boundary=x", ContentUnknown},
		{"text/plain", ContentUnknown},
		{"application/grpc", ContentUnknown},
		{"", ContentUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.ct, func(t *testing.T) {
			if got := DetectContent(tt.ct); got != tt.want {
				t.Errorf("DetectContent(%q) = %v, want %v", tt.ct, got, tt.want)
			}
		})
	}
}

func TestEmitCanStopEarly(t *testing.T) {
	var p Parser
	p.Reset(Limits{})

	n := 0
	err := p.ParseJSON([]byte(`{"a":1,"b":2,"c":3}`), func([]byte, []byte, Kind) bool {
		n++
		return n < 2
	})
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	if n != 2 {
		t.Errorf("emitted %d fields after asking to stop at 2", n)
	}
}

func TestParserIsReusable(t *testing.T) {
	var p Parser

	// Reuse across bodies must not leak path or scratch state.
	for range 3 {
		for _, src := range []string{
			`{"a":{"b":"1"}}`, `{"x":"2"}`, `[1,2,3]`, `{}`,
		} {
			p.Reset(Limits{})
			var names []string
			err := p.ParseJSON([]byte(src), func(name, _ []byte, k Kind) bool {
				if k != KindKey {
					names = append(names, string(name))
				}
				return true
			})
			if err != nil {
				t.Fatalf("ParseJSON(%q): %v", src, err)
			}
			for _, n := range names {
				if strings.Contains(n, "..") || strings.HasPrefix(n, ".") {
					t.Errorf("%q produced a malformed path %q — state leaked", src, n)
				}
			}
		}
	}
}

// FuzzParseJSON checks gwaf's parser against the standard library.
//
// Agreement on *acceptance* is the property that matters: if gwaf rejects a
// document the origin will parse, the request is blocked for the wrong reason;
// if gwaf accepts one the origin rejects, gwaf inspected something that will
// never exist. Neither is safe to guess at.
func FuzzParseJSON(f *testing.F) {
	seeds := []string{
		`{}`, `[]`, `{"a":1}`, `{"a":"<"}`, `[1,[2,[3]]]`,
		`{"a":{"b":{"c":"d"}}}`, `"x"`, `1`, `true`, `null`,
		`{"a":"😀"}`, `{"a":"\ud83d"}`, `{`, `}`, ``,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 16384 {
			t.Skip()
		}

		var p Parser
		p.Reset(Limits{MaxDepth: 64, MaxFields: 4096, MaxValueLen: 1 << 20,
			MaxTotalSize: 1 << 20})

		fields := 0
		err := p.ParseJSON([]byte(src), func(name, value []byte, k Kind) bool {
			fields++
			// Buffers must stay within their declared ceilings.
			if len(name) > 4096 {
				t.Fatalf("path grew to %d bytes", len(name))
			}
			return true
		})

		stdValid := json.Valid([]byte(src))

		// gwaf must not accept what the origin will reject.
		if err == nil && !stdValid {
			t.Fatalf("accepted %q which encoding/json rejects", src)
		}
		// gwaf may reject valid JSON only by hitting a declared limit, never by
		// disagreeing about the grammar.
		if err != nil && stdValid {
			switch err {
			case ErrTooDeep, ErrTooManyFields, ErrTooLarge:
			default:
				t.Fatalf("rejected valid JSON %q with %v", src, err)
			}
		}
	})
}

// FuzzParseForm asserts the parser never panics and always terminates.
func FuzzParseForm(f *testing.F) {
	for _, s := range []string{
		"", "a=1", "a=1&b=2", "a", "=", "&&&", "a=%", "a=%zz", "+", "%00=%00",
		strings.Repeat("a=1&", 100),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 16384 {
			t.Skip()
		}
		var p Parser
		p.Reset(Limits{})
		_ = p.ParseForm([]byte(src), func(name, value []byte, _ Kind) bool {
			if len(name) > 65536 || len(value) > 1<<20 {
				t.Fatal("buffer exceeded its ceiling")
			}
			return true
		})
	})
}

func BenchmarkParseJSON(b *testing.B) {
	src := []byte(`{"items":[{"id":1,"sku":"SKU-000001","qty":3,"note":"standard delivery"},` +
		`{"id":2,"sku":"SKU-000002","qty":1,"note":"express"}],"total":4}`)
	var p Parser
	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		p.Reset(Limits{})
		p.ParseJSON(src, func([]byte, []byte, Kind) bool { return true })
	}
}

func BenchmarkParseJSONEscaped(b *testing.B) {
	src := []byte(`{"c":"<script>alert(1)</script>","d":"plain"}`)
	var p Parser
	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		p.Reset(Limits{})
		p.ParseJSON(src, func([]byte, []byte, Kind) bool { return true })
	}
}

func BenchmarkParseForm(b *testing.B) {
	src := []byte("email=user%40example.com&subject=Hello+there&msg=Thanks+for+everything")
	var p Parser
	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		p.Reset(Limits{})
		p.ParseForm(src, func([]byte, []byte, Kind) bool { return true })
	}
}
