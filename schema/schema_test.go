// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package schema

import (
	"strings"
	"testing"
)

func TestValidateInteger(t *testing.T) {
	f := Field{Kind: KindInteger}

	valid := []string{"0", "1", "12345", "-1", "+1", "-0", "007"}
	for _, v := range valid {
		if got := Validate(f, []byte(v)); got != ViolationNone {
			t.Errorf("Validate(%q) = %v, want none", v, got)
		}
	}

	// Anything admitted here would undermine the Inert claim, so the invalid
	// list is deliberately aggressive.
	invalid := []string{
		"", " ", "1 ", " 1", "1.0", "1e5", "abc", "1a", "a1",
		"1 UNION SELECT", "<script>", "../", "0x1f", "+", "-", "１２３",
		"1,000", "1_000", "١٢٣", "1\n", "1\x00",
	}
	for _, v := range invalid {
		if got := Validate(f, []byte(v)); got == ViolationNone {
			t.Errorf("Validate(%q) accepted a non-integer", v)
		}
	}
}

func TestValidateNumber(t *testing.T) {
	f := Field{Kind: KindNumber}

	valid := []string{"0", "1.5", "-1.5", "+2", "1e5", "1E5", "1.5e-3", "0.1", ".5", "5."}
	for _, v := range valid {
		if got := Validate(f, []byte(v)); got != ViolationNone {
			t.Errorf("Validate(%q) = %v, want none", v, got)
		}
	}

	invalid := []string{"", ".", "e5", "1e", "1e+", "1.2.3", "abc", "1 2", "NaN", "Infinity"}
	for _, v := range invalid {
		if got := Validate(f, []byte(v)); got == ViolationNone {
			t.Errorf("Validate(%q) accepted a non-number", v)
		}
	}
}

func TestValidateEnum(t *testing.T) {
	f := Field{Kind: KindEnum, Enum: []string{"pending", "shipped"}}

	if got := Validate(f, []byte("pending")); got != ViolationNone {
		t.Errorf("Validate(pending) = %v", got)
	}
	for _, v := range []string{"Pending", "PENDING", "delivered", "", "pending "} {
		if got := Validate(f, []byte(v)); got != ViolationEnum {
			t.Errorf("Validate(%q) = %v, want ViolationEnum", v, got)
		}
	}
}

func TestValidateUUID(t *testing.T) {
	f := Field{Kind: KindString, Format: FormatUUID}

	valid := []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"00000000-0000-0000-0000-000000000000",
		"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
	}
	for _, v := range valid {
		if got := Validate(f, []byte(v)); got != ViolationNone {
			t.Errorf("Validate(%q) = %v, want none", v, got)
		}
	}

	invalid := []string{
		"", "550e8400", "550e8400-e29b-41d4-a716-44665544000",
		"550e8400-e29b-41d4-a716-4466554400000",
		"550e8400+e29b-41d4-a716-446655440000",
		"550e8400-e29b-41d4-a716-44665544000g",
		"550e8400-e29b-41d4-a716-446655440000 ",
	}
	for _, v := range invalid {
		if got := Validate(f, []byte(v)); got == ViolationNone {
			t.Errorf("Validate(%q) accepted a malformed UUID", v)
		}
	}
}

func TestValidateDateTime(t *testing.T) {
	f := Field{Kind: KindString, Format: FormatDateTime}

	valid := []string{
		"2026-08-05T07:38:00Z",
		"2026-08-05t07:38:00z",
		"2026-08-05T07:38:00+07:00",
		"2026-08-05T07:38:00-05:00",
		"2026-08-05T07:38:00.123Z",
		"2026-08-05T07:38:00.123456789Z",
	}
	for _, v := range valid {
		if got := Validate(f, []byte(v)); got != ViolationNone {
			t.Errorf("Validate(%q) = %v, want none", v, got)
		}
	}

	invalid := []string{
		"", "2026-08-05", "yesterday", "2026-08-05T07:38:00",
		// The space separator is legal RFC 3339 but is rejected on purpose: a
		// date-time field is declared inert, and a space is a byte the attack
		// vocabulary needs. See isDateTime.
		"2026-08-05 07:38:00Z",
		"2026-08-05T07:38Z", "2026/08/05T07:38:00Z", "2026-08-05T07:38:00.Z",
		"2026-08-05T07:38:00+7:00", "2026-08-05T07:38:00Z ",
	}
	for _, v := range invalid {
		if got := Validate(f, []byte(v)); got == ViolationNone {
			t.Errorf("Validate(%q) accepted a malformed date-time", v)
		}
	}
}

func TestValidateEmail(t *testing.T) {
	f := Field{Kind: KindString, Format: FormatEmail}

	valid := []string{"user@example.com", "first.last+tag@sub.example.co.uk", "a@b.co"}
	for _, v := range valid {
		if got := Validate(f, []byte(v)); got != ViolationNone {
			t.Errorf("Validate(%q) = %v, want none", v, got)
		}
	}

	// The point of the format check is to bound the character set, so payload
	// characters must be rejected even in inputs that resemble addresses.
	invalid := []string{
		"", "user", "@example.com", "user@", "user@@example.com",
		"user name@example.com", "user@example", `"x"@example.com`,
		"user<script>@example.com", "user';--@example.com", "user@exam ple.com",
	}
	for _, v := range invalid {
		if got := Validate(f, []byte(v)); got == ViolationNone {
			t.Errorf("Validate(%q) accepted a malformed email", v)
		}
	}
}

func TestValidateIPv4(t *testing.T) {
	f := Field{Kind: KindString, Format: FormatIPv4}

	for _, v := range []string{"0.0.0.0", "192.168.1.1", "255.255.255.255"} {
		if got := Validate(f, []byte(v)); got != ViolationNone {
			t.Errorf("Validate(%q) = %v, want none", v, got)
		}
	}
	for _, v := range []string{
		"", "256.1.1.1", "1.1.1", "1.1.1.1.1", "1.1.1.", "a.b.c.d",
		"1.1.1.1 ", "0001.1.1.1", "::1",
	} {
		if got := Validate(f, []byte(v)); got == ViolationNone {
			t.Errorf("Validate(%q) accepted a malformed IPv4", v)
		}
	}
}

func TestValidateMaxLength(t *testing.T) {
	f := Field{Kind: KindString, MaxLength: 10}

	if got := Validate(f, []byte("short")); got != ViolationNone {
		t.Errorf("Validate(short) = %v", got)
	}
	if got := Validate(f, []byte(strings.Repeat("a", 11))); got != ViolationLength {
		t.Errorf("= %v, want ViolationLength", got)
	}
}

// TestUnknownKindValidatesEverything guards the safety default: a field nobody
// described must not be treated as constrained.
func TestUnknownKindValidatesEverything(t *testing.T) {
	f := Field{Kind: KindUnknown}
	for _, v := range []string{"", "anything", "<script>", "1 UNION SELECT"} {
		if got := Validate(f, []byte(v)); got != ViolationNone {
			t.Errorf("Validate(%q) on an unspecified field = %v", v, got)
		}
	}
	if f.Inert() {
		t.Error("an unspecified field claims to be inert")
	}
}

// TestInertClaim is the safety property the whole optimization rests on: a
// field is inert only where validation constrains the character set enough that
// no payload can survive it.
func TestInertClaim(t *testing.T) {
	inert := []Field{
		{Kind: KindInteger},
		{Kind: KindNumber},
		{Kind: KindBoolean},
		{Kind: KindEnum, Enum: []string{"a", "b"}},
		{Kind: KindString, Format: FormatUUID},
		{Kind: KindString, Format: FormatDateTime},
		{Kind: KindString, Format: FormatDate},
		{Kind: KindString, Format: FormatHexadecimal},
		{Kind: KindString, Format: FormatIPv4},
	}
	for _, f := range inert {
		if !f.Inert() {
			t.Errorf("%s/%s should be inert", f.Kind, f.Format)
		}
	}

	notInert := []Field{
		{Kind: KindUnknown},
		{Kind: KindString},
		{Kind: KindString, Format: FormatEmail},
		// Base64 admits '+' and '/', and the decoded content is unknown.
		{Kind: KindString, Format: FormatBase64},
		{Kind: KindArray},
		{Kind: KindObject},
		{Kind: KindEnum}, // an enum with no values constrains nothing
	}
	for _, f := range notInert {
		if f.Inert() {
			t.Errorf("%s/%s must not be inert", f.Kind, f.Format)
		}
	}
}

// TestInertFieldsRejectPayloads is the claim stated as a test rather than an
// argument: every payload in the evasion vocabulary must fail validation for
// every field type declared inert. If one gets through, skipping rules for that
// field is a bypass.
func TestInertFieldsRejectPayloads(t *testing.T) {
	payloads := []string{
		"1 UNION SELECT password FROM users",
		"1' OR 1=1--",
		"<script>alert(1)</script>",
		"../../etc/passwd",
		"..%2f..%2fetc%2fpasswd",
		"%252e%252e%252f",
		"+ADw-script+AD4-",
		"&lt;script&gt;",
		"; cat /etc/passwd",
		"php://filter/read=convert.base64-encode",
		"%c0%ae%c0%ae/",
		"file%00.jpg",
		`..\..\windows\system32`,
		"${jndi:ldap://x/a}",
		"{{7*7}}",
		"$(whoami)",
	}

	inertFields := []Field{
		{Kind: KindInteger},
		{Kind: KindNumber},
		{Kind: KindBoolean},
		{Kind: KindEnum, Enum: []string{"pending", "shipped"}},
		{Kind: KindString, Format: FormatUUID},
		{Kind: KindString, Format: FormatDateTime},
		{Kind: KindString, Format: FormatDate},
		{Kind: KindString, Format: FormatHexadecimal},
		{Kind: KindString, Format: FormatIPv4},
	}

	for _, f := range inertFields {
		if !f.Inert() {
			continue
		}
		for _, p := range payloads {
			if Validate(f, []byte(p)) == ViolationNone {
				t.Errorf("field %s/%s accepted payload %q while claiming to be inert — "+
					"skipping rules for it would be a bypass", f.Kind, f.Format, p)
			}
		}
	}
}

func TestLookup(t *testing.T) {
	s, err := New(
		Operation{Method: "GET", Path: "/api/orders"},
		Operation{Method: "POST", Path: "/api/orders"},
		Operation{Method: "GET", Path: "/api/orders/{id}"},
		Operation{Method: "GET", Path: "/files/*"},
		Operation{Path: "/any-method"},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tests := []struct {
		method, path string
		want         bool
		wantPath     string
	}{
		{"GET", "/api/orders", true, "/api/orders"},
		{"POST", "/api/orders", true, "/api/orders"},
		{"GET", "/api/orders/123", true, "/api/orders/{id}"},
		{"GET", "/api/orders/abc-def", true, "/api/orders/{id}"},
		{"GET", "/files/a/b/c", true, "/files/*"},
		{"DELETE", "/any-method", true, "/any-method"},
		{"GET", "/api/orders/123/items", false, ""},
		{"GET", "/unknown", false, ""},
		{"DELETE", "/api/orders", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			op, ok := s.Lookup(tt.method, tt.path)
			if ok != tt.want {
				t.Fatalf("Lookup = %v, want %v", ok, tt.want)
			}
			if ok && op.Path != tt.wantPath {
				t.Errorf("matched %q, want %q", op.Path, tt.wantPath)
			}
		})
	}
}

func TestNewRejectsInvalidSchema(t *testing.T) {
	tests := []struct {
		name string
		op   Operation
	}{
		{"no path", Operation{Method: "GET"}},
		{"enum without values", Operation{Path: "/x",
			Query: []Field{{Name: "a", Kind: KindEnum}}}},
		{"format on a non-string", Operation{Path: "/x",
			Query: []Field{{Name: "a", Kind: KindInteger, Format: FormatUUID}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.op); err == nil {
				t.Error("New accepted an invalid operation")
			}
		})
	}
}

func TestFieldFor(t *testing.T) {
	fields := []Field{
		{Name: "id", Kind: KindInteger},
		{Name: "", Kind: KindString, MaxLength: 100}, // fallback
	}

	if f, ok := FieldFor(fields, "id"); !ok || f.Kind != KindInteger {
		t.Errorf("named lookup failed: %+v %v", f, ok)
	}
	if f, ok := FieldFor(fields, "other"); !ok || f.MaxLength != 100 {
		t.Errorf("fallback lookup failed: %+v %v", f, ok)
	}
	if _, ok := FieldFor([]Field{{Name: "id"}}, "other"); ok {
		t.Error("lookup succeeded with no fallback declared")
	}
}

func TestParseFormat(t *testing.T) {
	for s, want := range map[string]Format{
		"uuid": FormatUUID, "UUID": FormatUUID, "date-time": FormatDateTime,
		"email": FormatEmail, "byte": FormatBase64, "": FormatNone,
	} {
		got, ok := ParseFormat(s)
		if !ok || got != want {
			t.Errorf("ParseFormat(%q) = %v,%v want %v,true", s, got, ok, want)
		}
	}
	if _, ok := ParseFormat("no-such-format"); ok {
		t.Error("ParseFormat accepted an unknown name")
	}
}

// FuzzValidateInert is the critical invariant: if validation passes for a field
// that claims to be inert, the value must contain only characters from a set
// that cannot express an attack. A counterexample here is a bypass.
func FuzzValidateInert(f *testing.F) {
	seeds := []string{
		"", "1", "-1", "1.5", "true", "550e8400-e29b-41d4-a716-446655440000",
		"2026-08-05T07:38:00Z", "deadbeef", "192.168.1.1", "pending",
		"<script>", "1 UNION SELECT", "../", "%00", "+ADw-",
	}
	for _, s := range seeds {
		for k := 0; k < 9; k++ {
			f.Add(s, k)
		}
	}

	fields := []Field{
		{Kind: KindInteger},
		{Kind: KindNumber},
		{Kind: KindBoolean},
		{Kind: KindEnum, Enum: []string{"pending", "shipped"}},
		{Kind: KindString, Format: FormatUUID},
		{Kind: KindString, Format: FormatDateTime},
		{Kind: KindString, Format: FormatDate},
		{Kind: KindString, Format: FormatHexadecimal},
		{Kind: KindString, Format: FormatIPv4},
	}

	// Bytes that no inert field may ever admit. Every injection technique needs
	// at least one of them.
	const forbidden = "<>'\"`;()[]{}\\/&|$*?!#%@ \t\n\r\x00"

	f.Fuzz(func(t *testing.T, value string, idx int) {
		if len(value) > 4096 {
			t.Skip()
		}
		fld := fields[((idx%len(fields))+len(fields))%len(fields)]
		if !fld.Inert() {
			t.Skip()
		}
		if Validate(fld, []byte(value)) != ViolationNone {
			return
		}

		// An enum value is whatever the schema author wrote, so it is exempt:
		// if their own enum contains an attack, the schema is the problem.
		if fld.Kind == KindEnum {
			return
		}

		for i := 0; i < len(value); i++ {
			if strings.IndexByte(forbidden, value[i]) >= 0 {
				t.Fatalf("field %s/%s validated %q, which contains %q — "+
					"the Inert claim is false and skipping rules for this field "+
					"would be a bypass", fld.Kind, fld.Format, value, value[i])
			}
		}
	})
}

func BenchmarkValidateInteger(b *testing.B) {
	f := Field{Kind: KindInteger}
	v := []byte("1234567890")
	b.ReportAllocs()
	for b.Loop() {
		Validate(f, v)
	}
}

func BenchmarkValidateUUID(b *testing.B) {
	f := Field{Kind: KindString, Format: FormatUUID}
	v := []byte("550e8400-e29b-41d4-a716-446655440000")
	b.ReportAllocs()
	for b.Loop() {
		Validate(f, v)
	}
}

func BenchmarkLookupLiteral(b *testing.B) {
	s, _ := New(Operation{Method: "GET", Path: "/api/v1/orders"})
	b.ReportAllocs()
	for b.Loop() {
		s.Lookup("GET", "/api/v1/orders")
	}
}

func BenchmarkLookupTemplated(b *testing.B) {
	s, _ := New(Operation{Method: "GET", Path: "/api/v1/orders/{id}/items/{item}"})
	b.ReportAllocs()
	for b.Loop() {
		s.Lookup("GET", "/api/v1/orders/123/items/456")
	}
}
