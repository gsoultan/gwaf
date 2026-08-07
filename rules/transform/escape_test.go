// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package transform_test

import (
	"github.com/gsoultan/gwaf/rules/transform"
	"testing"
)

func TestEscapeDecode(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`\x41\x42`, "AB"},
		{`A`, "A"},
		{`c\at`, "cat"},
		{`a\nb`, "a\nb"},
		{`\101`, "A"},
		{"plain text", "plain text"},
		{`\x`, `\x`},
		{`SELECT\x20*`, "SELECT *"},
	} {
		got, _ := transform.EscapeDecode.Apply(nil, []byte(c.in))
		if string(got) != c.want {
			t.Errorf("EscapeDecode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
