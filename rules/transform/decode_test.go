// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package transform

import "testing"

func TestCSSDecode(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// The evasion this exists for: a browser reads both as "expression".
		{`\65 xpression`, "expression"},
		{`\000065xpression`, "expression"},
		{`\65xpression`, "\x65xpression"[0:1] + "xpression"},

		// One whitespace after the digits is the delimiter and is eaten; a
		// second is data.
		{`\65  x`, "e x"},
		{`\6 5`, "\x065"},

		// Non-hex escapes drop the backslash and keep the character, which is
		// how "\<" survives a filter looking for "<".
		{`\<script\>`, "<script>"},
		{`\\`, `\`},

		// Line continuations disappear entirely, both spellings.
		{"al\\\nert", "alert"},
		{"al\\\r\nert", "alert"},

		// Six digits is the maximum; a seventh is literal text.
		{`\0000651`, "e1"},

		// Nothing to do.
		{"expression", "expression"},
		{"", ""},

		// Truncated input must not read past the end.
		{`\`, `\`},
	} {
		if got, _ := apply(cssDecode{}, tc.in); got != tc.want {
			t.Errorf("CSSDecode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCSSDecodeUnchangedIsReported: the engine reuses the original bytes when a
// transform reports no change, so claiming a change that did not happen costs an
// allocation on every benign request.
func TestCSSDecodeUnchangedIsReported(t *testing.T) {
	src := []byte("nothing to decode here")
	out, changed := CSSDecode.Apply(make([]byte, 0, 64), src)
	if changed {
		t.Error("reported a change on input with no backslash")
	}
	if &out[0] != &src[0] {
		t.Error("did not return the original slice on the unchanged path")
	}
}

func TestCmdLine(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// Windows caret escaping, the classic cmd.exe evasion.
		{"c^m^d", "cmd"},
		{`"c"md`, "cmd"},
		{`c\md`, "cmd"},

		// Space inserted before a path or a call to break a literal.
		{"cat  /etc/passwd", "cat/etc/passwd"},
		{"system (1)", "system(1)"},

		// Separators become spaces, runs collapse, case folds.
		{"a,b;c", "a b c"},
		{"LS\t-LA", "ls -la"},
		{"  ls   -la  ", "ls -la"},

		{"", ""},
		{"already fine", "already fine"},
	} {
		if got, _ := apply(cmdLine{}, tc.in); got != tc.want {
			t.Errorf("CmdLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestReplaceComments(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// A space, not nothing: deleting the comment would weld the halves into
		// a keyword the database never sees.
		{"SEL/**/ECT", "SEL ECT"},
		{"UNION/*x*/SELECT", "UNION SELECT"},

		// Unterminated comments run to the end, as the databases that accept
		// them do.
		{"SELECT/*rest", "SELECT "},

		// Adjacent whitespace is left alone: one space per comment, as
		// ModSecurity does. Rules that care pair this with compressWhitespace.
		{"a /**/ b", "a   b"},

		{"no comments", "no comments"},
		{"", ""},
		{"/", "/"},
		{"/*", " "},
	} {
		if got, _ := apply(replaceComments{}, tc.in); got != tc.want {
			t.Errorf("ReplaceComments(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRemoveCommentsChar(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"UNION--SELECT", "UNIONSELECT"},
		{"UNION#SELECT", "UNIONSELECT"},
		{"a/*b*/c", "abc"},
		{"-", "-"},
		{"nothing", "nothing"},
		{"", ""},
	} {
		if got, _ := apply(removeCommentsChar{}, tc.in); got != tc.want {
			t.Errorf("RemoveCommentsChar(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestBase64Decode(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"YWxlcnQoMSk=", "alert(1)"},
		{"PHNjcmlwdD4=", "<script>"},

		// Lenient by design: a decoder that gives up on one stray byte is an
		// evasion, because the application's decoder usually does not.
		{"YWxl cnQo MSk=", "alert(1)"},
		{"YWxlcnQoMSk", "alert(1)"},

		// A lone character carries no whole byte.
		{"Q", ""},
		{"", ""},
	} {
		if got, _ := apply(base64Decode{}, tc.in); got != tc.want {
			t.Errorf("Base64Decode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestNewTransformsNeverExceedTheirBound is the property that matters for the
// hot path: the engine sizes the arena from MaxOutputLen, so exceeding it turns
// into a per-request allocation. Covered for every transform by
// TestMaxOutputLenRespected; this pins the decoders against inputs shaped to
// grow, which is where a decoder gets it wrong.
func TestNewTransformsNeverExceedTheirBound(t *testing.T) {
	inputs := []string{
		`\`, `\6`, `\65`, `\000065`, `\\\\\\`, "a\\\r", "a\\\r\n",
		"/*", "*/", "/*/", "--", "###", "-", "/**//**/",
		"^^^^", `""""`, "'''", ",,,", ";;;", "   ", "\t\t\t",
		"Q", "QQ", "QQQ", "QQQQ", "====", "++++", "////",
	}
	for _, tr := range All {
		for _, in := range inputs {
			bound := tr.MaxOutputLen(len(in))
			dst := make([]byte, 0, bound)
			out, changed := tr.Apply(dst, []byte(in))
			if len(out) > bound {
				t.Errorf("%s(%q): %d bytes exceeds bound %d", tr.Name(), in, len(out), bound)
			}
			if changed && cap(out) > bound {
				t.Errorf("%s(%q): reallocated to cap %d over bound %d",
					tr.Name(), in, cap(out), bound)
			}
		}
	}
}
