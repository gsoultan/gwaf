// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package transform

import "testing"

// TestHexEscapeDecodePreservesBackslashSeparators is the reason this transform
// exists separately from EscapeDecode. The evasion corpus found that
// "..\u002f..\u002fetc\u002fpasswd" reached no traversal rule, because the path
// chain does no escape decoding at all -- and it could not adopt EscapeDecode,
// which drops the backslash from "\." and would flatten every Windows path.
func TestHexEscapeDecodePreservesBackslashSeparators(t *testing.T) {
	buf := make([]byte, 0, 256)
	apply := func(s string) string {
		out, _ := HexEscapeDecode.Apply(buf, []byte(s))
		return string(out)
	}

	t.Run("numeric escapes decode", func(t *testing.T) {
		for _, tc := range []struct{ in, want string }{
			{`..\u002f..\u002fetc\u002fpasswd`, "../../etc/passwd"},
			{`..\x2f..\x2fetc\x2fpasswd`, "../../etc/passwd"},
			{`\u002fetc\u002fpasswd`, "/etc/passwd"},
			{`\x2fetc\x2fpasswd`, "/etc/passwd"},
			{`\x3cscript\x3e`, "<script>"},
			{`\u003cscript\u003e`, "<script>"},
		} {
			if got := apply(tc.in); got != tc.want {
				t.Errorf("Apply(%q) = %q, want %q", tc.in, got, tc.want)
			}
		}
	})

	t.Run("other escapes are preserved verbatim", func(t *testing.T) {
		// The whole point: a Windows path keeps its separators. EscapeDecode
		// would return "....windowswin.ini" for the first of these.
		for _, in := range []string{
			`..\..\windows\win.ini`,
			`c:\windows\system32`,
			`..\..\..\boot.ini`,
			`a\qb`,
			`\xZZ`,
			`trailing\`,
			`\u00`,
		} {
			if got := apply(in); got != in {
				t.Errorf("Apply(%q) = %q, want it unchanged", in, got)
			}
		}
	})
}
