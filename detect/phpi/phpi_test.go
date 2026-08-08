// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package phpi

import (
	"strings"
	"testing"
)

func TestPHPInjectionIsDetected(t *testing.T) {
	d := New()
	for _, tc := range []struct {
		name, payload string
		want          Signal
	}{
		{"open tag", "<?php system($_GET['c']); ?>", SignalOpenTag},
		{"echo tag", "<?= `id` ?>", SignalOpenTag},

		{"filter wrapper", "php://filter/read=convert.base64-encode/resource=index.php", SignalStreamWrapper},
		{"input wrapper", "php://input", SignalStreamWrapper},
		{"expect wrapper", "expect://id", SignalStreamWrapper},
		{"data wrapper", "data://text/plain;base64,PD9waHAgc3lzdGVtKCk7", SignalStreamWrapper},
		{"phar wrapper", "phar://uploads/x.jpg/payload", SignalStreamWrapper},

		// The attack no function list can cover: the payload never names one.
		{"variable function", "$_GET[0]($_GET[1])", SignalVariableFunction},
		{"variable variable", "$$var", SignalVariableFunction},

		{"config directive", "allow_url_include=1", SignalConfigDirective},

		// A short tag still scores through what it does, not the tag.
		{"short tag with call", "<? system('id'); ?>", SignalDangerCall},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := d.Analyze([]byte(tc.payload))
			if !v.Detected() {
				t.Errorf("missed (score %d, signals %v)", v.Score, v.Signals)
			}
			if v.Signals&tc.want == 0 {
				t.Errorf("signals %v, expected %v among them", v.Signals, tc.want)
			}
		})
	}
}

// TestFunctionNamesInProseArePassed is the reason this package reads structure
// instead of carrying CRS's three function lists.
//
// Those lists are several hundred names and sit behind paranoia levels, because
// "array_diff", "filemtime" and "date_add" are words a support ticket or a
// documentation search contains all day. A name scores here only in call
// position, and even then only as corroboration.
func TestFunctionNamesInProseArePassed(t *testing.T) {
	d := New()
	for _, benign := range []string{
		"we should replace array_diff with a set",
		"the payment system failed twice today",
		"filemtime returns the modification time",
		"date_add adds an interval to a date",
		"our price is $100 for the system upgrade",
		"see the include guide for details",
		"the file is data/report.csv",
		"$name and $total are template fields",
		"exec summary attached",
		"never eval() untrusted input in production",
		"a <? b and c ?> d are comparisons",
		"the phar format is a PHP archive",
	} {
		if v := d.Analyze([]byte(benign)); v.Detected() {
			t.Errorf("false positive on %q (score %d, signals %v)", benign, v.Score, v.Signals)
		}
	}
}

// TestDangerCallCorroborates keeps the call signal below the threshold on its
// own. "never eval() untrusted input in production" is advice, and a security
// blog is full of sentences like it — the call has to arrive with PHP structure
// around it before it means anything.
func TestDangerCallCorroborates(t *testing.T) {
	d := New()
	if v := d.Analyze([]byte("eval()")); v.Detected() {
		t.Errorf("a bare call fired alone: score %d", v.Score)
	}
	if v := d.Analyze([]byte("<?php eval($_POST['x']); ?>")); !v.Detected() {
		t.Errorf("a call inside PHP structure did not fire: score %d", v.Score)
	}
}

func TestBounds(t *testing.T) {
	d := New()
	if d.Analyze(nil).Detected() {
		t.Error("nil detected")
	}
	for _, s := range []string{"<", "<?", "$", "$$", "://", "?>", "(", "$("} {
		d.Analyze([]byte(s)) // must not panic
	}
	d.Analyze([]byte(strings.Repeat("$", maxScan*2)))
}

// FuzzLiteralsAreExhaustive enforces the claim the prefilter depends on: any
// value the detector reports must contain a declared literal, or the value would
// be filtered out and the rule would silently never fire.
func FuzzLiteralsAreExhaustive(f *testing.F) {
	for _, s := range []string{
		"<?php", "<?=", "php://input", "$_GET[0]($_GET[1])", "$$x",
		"system(", "allow_url_include", "?>", "", "$", "<?", "://",
		"expect://id", "assert (", "data://",
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
			if indexFold([]byte(value), l) >= 0 {
				return
			}
		}
		t.Fatalf("detected %q but no literal covers it: the prefilter would drop it", value)
	})
}

func BenchmarkAnalyzeBenign(b *testing.B) {
	d := New()
	v := []byte("we should replace array_diff with a set")
	b.ReportAllocs()
	for b.Loop() {
		d.Analyze(v)
	}
}

// TestCodeSamplesArePassedButStatementsAreNot is the false positive a WordPress
// replay found, next to the miss that shares a cause.
//
// A comment field carrying "<?php echo $name; ?>" is somebody explaining PHP,
// and it blocked because an open tag alone reached the threshold. A body
// carrying "system('X');" is a webshell being installed, and it passed because
// a danger call was priced as corroboration only. Writing "<?php" is how PHP is
// written; calling system() with an argument and terminating the statement is
// not something prose does.
func TestCodeSamplesArePassedButStatementsAreNot(t *testing.T) {
	d := New()

	// Code samples carrying a PHP *open tag* are not here: an open tag convicts
	// alone and is meant to, because a PHP payload is very often just a tag and
	// a body. Blocking "<?php echo $name; ?>" in a comment field is a real cost,
	// and an embedder whose users write PHP in post bodies scopes an exception
	// for those fields. What must keep passing is prose that merely *names* a
	// function, which is what a security blog writes constantly.
	t.Run("prose naming functions passes", func(t *testing.T) {
		for _, benign := range []string{
			"never eval() untrusted input in production",
			"the system() function is dangerous, avoid it",
			"call exec() only with escaped arguments",
		} {
			if v := d.Analyze([]byte(benign)); v.Detected() {
				t.Errorf("false positive on %q (score %d, signals %v)", benign, v.Score, v.Signals)
			}
		}
	})

	t.Run("statements fire", func(t *testing.T) {
		for _, attack := range []string{
			"system('X');",
			"blowfish=1&blowf=system('X');",
			"passthru('id');",
			"shell_exec('cat /etc/passwd');",
			"<?php system($_GET['c']); ?>",
			"<?php eval($_POST['x']); ?>",
		} {
			if v := d.Analyze([]byte(attack)); !v.Detected() {
				t.Errorf("missed %q (score %d, signals %v)", attack, v.Score, v.Signals)
			}
		}
	})
}
