// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package ssti

import (
	"strings"
	"testing"
)

func TestTemplateInjectionIsDetected(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    Signal
	}{
		// Jinja / Twig: the escape always walks the object graph.
		{"jinja class traversal", "{{''.__class__.__mro__[1].__subclasses__()}}", SignalPythonInternals},
		{"jinja globals", "{{request.application.__globals__}}", SignalPythonInternals},
		{"jinja builtins import", "{{self.__init__.__globals__.__builtins__.__import__('os')}}", SignalPythonInternals},
		{"jinja config items", "{{config.items()}}", SignalAppObject},
		{"jinja request attr", "{{request.args}}", SignalAppObject},
		{"jinja statement", "{% for x in ''.__class__.__mro__ %}", SignalPythonInternals},
		{"jinja lipsum", "{{lipsum.__globals__['os'].popen('id').read()}}", SignalPythonInternals},

		// Spring EL and FreeMarker reach the class loader.
		{"spring runtime", `${T(java.lang.Runtime).getRuntime().exec("id")}`, SignalJVMClassAccess},
		{"spring processbuilder", "${T(java.lang.ProcessBuilder)}", SignalJVMClassAccess},
		{"spring classloader", "${''.class.classLoader}", SignalJVMClassAccess},
		{"freemarker execute", `<#assign x="freemarker.template.utility.Execute"?new()>`, SignalJVMClassAccess},
		{"jsp el runtime", "${pageContext.request.getClass().forName('x')}", SignalJVMClassAccess},

		// Ruby.
		{"erb backtick", "<%= `id` %>", SignalRubyExecution},
		{"erb system", "<%= system('id') %>", SignalRubyExecution},
		{"ruby interp popen", `#{IO.popen("id").read}`, SignalRubyExecution},
		{"ruby interp file", "#{File.read('/etc/passwd')}", SignalRubyExecution},

		// Velocity and Smarty directives.
		{"velocity runtime", "#set($x=$rt.getRuntime().exec('id'))", SignalDirectiveExecution},
		{"smarty php", "{php}echo `id`;{/php}", SignalDirectiveExecution},
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

// TestOrdinaryTemplatesPass is the table that decides whether this detector can
// ship at all. Braces are not an attack: they are Vue, Angular, Handlebars,
// Jinja, Liquid, i18n, CI config, Terraform, and shell prose.
//
// A detector that fires on "{{" would score perfectly above and block every
// CMS, documentation tool, and issue tracker in existence — and it would be
// most wrong precisely where template content is the application's whole point.
func TestOrdinaryTemplatesPass(t *testing.T) {
	values := []string{
		// Front-end interpolation.
		"{{ user.name }}",
		"{{ item.price | currency }}",
		"{{ product.title | upcase }}",
		"{{#each items}}{{this.title}}{{/each}}",
		"{{ user.firstName }} {{ user.lastName }}",
		"{{ items.length }} results",

		// i18n and mail templates, where braces are the entire feature.
		"{{count}} items remaining",
		"Hello {{name}}, you have {{n}} messages",
		"Welcome {{first_name}}! Your order {{order_id}} shipped.",
		"{% for row in rows %}{{ row.id }}{% endfor %}",
		"{% if user.admin %}Admin{% endif %}",

		// CI, infrastructure, and shell.
		"${{ matrix.os }}",
		"${{ secrets.GITHUB_TOKEN }}",
		"${{ github.event.pull_request.number }}",
		"${var.region}",
		"${POSTGRES_PASSWORD}",
		"${HOME}/bin",
		"use ${VAR:-default} for a fallback",
		"$(CC) -o $@ $<",
		"${datasource}",

		// Ruby and ERB that people write in tutorials.
		`puts "hello #{name}"`,
		"<%= link_to 'Home', root_path %>",
		"<%= @user.email %>",
		"#{user.id}",

		// Arithmetic that is a template, not a probe.
		"{{ 2 * count }}",
		"{{ price * quantity }}",
		"{{ total / 100 }}",

		// Naming an object without walking into it.
		"{{ config }}",
		"{{ request }}",
		"the config value is read at boot",

		// Prose and markup.
		"a set of {braces} in text",
		"see the <%= %> syntax in ERB",
		"JSON is {\"a\":1}",
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

// TestDelimitersAloneAreWorthless is the design as a test: template context
// carries no weight, so no number of delimiters can reach the threshold.
func TestDelimitersAloneAreWorthless(t *testing.T) {
	d := New()
	v := d.Analyze([]byte("{{x}}${y}#{z}<%w%>{%q%}"))
	if v.Detected() {
		t.Errorf("delimiters alone reached the threshold: %v", v.Signals)
	}
	if v.Signals&SignalTemplateContext == 0 {
		t.Error("template context was not even noticed")
	}
	if v.Score != 0 {
		t.Errorf("score = %d, want 0", v.Score)
	}
}

// TestSignalsOnlyCountInsideAnExpression checks that the dangerous vocabulary
// is scored in position. Prose about __subclasses__ is a bug report, not an
// attack, and blocking it is how a WAF ends up blocking the security team.
func TestSignalsOnlyCountInsideAnExpression(t *testing.T) {
	d := New()
	for _, v := range []string{
		"the __class__ attribute is documented here",
		"call getRuntime() to obtain the runtime",
		"we use IO.popen in the worker",
		"java.lang.Runtime is the class you want",
		"__subclasses__ walks the type hierarchy",
	} {
		if got := d.Analyze([]byte(v)); got.Detected() {
			t.Errorf("%q detected outside any template expression: %v", v, got.Signals)
		}
	}
}

// TestArithmeticProbeCorroborates records that "{{7*7}}" cannot fire alone.
func TestArithmeticProbeCorroborates(t *testing.T) {
	d := New()

	v := d.Analyze([]byte("{{7*7}}"))
	if v.Detected() {
		t.Error("a bare arithmetic probe fired; {{ 2*count }} is a real template")
	}
	if v.Signals&SignalArithmeticProbe == 0 {
		t.Error("arithmetic probe not noticed at all")
	}

	// With an app object it is no longer ambiguous.
	if v := d.Analyze([]byte("{{ config.x * 7 * 7 }}")); !v.Detected() {
		t.Errorf("probe plus app-object access did not corroborate: %v", v.Signals)
	}
}

// TestUnterminatedExpression covers a payload that omits the closing delimiter,
// which several engines still evaluate and which trivially defeats a matcher
// that requires a balanced pair.
func TestUnterminatedExpression(t *testing.T) {
	d := New()
	if v := d.Analyze([]byte("{{''.__class__.__mro__[1].__subclasses__()")); !v.Detected() {
		t.Errorf("unterminated payload missed: %v", v.Signals)
	}
}

func TestBounds(t *testing.T) {
	d := New()
	if d.Analyze(nil).Detected() {
		t.Error("nil detected")
	}
	// Deeply repeated delimiters must terminate and stay bounded.
	if d.Analyze([]byte(strings.Repeat("{{", 100000))).Detected() {
		t.Error("repeated delimiters reached the threshold")
	}
	long := strings.Repeat("a", maxScan*2) + "{{config.items()}}"
	if d.Analyze([]byte(long)).Detected() {
		t.Error("a payload past the scan bound was reported")
	}
}

// FuzzLiteralsAreExhaustive enforces the claim the prefilter depends on: any
// value the detector reports must contain a declared literal, or the value
// would be filtered out and the rule would silently never fire.
func FuzzLiteralsAreExhaustive(f *testing.F) {
	for _, s := range []string{
		"{{config.items()}}", "${T(java.lang.Runtime)}", "<%= `id` %>",
		"#set($x=$rt.getRuntime())", "{{ user.name }}", "", "{{", "}}",
		"{%", "@{", "<#", "{php}", "\x00{{__class__}}",
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
	v := []byte("Hello {{name}}, you have {{n}} messages")
	b.ReportAllocs()
	for b.Loop() {
		d.Analyze(v)
	}
}

func BenchmarkAnalyzeAttack(b *testing.B) {
	d := New()
	v := []byte("{{''.__class__.__mro__[1].__subclasses__()}}")
	b.ReportAllocs()
	for b.Loop() {
		d.Analyze(v)
	}
}
