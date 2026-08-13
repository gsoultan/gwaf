// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

import (
	"strings"
	"testing"
)

func parseXML(t *testing.T, src string, lim Limits) ([]string, error) {
	t.Helper()
	var p Parser
	p.Reset(lim)
	var out []string
	err := p.ParseXML([]byte(src), func(name, value []byte, kind Kind) bool {
		k := "str"
		if kind == KindKey {
			k = "key"
		}
		out = append(out, k+" "+string(name)+"="+string(value))
		return true
	})
	return out, err
}

func TestParseXMLExtractsTextAndAttributes(t *testing.T) {
	got, err := parseXML(t, `<order id="7"><note>hi</note></order>`, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"key order=order",
		"key order=id",
		"str order@id=7",
		"key order.note=note",
		"str order.note=hi",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d emissions, want %d:\n  %s", len(got), len(want), strings.Join(got, "\n  "))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("emission %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestParseXMLNeverExpandsAnEntity is the security property the parser is built
// around, and the reason a billion-laughs document is not a special case here.
//
// A parser that expands and then caps the result has to be right about the cap.
// This has nothing to be right about: there is no expansion step. The bomb is
// copied through as the bytes it is, and the output is bounded by the input.
func TestParseXMLNeverExpandsAnEntity(t *testing.T) {
	// The classic billion laughs, nine levels of tenfold expansion.
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">`)
	for i := 1; i <= 9; i++ {
		b.WriteString(`<!ENTITY lol`)
		b.WriteByte(byte('0' + i))
		b.WriteString(` "`)
		for j := 0; j < 10; j++ {
			b.WriteString(`&lol`)
			if i == 1 {
				b.WriteString(`;`)
			} else {
				b.WriteByte(byte('0' + i - 1))
				b.WriteString(`;`)
			}
		}
		b.WriteString(`">`)
	}
	b.WriteString(`]><lolz>&lol9;</lolz>`)
	bomb := b.String()

	var total int
	var p Parser
	p.Reset(Limits{})
	err := p.ParseXML([]byte(bomb), func(name, value []byte, kind Kind) bool {
		total += len(value)
		return true
	})
	if err != nil {
		t.Fatalf("a bomb must parse, not error: %v", err)
	}
	if total > len(bomb) {
		t.Fatalf("emitted %d bytes from a %d byte document; something expanded",
			total, len(bomb))
	}
	t.Logf("%d byte bomb produced %d bytes of values", len(bomb), total)
}

func TestParseXMLIsBounded(t *testing.T) {
	deep := strings.Repeat("<a>", 200) + "x" + strings.Repeat("</a>", 200)
	if _, err := parseXML(t, deep, Limits{MaxDepth: 8}); err != ErrTooDeep {
		t.Errorf("deep document: err = %v, want ErrTooDeep", err)
	}

	var wide strings.Builder
	wide.WriteString("<r>")
	for i := 0; i < 500; i++ {
		wide.WriteString("<f>v</f>")
	}
	wide.WriteString("</r>")
	if _, err := parseXML(t, wide.String(), Limits{MaxFields: 16}); err != ErrTooManyFields {
		t.Errorf("wide document: err = %v, want ErrTooManyFields", err)
	}

	long := "<r a=\"" + strings.Repeat("x", 5000) + "\"/>"
	if _, err := parseXML(t, long, Limits{MaxValueLen: 64}); err != ErrTooLarge {
		t.Errorf("long attribute: err = %v, want ErrTooLarge", err)
	}
}

// TestParseXMLSurvivesMalformedInput: every one of these is something a scanner
// sends, and none may hang, panic, or consume the rest of the document.
func TestParseXMLSurvivesMalformedInput(t *testing.T) {
	for _, src := range []string{
		"", "<", "<>", "</>", "<a", "<a ", "<a b", "<a b=", `<a b="`,
		"<!", "<!-", "<!--", "<!--x", "<?", "<?xml", "<![CDATA[", "<![CDATA[x",
		"<!DOCTYPE", "<!DOCTYPE a [", "<!DOCTYPE a [<!ENTITY", "</a>", "</a",
		"<a></b></c>", "<a/><", "< a>", "<a>>", "<a b='c\"d'>", "\x00<a>\x00",
		strings.Repeat("<a>", 50), strings.Repeat("</a>", 50),
		strings.Repeat("<", 100), "<a>" + strings.Repeat("&lol;", 100) + "</a>",
	} {
		t.Run(src, func(t *testing.T) {
			if _, err := parseXML(t, src, Limits{}); err != nil {
				switch err {
				case ErrTooDeep, ErrTooManyFields, ErrTooLarge:
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestParseXMLHandlesSOAPAndCDATA(t *testing.T) {
	soap := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
	  <soapenv:Body><run><cmd><![CDATA[cat /etc/passwd]]></cmd></run></soapenv:Body>
	</soapenv:Envelope>`
	got, err := parseXML(t, soap, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "cat /etc/passwd") {
		t.Errorf("CDATA payload not extracted:\n%s", joined)
	}
	// The namespace prefix stays part of the name, because that is what an
	// operator reads in a finding.
	if !strings.Contains(joined, "soapenv:Envelope") {
		t.Errorf("namespace prefix lost:\n%s", joined)
	}
}

func TestSniffXML(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{`<?xml version="1.0"?><a/>`, true},
		{`<!DOCTYPE html>`, true},
		{`<soapenv:Envelope>`, true},
		{`  <order/>`, true},
		{`{"a":1}`, false},
		{`a=1&b=2`, false},
		{``, false},
		{`<`, false},
		{`<!-- just a comment -->`, false},
		{`<1abc>`, false},
	} {
		if got := SniffXML([]byte(tc.src)); got != tc.want {
			t.Errorf("SniffXML(%q) = %v, want %v", tc.src, got, tc.want)
		}
	}
}

// FuzzParseXML is non-negotiable: this takes hostile input (CLAUDE.md §4).
func FuzzParseXML(f *testing.F) {
	seeds := []string{
		"", "<a/>", "<a>x</a>", `<a b="c"/>`, "<![CDATA[x]]>",
		`<?xml version="1.0"?><r><f>v</f></r>`,
		`<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>`,
		`<soap:Envelope xmlns:soap="x"><soap:Body/></soap:Envelope>`,
		"<a", "<a b=", "<!--", "<?", "</", "<a>&lol9;</a>",
		"<a b='c'>t</a>", strings.Repeat("<a>", 40),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 1<<20 {
			t.Skip()
		}
		var p Parser
		p.Reset(Limits{})
		emitted := 0
		err := p.ParseXML([]byte(src), func(name, value []byte, kind Kind) bool {
			emitted += len(value)
			// A name or value must always be a view into the input, never
			// something invented: the parser does not decode, so it cannot
			// produce a byte the document did not contain.
			if len(value) > len(src) {
				t.Fatalf("value of %d bytes from %d bytes of input", len(value), len(src))
			}
			return true
		})
		switch err {
		case nil, ErrTooDeep, ErrTooManyFields, ErrTooLarge:
		default:
			t.Fatalf("unexpected error: %v", err)
		}
		// Nothing expands. Total emitted bytes cannot exceed the document,
		// which is what makes an entity bomb a non-event here.
		if emitted > len(src) {
			t.Fatalf("emitted %d bytes from %d bytes of input", emitted, len(src))
		}
	})
}
