// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"encoding/base64"
	"math/rand/v2"
	"net/url"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/ruleset/core"
	"github.com/gsoultan/gwaf/types"
)

// Fixtures for native object streams, shared by the evasion and benign corpora
// and the CVE drill. They are built rather than pasted because the bytes that
// matter are the framing, and a hand-written literal of a .NET stream is
// unreadable.

// javaStream is a Java object stream long enough that its base64 spelling is
// past the 64-character floor at which a field is decoded instead of read as
// text -- the length at which the magic used to be lost.
var javaStream = append([]byte("\xac\xed\x00\x05sr\x00\x2eorg.apache.commons.beanutils.BeanComparator"+
	"\xe3\xa1\x88\xea\x73\x22\xa4\x48\x02\x00\x02L\x00\x0acomparatort\x00\x16Ljava/util/Comparator;"),
	make([]byte, 64)...)

// binaryFormatterStream is a .NET BinaryFormatter graph: the seventeen-byte
// SerializedStreamHeader, then a library record naming the assembly and the
// first class record. The type named is TextFormattingRunProperties, the
// ysoserial.net gadget that carries a XAML payload.
var binaryFormatterStream = append([]byte{
	0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0c, 0x02, 0x00, 0x00, 0x00},
	"\x5eMicrosoft.PowerShell.Editor, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"+
		"\x05\x01\x00\x00\x00\x42Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties"...)

// varint7 is ObjectStateFormatter's 7-bit encoded length.
func varint7(n int) []byte {
	var out []byte
	for n >= 0x80 {
		out = append(out, byte(n)|0x80)
		n >>= 7
	}
	return append(out, byte(n))
}

// viewStateGadget is what the ysoserial.net ViewState plugin emits: the
// ObjectStateFormatter marker, token 0x32 (binary-serialized) at the top level,
// and the BinaryFormatter gadget as the whole graph.
func viewStateGadget() string {
	b := append([]byte{0xff, 0x01, 0x32}, varint7(len(binaryFormatterStream))...)
	return base64.StdEncoding.EncodeToString(append(b, binaryFormatterStream...))
}

// viewStateBenign is a page's own state: a Pair at the top level, a control's
// Text property, and a [Serializable] object the page stored, which
// ObjectStateFormatter binary-serializes *inside* the Pair. That nested 0x32 is
// ordinary in legacy WebForms apps (a DataTable kept in ViewState is the common
// case), and the MAC that follows is twenty random bytes.
func viewStateBenign() string {
	b := []byte("\xff\x01\x0f\x0f\x05\x0a1654561052\x0f\x16\x02\x1e\x04Text\x05\x05Hello\x32")
	b = append(b, varint7(len(binaryFormatterStream))...)
	b = append(b, binaryFormatterStream...)
	mac := make([]byte, 20)
	for i := range mac {
		mac[i] = byte(rand.N(256))
	}
	return base64.StdEncoding.EncodeToString(append(b, mac...))
}

func formBody(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v.Encode()
}

// TestRandomBinaryIsNotASerializedStream is the false-positive half of the
// stream header detection: uploads, images and encrypted blobs are binary, and
// a stream header must never be recognized in them. Random bytes, raw and as a
// base64 field, stand in for every format that is not one of the three
// headers; a match would be a header recognized somewhere other than offset 0,
// or one too short to be a statement about the format.
//
// It asserts on the two rules that read the recorded header rather than on the
// verdict as a whole, because random bytes are blocked by other rules at a rate
// that predates the header change (printable runs that happen to parse as
// PHP, a template or an LDAP filter; logged below) and that is a separate
// problem with its own fix.
func TestRandomBinaryIsNotASerializedStream(t *testing.T) {
	wc, _ := drillWAFs(t)
	r := rand.New(rand.NewPCG(1, 2))
	other := 0
	const samples = 2000
	for i := range samples {
		b := make([]byte, 64+r.IntN(2048))
		for j := range b {
			b[j] = byte(r.IntN(256))
		}
		raw := drillReq{method: "POST", target: "/upload", ct: "application/octet-stream", body: string(b)}
		field := drillReq{method: "POST", target: "/api", ct: "application/x-www-form-urlencoded",
			body: formBody("blob", base64.StdEncoding.EncodeToString(b))}
		for _, req := range []drillReq{raw, field} {
			id := drillRule(wc, req)
			switch {
			case id == core.IDDotNetSerialized || id == core.IDDotNetSerialized+900 ||
				id == core.IDJavaSemantic || id == core.IDJavaSemantic+900:
				t.Fatalf("sample %d: random binary read as a serialized stream (rule %d)", i, id)
			case id != 0:
				other++
			}
		}
	}
	t.Logf("random binary blocked by unrelated rules: %d of %d requests", other, 2*samples)
}

// TestSerializedStreamsInBinaryValues is the regression test for the gap the
// 2026-11-28 CVE round found: a native object stream inside a value that gwaf
// treats as binary -- a long base64 field, or a raw request body -- was split
// into printable runs, and the non-printable header that identifies it was the
// part thrown away. Each case passed core before the fix.
func TestSerializedStreamsInBinaryValues(t *testing.T) {
	wc, _ := drillWAFs(t)
	cases := []struct {
		name string
		req  drillReq
	}{
		{"java stream, long base64 form field", drillReq{method: "POST", target: "/invoker",
			ct: "application/x-www-form-urlencoded", body: formBody("x", base64.StdEncoding.EncodeToString(javaStream))}},
		{"java stream, long base64 json field", drillReq{method: "POST", target: "/api/state",
			ct: "application/json", body: `{"state":"` + base64.StdEncoding.EncodeToString(javaStream) + `"}`}},
		{"java stream, raw body", drillReq{method: "POST", target: "/invoker/JMXInvokerServlet",
			ct: "application/x-java-serialized-object", body: string(javaStream)}},
		{"java stream, raw body with no content type", drillReq{method: "POST", target: "/hub", body: string(javaStream)}},
		{"binaryformatter, long base64 form field", drillReq{method: "POST", target: "/api",
			ct: "application/x-www-form-urlencoded", body: formBody("data", base64.StdEncoding.EncodeToString(binaryFormatterStream))}},
		{"binaryformatter, raw body", drillReq{method: "POST", target: "/RemotingService.rem",
			ct: "application/octet-stream", body: string(binaryFormatterStream)}},
		{"viewstate gadget", drillReq{method: "POST", target: "/Default.aspx",
			ct: "application/x-www-form-urlencoded", body: formBody("__VIEWSTATE", viewStateGadget(), "__VIEWSTATEGENERATOR", "CA0B0334")}},
	}
	for _, c := range cases {
		if !drillBlocked(wc, c.req) {
			t.Errorf("%s: passed core", c.name)
		}
	}

	benign := drillReq{method: "POST", target: "/Default.aspx", ct: "application/x-www-form-urlencoded",
		body: formBody("__VIEWSTATE", viewStateBenign(), "__VIEWSTATEGENERATOR", "CA0B0334", "__EVENTVALIDATION", "/wEdAAKmV9J1")}
	if drillBlocked(wc, benign) {
		t.Error("an ordinary ViewState with a nested binary-serialized object was blocked")
	}
}

// drillRule returns the rule that blocked r, or 0.
func drillRule(w *gwaf.WAF, r drillReq) types.RuleID {
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRemoteAddr("192.0.2.10")
	tx.SetRequestLine(r.method, r.target, "HTTP/1.1")
	if r.ct != "" {
		tx.AddRequestHeader("Content-Type", r.ct)
	}
	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		return d.RuleID()
	}
	tx.SetRequestBody([]byte(r.body))
	if d := tx.ProcessRequestBody(); d.Blocked() {
		return d.RuleID()
	}
	return 0
}
