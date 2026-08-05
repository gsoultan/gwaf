// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

import (
	"strings"
	"testing"
)

// mp builds a multipart body with CRLF line endings, as a browser sends.
func mp(boundary string, parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString(p)
		b.WriteString("\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.String()
}

func parseMP(t testing.TB, src, boundary string, limits Limits) ([]field, []PartInfo, error) {
	t.Helper()
	var p Parser
	p.Reset(limits)

	var fs []field
	var infos []PartInfo
	err := p.ParseMultipart([]byte(src), []byte(boundary),
		func(i PartInfo) bool {
			infos = append(infos, PartInfo{
				Name:        append([]byte(nil), i.Name...),
				Filename:    append([]byte(nil), i.Filename...),
				ContentType: append([]byte(nil), i.ContentType...),
				Charset:     append([]byte(nil), i.Charset...),
				Index:       i.Index,
			})
			return true
		},
		func(name, value []byte, k Kind) bool {
			fs = append(fs, field{string(name), string(value), k})
			return true
		})
	return fs, infos, err
}

func TestParseMultipartBasic(t *testing.T) {
	src := mp("BOUNDARY",
		"Content-Disposition: form-data; name=\"user\"\r\n\r\nAlice",
		"Content-Disposition: form-data; name=\"qty\"\r\n\r\n3",
	)

	fs, infos, err := parseMP(t, src, "BOUNDARY", Limits{})
	if err != nil {
		t.Fatalf("ParseMultipart: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("got %d parts, want 2", len(infos))
	}
	got := valuesOf(fs)
	if got["user"] != "Alice" || got["qty"] != "3" {
		t.Errorf("values = %v", got)
	}
}

// TestEveryPartIsInspected is the CVE-2026-21876 regression test.
//
// That flaw (CVSS 9.3, January 2026) broke the OWASP Core Rule Set across
// ModSecurity v2, v3, and Coraza because a chained rule captured the multipart
// charset once and evaluated it once — so only the *final* part was actually
// checked, and a payload in any earlier part passed unexamined.
//
// The property that closes it is simple and must never regress: every part's
// content reaches the caller, regardless of position or count.
func TestEveryPartIsInspected(t *testing.T) {
	const n = 20
	parts := make([]string, 0, n)
	for i := range n {
		parts = append(parts, "Content-Disposition: form-data; name=\"f"+itoaStr(i)+"\"\r\n"+
			"Content-Type: text/plain; charset=utf-7\r\n\r\npayload"+itoaStr(i))
	}

	fs, infos, err := parseMP(t, mp("B", parts...), "B", Limits{})
	if err != nil {
		t.Fatalf("ParseMultipart: %v", err)
	}
	if len(infos) != n {
		t.Fatalf("parsed %d parts, want %d", len(infos), n)
	}

	got := valuesOf(fs)
	for i := range n {
		key := "f" + itoaStr(i)
		if got[key] != "payload"+itoaStr(i) {
			t.Errorf("part %d content missing: %q — a part that is not emitted "+
				"is a part nobody inspected", i, got[key])
		}
	}

	// And every part's charset is reported, not just the last one's.
	for i, info := range infos {
		if string(info.Charset) != "utf-7" {
			t.Errorf("part %d charset = %q, want utf-7 — reporting only the "+
				"final part's charset is exactly CVE-2026-21876",
				i, info.Charset)
		}
	}
}

// TestFilenameIsInspected covers the most attacker-controlled field in an
// upload. A filename is a classic traversal and double-extension vector, and
// treating it as metadata rather than as a value is how those get through.
func TestFilenameIsInspected(t *testing.T) {
	src := mp("B",
		"Content-Disposition: form-data; name=\"upload\"; filename=\"../../etc/passwd\"\r\n"+
			"Content-Type: application/octet-stream\r\n\r\ncontent")

	fs, infos, err := parseMP(t, src, "B", Limits{})
	if err != nil {
		t.Fatalf("ParseMultipart: %v", err)
	}
	if string(infos[0].Filename) != "../../etc/passwd" {
		t.Errorf("Filename = %q", infos[0].Filename)
	}

	found := false
	for _, f := range fs {
		if f.name == "upload.filename" && f.value == "../../etc/passwd" {
			found = true
		}
	}
	if !found {
		t.Errorf("filename was not emitted as a value; got %+v", fs)
	}
}

func TestPartHeaderParsing(t *testing.T) {
	tests := []struct {
		name, headers              string
		wantName, wantFile, wantCS string
		wantType                   string
	}{
		{"quoted name", `Content-Disposition: form-data; name="a"`, "a", "", "", ""},
		{"bare name", `Content-Disposition: form-data; name=a`, "a", "", "", ""},
		{"name and filename", `Content-Disposition: form-data; name="f"; filename="x.txt"`,
			"f", "x.txt", "", ""},
		{"spaces around equals", `Content-Disposition: form-data; name = "a"`, "a", "", "", ""},
		{"case insensitive header", `content-disposition: form-data; NAME="a"`, "a", "", "", ""},
		{"content type with charset",
			"Content-Disposition: form-data; name=\"a\"\r\nContent-Type: text/plain; charset=utf-7",
			"a", "", "utf-7", "text/plain"},
		{"filename with spaces", `Content-Disposition: form-data; name="f"; filename="my file.txt"`,
			"f", "my file.txt", "", ""},
		{"empty filename", `Content-Disposition: form-data; name="f"; filename=""`, "f", "", "", ""},
		// "xfilename" must not satisfy a lookup for "filename".
		{"similar param name", `Content-Disposition: form-data; name="f"; xfilename="y"`,
			"f", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, infos, err := parseMP(t, mp("B", tt.headers+"\r\n\r\nbody"), "B", Limits{})
			if err != nil {
				t.Fatalf("ParseMultipart: %v", err)
			}
			i := infos[0]
			if string(i.Name) != tt.wantName {
				t.Errorf("Name = %q, want %q", i.Name, tt.wantName)
			}
			if string(i.Filename) != tt.wantFile {
				t.Errorf("Filename = %q, want %q", i.Filename, tt.wantFile)
			}
			if string(i.Charset) != tt.wantCS {
				t.Errorf("Charset = %q, want %q", i.Charset, tt.wantCS)
			}
			if tt.wantType != "" && string(i.ContentType) != tt.wantType {
				t.Errorf("ContentType = %q, want %q", i.ContentType, tt.wantType)
			}
		})
	}
}

// TestBoundaryInContentIsNotADelimiter guards the split. A delimiter only
// counts at a line start; a body containing the boundary string mid-line must
// not be cut there, or the parts an origin sees and the parts gwaf sees differ.
func TestBoundaryInContentIsNotADelimiter(t *testing.T) {
	src := mp("XYZ",
		"Content-Disposition: form-data; name=\"a\"\r\n\r\ntext --XYZ still the same part")

	fs, infos, err := parseMP(t, src, "XYZ", Limits{})
	if err != nil {
		t.Fatalf("ParseMultipart: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("split into %d parts, want 1", len(infos))
	}
	if got := valuesOf(fs)["a"]; got != "text --XYZ still the same part" {
		t.Errorf("content = %q", got)
	}
}

func TestBareLFLineEndings(t *testing.T) {
	// A lenient origin accepts LF, so a firewall requiring CRLF would refuse to
	// parse bodies the application reads fine.
	src := "--B\nContent-Disposition: form-data; name=\"a\"\n\nvalue\n--B--\n"

	fs, _, err := parseMP(t, src, "B", Limits{})
	if err != nil {
		t.Fatalf("ParseMultipart: %v", err)
	}
	if got := valuesOf(fs)["a"]; got != "value" {
		t.Errorf("content = %q, want %q", got, "value")
	}
}

func TestUnnamedPartIsStillInspected(t *testing.T) {
	src := mp("B", "Content-Type: text/plain\r\n\r\norphan content")

	fs, _, err := parseMP(t, src, "B", Limits{})
	if err != nil {
		t.Fatalf("ParseMultipart: %v", err)
	}
	found := false
	for _, f := range fs {
		if f.value == "orphan content" {
			found = true
		}
	}
	if !found {
		t.Errorf("a part with no name was dropped; got %+v", fs)
	}
}

func TestParseMultipartMalformed(t *testing.T) {
	// A body that cannot be split is a decision, not a partial result: the
	// origin may split it differently, and guessing is the whole failure mode.
	tests := []struct{ name, src, boundary string }{
		{"no boundary in body", "just text", "B"},
		{"truncated, no final delimiter", "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv", "B"},
		{"empty boundary", mp("B", "x"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := parseMP(t, tt.src, tt.boundary, Limits{}); err == nil {
				t.Error("accepted malformed multipart")
			}
		})
	}
}

func TestParseMultipartLimits(t *testing.T) {
	t.Run("part count", func(t *testing.T) {
		parts := make([]string, 0, MaxParts+10)
		for i := range MaxParts + 10 {
			parts = append(parts, "Content-Disposition: form-data; name=\"f"+itoaStr(i)+"\"\r\n\r\nv")
		}
		_, _, err := parseMP(t, mp("B", parts...), "B", Limits{MaxFields: 100000})
		if err != ErrTooManyParts {
			t.Errorf("err = %v, want ErrTooManyParts", err)
		}
	})

	t.Run("field count", func(t *testing.T) {
		parts := make([]string, 0, 50)
		for i := range 50 {
			parts = append(parts, "Content-Disposition: form-data; name=\"f"+itoaStr(i)+"\"\r\n\r\nv")
		}
		_, _, err := parseMP(t, mp("B", parts...), "B", Limits{MaxFields: 5})
		if err != ErrTooManyFields {
			t.Errorf("err = %v, want ErrTooManyFields", err)
		}
	})

	t.Run("total size", func(t *testing.T) {
		src := mp("B", "Content-Disposition: form-data; name=\"a\"\r\n\r\n"+strings.Repeat("x", 1000))
		if _, _, err := parseMP(t, src, "B", Limits{MaxTotalSize: 100}); err != ErrTooLarge {
			t.Errorf("err = %v, want ErrTooLarge", err)
		}
	})
}

// TestFileContentIsBounded records the coverage decision explicitly: content
// beyond maxFileContent is not inspected, and that must be a deliberate,
// visible choice rather than an accident.
func TestFileContentIsBounded(t *testing.T) {
	big := strings.Repeat("A", maxFileContent*3)
	src := mp("B",
		"Content-Disposition: form-data; name=\"up\"; filename=\"x.bin\"\r\n\r\n"+big)

	fs, _, err := parseMP(t, src, "B", Limits{MaxValueLen: 1 << 20})
	if err != nil {
		t.Fatalf("ParseMultipart: %v", err)
	}
	for _, f := range fs {
		if f.name == "up" && len(f.value) > maxFileContent {
			t.Errorf("file content %d bytes exceeds the %d-byte inspection bound",
				len(f.value), maxFileContent)
		}
	}

	// A non-file part is not truncated by the file bound.
	src2 := mp("B", "Content-Disposition: form-data; name=\"text\"\r\n\r\n"+big)
	fs2, _, err := parseMP(t, src2, "B", Limits{MaxValueLen: 1 << 20})
	if err != nil {
		t.Fatalf("ParseMultipart: %v", err)
	}
	if got := len(valuesOf(fs2)["text"]); got != len(big) {
		t.Errorf("non-file part truncated to %d bytes, want %d", got, len(big))
	}
}

func TestBoundary(t *testing.T) {
	tests := []struct {
		ct        string
		want      string
		multipart bool
	}{
		{"multipart/form-data; boundary=abc", "abc", true},
		{`multipart/form-data; boundary="a b c"`, "a b c", true},
		{"MULTIPART/FORM-DATA; BOUNDARY=abc", "abc", true},
		{"multipart/form-data; charset=utf-8; boundary=xyz", "xyz", true},
		{"multipart/mixed; boundary=q", "q", true},
		{"multipart/form-data", "", true},
		{"application/json", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.ct, func(t *testing.T) {
			b, isMP := Boundary(tt.ct)
			if isMP != tt.multipart {
				t.Errorf("multipart = %v, want %v", isMP, tt.multipart)
			}
			if string(b) != tt.want {
				t.Errorf("boundary = %q, want %q", b, tt.want)
			}
		})
	}
}

func FuzzParseMultipart(f *testing.F) {
	f.Add(mp("B", "Content-Disposition: form-data; name=\"a\"\r\n\r\nv"), "B")
	f.Add("--B\r\n\r\n\r\n--B--\r\n", "B")
	f.Add("", "B")
	f.Add("--B", "B")
	f.Add("--B--", "B")
	f.Add(strings.Repeat("--B\r\n", 100), "B")

	f.Fuzz(func(t *testing.T, src, boundary string) {
		if len(src) > 32768 || len(boundary) > 256 {
			t.Skip()
		}
		var p Parser
		p.Reset(Limits{})
		_ = p.ParseMultipart([]byte(src), []byte(boundary),
			func(PartInfo) bool { return true },
			func(name, value []byte, _ Kind) bool {
				if len(name) > 65536 || len(value) > 1<<20 {
					t.Fatal("buffer exceeded its ceiling")
				}
				return true
			})
	})
}

func BenchmarkParseMultipart(b *testing.B) {
	src := []byte(mp("BOUNDARY",
		"Content-Disposition: form-data; name=\"user\"\r\n\r\nAlice",
		"Content-Disposition: form-data; name=\"email\"\r\n\r\nalice@example.com",
		"Content-Disposition: form-data; name=\"file\"; filename=\"doc.txt\"\r\n"+
			"Content-Type: text/plain\r\n\r\n"+strings.Repeat("content ", 100),
	))
	var p Parser
	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		p.Reset(Limits{})
		p.ParseMultipart(src, []byte("BOUNDARY"), nil,
			func([]byte, []byte, Kind) bool { return true })
	}
}

func itoaStr(n int) string {
	return string(itoa(nil, n))
}
