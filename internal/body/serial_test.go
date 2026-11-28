// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

import (
	"bytes"
	"testing"
)

func bf(tail string) []byte { return append(append([]byte(nil), bfHeader...), tail...) }

func osf(graph []byte, lenBytes ...byte) []byte {
	return append(append([]byte{0xff, 0x01, 0x32}, lenBytes...), graph...)
}

func TestSerializedStreamPrefix(t *testing.T) {
	long := bytes.Repeat([]byte("A"), 200)
	cases := []struct {
		name string
		in   []byte
		want int
	}{
		{"java stream", []byte("\xac\xed\x00\x05sr\x00\x11java.util.HashMap"), 25},
		{"java stream is cut to the prefix", append([]byte("\xac\xed\x00\x05"), long...), serialPrefixLen},
		{"binaryformatter", bf("\x0c\x02"), 19},
		{"viewstate gadget, one-byte length", osf(bf("x"), 0x12), 22},
		{"viewstate gadget, two-byte length", osf(bf("x"), 0x92, 0x01), 23},

		{"empty", nil, 0},
		{"java magic with another version", []byte("\xac\xed\x00\x04sr"), 0},
		{"java magic not at the start", []byte("x\xac\xed\x00\x05sr"), 0},
		{"binaryformatter header truncated", bfHeader[:16], 0},
		{"binaryformatter header not at the start", append([]byte{0}, bfHeader...), 0},
		{"ordinary viewstate, Pair at the top", append([]byte{0xff, 0x01, 0x0f, 0x0f}, bfHeader...), 0},
		{"viewstate token 0x32 without a binaryformatter graph", osf([]byte("not a graph at all.."), 0x14), 0},
		{"viewstate header further than a length can reach", append([]byte{0xff, 0x01, 0x32, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, bfHeader...), 0},
		{"png", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"), 0},
		{"gzip", []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00"), 0},
	}
	for _, c := range cases {
		if got := SerializedStreamPrefix(c.in); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// FuzzSerializedStreamPrefix holds the two properties the transaction relies
// on: the prefix is never longer than the input or the bound, and it is never
// reported for input that IsDotNetStream and the Java magic both reject.
func FuzzSerializedStreamPrefix(f *testing.F) {
	f.Add([]byte("\xac\xed\x00\x05sr"))
	f.Add(bf("x"))
	f.Add(osf(bf("x"), 0x12))
	f.Add([]byte{0xff, 0x01, 0x32, 0x80, 0x80})
	f.Fuzz(func(t *testing.T, b []byte) {
		n := SerializedStreamPrefix(b)
		if n < 0 || n > len(b) || n > serialPrefixLen {
			t.Fatalf("prefix %d out of range for %d bytes", n, len(b))
		}
		java := len(b) >= 4 && b[0] == 0xac && b[1] == 0xed && b[2] == 0 && b[3] == 5
		if (n > 0) != (java || IsDotNetStream(b)) {
			t.Fatalf("prefix %d disagrees with the recognizers", n)
		}
	})
}
