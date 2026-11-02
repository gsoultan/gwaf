// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf

import (
	"strings"
	"testing"
)

func TestOriginStart(t *testing.T) {
	for target, want := range map[string]int{
		"/index.php":              -1,
		"":                        -1,
		"*":                       -1,
		"//host/x":                -1,
		"http:/x":                 -1,
		"1http://h/x":             -1,
		"http://h":                8,
		"http://h/x.php":          8,
		"http://h?x":              8,
		"http://h#f":              8,
		"HTTPS://h:443/x":         13,
		"svn+ssh://u@h/x":         13,
		"http://":                 7,
		"a.b-c+d://h/":            11,
		"http://h/x?u=http://e/y": 8,
	} {
		if got := originStart(target); got != want {
			t.Errorf("originStart(%q) = %d, want %d", target, got, want)
		}
	}
}

// FuzzOriginStart asserts the two properties the rewrite rests on. Whatever is
// cut off is exactly "scheme://authority" -- never a byte of path, query or
// fragment -- and an origin-form target behind any authority is recovered
// whole, so no interpretation of the path is lost to the rewrite.
func FuzzOriginStart(f *testing.F) {
	for _, s := range []string{"http://h/x.php", "/x", "HTTP://h?q", "http://h", "//h/x", "a://b/c"} {
		f.Add(s, "host:80", "/p?q=http://e/x.php")
	}
	f.Fuzz(func(t *testing.T, target, authority, origin string) {
		if k := originStart(target); k >= 0 {
			cut := target[:k]
			i := strings.Index(cut, "://")
			if i < 1 || strings.ContainsAny(cut[i+3:], "/?#") || strings.ContainsAny(cut[:i], ":/?#") {
				t.Fatalf("originStart(%q) cut %q, which is not scheme://authority", target, cut)
			}
			if rest := target[k:]; rest != "" && !strings.ContainsRune("/?#", rune(rest[0])) {
				t.Fatalf("originStart(%q) left %q, which does not start a path, query or fragment", target, rest)
			}
		}
		if strings.ContainsAny(authority, "/?#") || !strings.HasPrefix(origin, "/") {
			return
		}
		abs := "http://" + authority + origin
		if k := originStart(abs); k < 0 || abs[k:] != origin {
			t.Fatalf("originStart(%q) did not recover %q", abs, origin)
		}
		if originStart(origin) != -1 {
			t.Fatalf("origin-form %q was treated as absolute", origin)
		}
	})
}
