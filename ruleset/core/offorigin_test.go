// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"testing"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// TestOffOriginURLOperator covers the single largest class of miss in the
// WordPress CVE replay: 27 of 70 remaining exploits were one shape, an absolute
// URL handed to a parameter whose name says the application will follow it.
// Open redirect and SSRF are the same request-side signal and differ only in who
// does the following -- the browser or the server.
//
// The parameter name carries the evidence, which is why this reads ctx.Key. A
// URL in "q" is a search term; the same URL in "redirect_to" is a destination.
func TestOffOriginURLOperator(t *testing.T) {
	o := offOriginURL()

	fire := func(key, value string) bool {
		ctx := rules.EvalContext{Target: types.Target{Kind: types.TargetArgs}, Key: key}
		_, ok := o.Eval(&ctx, []byte(value))
		return ok
	}

	t.Run("absolute URLs in sink parameters fire", func(t *testing.T) {
		for _, c := range []struct{ key, val string }{
			{"redirect", "http://interact.sh"},
			{"redirect_to", "https://oast.me"},
			{"redirecturl", "http://interact.sh"},
			{"tb_redirect_fail", "https://oast.me"},
			{"api_url", "https://oast.me"},
			{"url", "http://oast.example.com/live.m3u8"},
			{"URL", "https://oast.example.com"},
			{"source_url", "http://oast.example.com"},
			{"swp_url", "http://oast.example.com"},
			{"return_url", "https://oast.example.com"},
			{"redirectionurl", "http://x.x"},
			{"next", "//evil.example.com/path"}, // protocol-relative
		} {
			if !fire(c.key, c.val) {
				t.Errorf("missed %s=%s", c.key, c.val)
			}
		}
	})

	t.Run("relative destinations pass", func(t *testing.T) {
		// WordPress's own redirect_to is relative, which is the common case and
		// the reason this does not simply block the parameter name.
		for _, c := range []struct{ key, val string }{
			{"redirect_to", "/wp-admin/"},
			{"redirect_to", "/wp-admin/themes.php?page=x"},
			{"url", "/wp-content/uploads/2026/01/a.jpg"},
			{"next", "dashboard"},
			{"return_url", ""},
		} {
			if fire(c.key, c.val) {
				t.Errorf("false positive on %s=%s", c.key, c.val)
			}
		}
	})

	t.Run("URLs outside sink parameters pass", func(t *testing.T) {
		// A URL is ordinary content nearly everywhere else: a comment linking to
		// a site, a search for a domain, a profile field.
		for _, c := range []struct{ key, val string }{
			{"q", "https://example.com/docs"},
			{"comment", "see https://example.com/docs?id=5 for details"},
			{"author_url", "https://bob.example.com"},
			{"s", "http://news.example.com"},
			{"content", "<a href=\"https://example.com\">link</a>"},
		} {
			if fire(c.key, c.val) {
				t.Errorf("false positive on %s=%s", c.key, c.val)
			}
		}
	})
}
