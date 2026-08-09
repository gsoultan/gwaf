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
		// A request host deliberately unrelated to the destinations below, so
		// this case tests the sink-parameter logic and not the same-origin
		// logic -- TestOffOriginURLIsSameOriginAware covers that.
		ctx := rules.EvalContext{Target: types.Target{Kind: types.TargetArgs}, Key: key,
			Host: []byte("target.local")}
		_, ok := o.Eval(&ctx, []byte(value))
		return ok
	}

	t.Run("off-origin URLs in navigation parameters fire", func(t *testing.T) {
		for _, c := range []struct{ key, val string }{
			{"redirect", "http://interact.sh"},
			{"redirect_to", "https://oast.me"},
			{"redirecturl", "http://interact.sh"},
			{"tb_redirect_fail", "https://oast.me"},
			{"return_url", "https://oast.example.com"},
			{"redirectionurl", "http://x.x"},
			{"next", "//evil.example.com/path"}, // protocol-relative
			{"goto", "https://evil.tld"},
		} {
			if !fire(c.key, c.val) {
				t.Errorf("missed %s=%s", c.key, c.val)
			}
		}
	})

	// The fetch half is a separate, opt-in operator: handing a server a foreign
	// URL is what webhook registration and feed subscription are, so it cannot
	// ship enabled. What must hold is that each operator answers for its own
	// half and not the other's.
	t.Run("fetch parameters are the other rule", func(t *testing.T) {
		nav, fetch := offOriginURL(), offOriginFetchURL()
		ev := func(o rules.Operator, key, val string) bool {
			ctx := rules.EvalContext{Target: types.Target{Kind: types.TargetArgs},
				Key: key, Host: []byte("target.local")}
			_, ok := o.Eval(&ctx, []byte(val))
			return ok
		}
		for _, key := range []string{"url", "URL", "source_url", "swp_url", "api_url", "webhook", "feed"} {
			if ev(nav, key, "http://oast.example.com") {
				t.Errorf("navigation rule fired on fetch parameter %s", key)
			}
			if !ev(fetch, key, "http://oast.example.com") {
				t.Errorf("fetch rule missed %s", key)
			}
		}
		for _, key := range []string{"redirect_to", "next", "goto"} {
			if ev(fetch, key, "http://oast.example.com") {
				t.Errorf("fetch rule fired on navigation parameter %s", key)
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

// TestOffOriginURLIsSameOriginAware is what moved this rule out of opt-in.
//
// Without the request's own Host there is no difference between
// "redirect_to=https://shop.example.com/cart" and
// "redirect_to=https://evil.tld/cart", so the rule had to fire on both and
// could not ship enabled -- OAuth, SSO and payment returns all send an absolute
// destination and all of them would have broken. With the Host it fires on the
// second and not the first, which is the actual vulnerability.
//
// The registrable-domain comparison is deliberately a suffix match on a label
// boundary rather than a public-suffix lookup. gwaf's core module takes no
// third-party dependencies, and the failure mode of the cheap comparison is to
// *allow* a sibling under a shared suffix -- a miss, not a block -- which is the
// right direction for a rule that ships on.
func TestOffOriginURLIsSameOriginAware(t *testing.T) {
	o := offOriginURL()

	fire := func(host, key, value string) bool {
		ctx := rules.EvalContext{Target: types.Target{Kind: types.TargetArgs}, Key: key,
			Host: []byte(host)}
		_, ok := o.Eval(&ctx, []byte(value))
		return ok
	}

	t.Run("same origin passes", func(t *testing.T) {
		for _, c := range []struct{ host, val string }{
			{"shop.example.com", "https://shop.example.com/cart"},
			{"shop.example.com", "https://shop.example.com:443/cart"},
			{"shop.example.com", "https://auth.example.com/oauth/cb"},
			{"shop.example.com", "//shop.example.com/x"},
			{"example.com", "https://www.example.com/"},
			{"shop.example.com:8443", "https://shop.example.com/cart"},
		} {
			if fire(c.host, "redirect_to", c.val) {
				t.Errorf("false positive: host=%s redirect_to=%s", c.host, c.val)
			}
		}
	})

	t.Run("off origin fires", func(t *testing.T) {
		for _, c := range []struct{ host, val string }{
			{"shop.example.com", "https://evil.tld/cart"},
			{"shop.example.com", "http://interact.sh"},
			{"shop.example.com", "//oast.me/x"},
			{"shop.example.com", "https://example.com.evil.tld/"},
			{"shop.example.com", "https://shop.example.com.evil.tld/"},
		} {
			if !fire(c.host, "redirect_to", c.val) {
				t.Errorf("missed: host=%s redirect_to=%s", c.host, c.val)
			}
		}
	})

	t.Run("no Host header does not fire", func(t *testing.T) {
		// This rule ships in the default set, so it must not block on absence of
		// evidence: with no request host there is nothing for a destination to
		// be foreign to. The repo's own benign corpus found this -- a JSON body
		// carrying {"url": "https://example.com/x"} through a transaction with
		// no Host was blocked, which is a false positive on ordinary traffic.
		if fire("", "redirect_to", "https://evil.tld/") {
			t.Error("fired with no Host to compare against")
		}
	})
}
