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
			Origins: []string{"target.local"}}
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
				Key: key, Origins: []string{"target.local"}}
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

// TestOffOriginURLTrustsConfigurationNotTheRequest is the regression for a
// bypass this rule shipped with in v0.4.0.
//
// The rule compared the destination against the request's Host header to decide
// whether it pointed somewhere else. An attacker supplies both: "Host: evil.tld"
// with "redirect_to=https://evil.tld/" compared same-origin and passed, which
// made the rule's entire safety argument -- that it could now tell an OAuth
// callback from an open redirect -- revocable by the request it was judging.
//
// The trusted side is configuration now. The Host header is not read at all,
// and the test asserts that by setting it to the attacker's own domain.
func TestOffOriginURLTrustsConfigurationNotTheRequest(t *testing.T) {
	o := offOriginURL()

	fire := func(origins []string, host, val string) bool {
		ctx := rules.EvalContext{
			Target: types.Target{Kind: types.TargetArgs}, Key: "redirect_to",
			Host: []byte(host), Origins: origins,
		}
		_, ok := o.Eval(&ctx, []byte(val))
		return ok
	}
	mine := []string{"shop.example.com", "auth.example.com"}

	t.Run("a forged Host no longer excuses a foreign destination", func(t *testing.T) {
		for _, host := range []string{"evil.tld", "x.evil.tld", "shop.example.com", ""} {
			if !fire(mine, host, "https://evil.tld/") {
				t.Errorf("bypass: Host=%q made https://evil.tld/ same-origin", host)
			}
		}
	})

	t.Run("declared origins and their subdomains pass", func(t *testing.T) {
		for _, val := range []string{
			"https://shop.example.com/cart",
			"https://shop.example.com:443/cart",
			"https://www.shop.example.com/cart",
			"https://auth.example.com/oauth/cb",
			"//shop.example.com/x",
		} {
			if fire(mine, "evil.tld", val) {
				t.Errorf("false positive on a declared origin: %s", val)
			}
		}
	})

	t.Run("lookalikes are not subdomains", func(t *testing.T) {
		for _, val := range []string{
			"https://shop.example.com.evil.tld/",
			"https://notshop.example.com/",
			"https://example.com/",
		} {
			if !fire(mine, "shop.example.com", val) {
				t.Errorf("missed lookalike: %s", val)
			}
		}
	})

	t.Run("no declared origins reports nothing", func(t *testing.T) {
		// The safe direction for a rule in the default set: without something
		// trustworthy to compare against, nothing can be shown foreign.
		if fire(nil, "shop.example.com", "https://evil.tld/") {
			t.Error("fired with no configured origins")
		}
	})
}
