// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/transform"
	"github.com/gsoultan/gwaf/types"
)

// OffOriginURLRule reports an absolute URL handed to a parameter whose name says
// the application will follow it.
//
// This is the navigation half. The server-side fetch half is SSRFParamRule,
// which is opt-in for the reason documented there.
//
// # Why the two halves share one comparison
//
// Open redirect and server-side request forgery are the same request-side
// signal. The request carries a destination the attacker chose; the only
// difference is who dereferences it, the browser or the server. Replaying real
// WordPress CVEs, 27 of 70 remaining exploits were this exact shape and split
// evenly across the two labels -- "redirect=http://interact.sh" and
// "url=http://oast.example.com" are indistinguishable until something follows
// them.
//
// They are two rules anyway, because *who dereferences it* decides whether the
// benign reading exists. Nothing legitimate sends a site's own users to another
// origin through a "redirect_to" parameter. Plenty legitimately hands a server a
// foreign URL through a "url" parameter -- that is what webhook registration,
// avatar import and feed subscription are.
//
// # Why the parameter name carries the evidence
//
// A URL is ordinary content nearly everywhere. It is a search term in "q", a
// link in a comment, a profile field in "author_url". What makes it a
// destination is the parameter it arrives in, so this is one of the few rules
// that reads ctx.Key rather than only the value. The name list is a closed set
// of *sink* words, and it is matched as a whole word or a suffix so that
// "author_url" does not read as a redirect target while "return_url" does.
//
// # Why it can ship enabled
//
// It could not, at first. A cross-origin destination is exactly what OAuth
// authorisation, payment returns and SSO flows send --
// "redirect_uri=https://app.example.com/cb" is the protocol working -- and
// without the request's own origin to compare against, this rule saw the same
// bytes in that and in "redirect=https://evil.tld". Firing on both would have
// broken a login flow on somebody's first deploy, so it shipped opt-in.
//
// rules.EvalContext now carries the request Host, which is the difference
// between "an absolute URL" and "an absolute URL somewhere else". A destination
// on the site's own registrable domain is the application navigating itself and
// passes; a foreign one is the vulnerability and fires. That is a question about
// the request alone, so it belongs here rather than in the embedder's policy.
//
// The residue that is still policy -- an allow-list of *third-party* domains a
// particular deployment trusts, a payment provider or an identity provider --
// is expressed as a scoped exception on this rule, which is narrower than
// turning it off.
func offOriginURLRule(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:    id,
		Phase: types.PhaseRequestHeaders,
		// Arguments only: the parameter name is half the evidence, so an
		// unkeyed collection can never match and evaluating it there is cost
		// with no possible finding.
		Targets: []types.Target{{Kind: types.TargetArgs}},
		// Deliberately not decodeChain: RemoveWhitespace would weld a sentence
		// containing a URL into something that looks like a bare destination,
		// and the value here has to keep its shape to be parsed as a URL.
		Transforms: []rules.Transform{transform.URLDecode, transform.Lowercase},
		Op:         offOriginURL(),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityWarning,
		Confidence: types.High,
		Msg:        "Absolute URL in a redirect or fetch parameter",
		Tags:       []string{"redirect", "ssrf", "owasp-a01", "owasp-a10"},
	}
}

// navigationParamNames are parameter names whose value the *browser* is sent to.
//
// An off-origin value here is an open redirect, and there is no ordinary reading
// of it: an application navigating its own users somewhere else is the
// vulnerability. Legitimate cross-origin navigation exists -- an OAuth
// authorisation server sending the user back to the client -- but it is narrow
// and specific, and an exception naming that route is narrower than leaving the
// whole class unchecked. So this half ships enabled.
var navigationParamNames = setOf(
	"redirect", "redirect_to", "redirecturl", "redirect_url", "redirect_uri",
	"redirection", "redirectionurl", "redir", "return", "return_url", "returnurl",
	"return_to", "returnto", "next", "next_url", "continue", "goto",
	"destination", "dest", "target_url", "forward", "forwardurl",
	"checkout_url", "success_url", "cancel_url", "login_redirect", "logout_redirect",
)

// fetchParamNames are parameter names whose value the *server* retrieves.
//
// An off-origin value here is SSRF -- or a webhook being registered, an avatar
// being imported, a feed being subscribed to, or a commenter typing their own
// homepage. Those are ordinary operations, and the request cannot tell them
// apart from the attack, because in both cases the application was handed a
// foreign URL on purpose.
//
// That is the Ownership test in CLAUDE.md §1: whether this application fetches
// user-supplied URLs by design is something the embedder knows and gwaf does
// not. So this half is opt-in, via SSRFParamRule. Enabling it by default was
// measured and rejected -- it blocked a webhook registration and a WordPress
// comment author's website field on the benign corpus, which is a working
// integration broken on somebody's first deploy.
var fetchParamNames = setOf(
	"url", "uri", "link", "fetch", "load", "proxy", "feed", "endpoint",
	"api_url", "source_url", "remote", "remote_url", "webhook", "image_url",
	"img_url", "avatar_url", "media_url", "file_url", "download_url", "import_url",
)

// matchesParam reports whether key names one of names, whole or as a
// separator-delimited part of a namespaced name.
//
// Map lookups over the key's own segments rather than a scan over every name.
// The rule's literal is "//", which appears in most URLs, so the prefilter makes
// this a candidate on a lot of ordinary values and it is reached far more often
// than it matches -- a loop over two dozen names cost 10% of the benign
// benchmarks. The key is short and its segments are few, so this is bounded by
// the key rather than by the vocabulary.
func matchesParam(key string, names map[string]bool) bool {
	if key == "" || len(key) > maxParamNameLen {
		return false
	}
	key = lowerASCII(key)
	// Array-style keys arrive as "header_links[]" from PHP-shaped forms.
	if n := len(key); n > 2 && key[n-2] == '[' && key[n-1] == ']' {
		key = key[:n-2]
	}
	if names[key] {
		return true
	}
	// Namespaced forms: "tb_redirect_fail" and "swp_url" carry the word as a
	// separator-delimited segment. Every suffix beginning at a separator is
	// checked, which covers both "swp_url" -> "url" and "x_return_url" ->
	// "return_url"; single segments are covered because a suffix of one segment
	// is a suffix.
	for i := 0; i < len(key); i++ {
		if key[i] != '_' && key[i] != '-' {
			continue
		}
		if names[key[i+1:]] {
			return true
		}
		// A segment in the middle: "tb_redirect_fail".
		for j := i + 1; j < len(key); j++ {
			if key[j] == '_' || key[j] == '-' {
				if names[key[i+1:j]] {
					return true
				}
				break
			}
		}
	}
	return false
}

// maxParamNameLen bounds the key this inspects. A destination parameter has a
// short name; anything longer is not one, and the bound keeps an
// attacker-supplied key from driving the segment scan.
const maxParamNameLen = 64

// offOriginURL matches an absolute destination in a sink-named parameter.
//
// This implements rules.Operator directly rather than wrapping op.Func, because
// op.Func's predicate sees only the value and the parameter name is half the
// evidence here.
func offOriginURL() rules.Operator { return offOriginOp{} }

// offOriginFetchURL is the SSRF half: the same comparison over the parameter
// names a server dereferences rather than the ones a browser is sent to.
func offOriginFetchURL() rules.Operator { return offOriginOp{fetch: true} }

type offOriginOp struct{ fetch bool }

func (o offOriginOp) Name() string {
	if o.fetch {
		return "off_origin_fetch_url"
	}
	return "off_origin_navigation_url"
}

func (o offOriginOp) Eval(ctx *rules.EvalContext, value []byte) (rules.Match, bool) {
	// Argument *names* are themselves a target, and a name is not a destination.
	if ctx == nil || ctx.Target.Kind == types.TargetArgNames {
		return rules.Match{}, false
	}
	names := navigationParamNames
	if o.fetch {
		names = fetchParamNames
	}
	if !matchesParam(ctx.Key, names) {
		return rules.Match{}, false
	}
	// No request host means no origin to compare against, and this rule ships
	// enabled: it must not block on absence of evidence. A destination cannot be
	// shown foreign without something to be foreign to, so it stands. The
	// net/http integration always supplies one; a caller driving the transaction
	// API by hand may not, and that is their traffic to describe, not ours to
	// guess at.
	if len(ctx.Host) == 0 {
		return rules.Match{}, false
	}
	host, ok := absoluteHostOf(value)
	if !ok {
		return rules.Match{}, false
	}
	// A destination on the site's own domain is the application navigating
	// itself, which is most of what these parameters carry. Only a foreign one
	// is the vulnerability.
	if sameSite(host, ctx.Host) {
		return rules.Match{}, false
	}
	return rules.WholeValue(value), true
}

// sameSite reports whether dest is the request's own host or a sibling under the
// same registrable domain.
//
// The comparison is a label-boundary suffix match rather than a public-suffix
// lookup, because core takes no third-party dependencies and the Public Suffix
// List is exactly that. The approximation errs toward *allowing* a sibling under
// a shared two-label suffix, which for a rule that ships enabled is the right
// direction: the failure is a miss, not somebody's login flow.
//
// An empty request host means the request carried none, and nothing can be shown
// same-site against nothing, so the destination stands as foreign.
func sameSite(dest, reqHost []byte) bool {
	if len(reqHost) == 0 || len(dest) == 0 {
		return false
	}
	self := stripPort(lowerBytes(reqHost))
	other := stripPort(lowerBytes(dest))
	if bytesEqual(self, other) {
		return true
	}
	a, b := registrable(self), registrable(other)
	return len(a) > 0 && bytesEqual(a, b)
}

// registrable returns the last two labels of a host, which approximates the
// registrable domain for the common single-suffix case ("example.com" from
// "shop.example.com"). A host with fewer than two labels has none.
func registrable(h []byte) []byte {
	dot := -1
	for i := len(h) - 1; i >= 0; i-- {
		if h[i] != '.' {
			continue
		}
		if dot < 0 {
			dot = i
			continue
		}
		return h[i+1:]
	}
	if dot < 0 {
		return nil
	}
	return h
}

// stripPort removes a trailing ":port". IPv6 literals are bracketed, so a colon
// inside brackets is part of the address and is left alone.
func stripPort(h []byte) []byte {
	if len(h) > 0 && h[len(h)-1] == ']' {
		return h
	}
	for i := len(h) - 1; i >= 0; i-- {
		switch h[i] {
		case ':':
			return h[:i]
		case ']':
			return h
		}
	}
	return h
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// lowerBytes lowercases ASCII in place-free fashion, returning the input when it
// is already lowercase so the common path allocates nothing.
func lowerBytes(b []byte) []byte {
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			out := make([]byte, len(b))
			copy(out, b)
			for j := range out {
				if out[j] >= 'A' && out[j] <= 'Z' {
					out[j] += 'a' - 'A'
				}
			}
			return out
		}
	}
	return b
}

// Literals is an honest assertion: every form this matches -- "scheme://host",
// "//host", and the backslash variants browsers normalise -- contains two
// adjacent slash-or-backslash bytes, so a value without one cannot match.
func (offOriginOp) Literals() ([]string, bool) {
	return []string{"://", `:\\`, `:/\`, `:\/`}, true
}

func (offOriginOp) Cost() types.Fuel { return types.CostLiteralMatch * 2 }

// absoluteHostOf returns the host of an absolute URL at the start of v:
// "scheme://host" or the protocol-relative "//host".
//
// Anchored at the start on purpose. A destination parameter holds a
// destination, not a sentence containing one, and anchoring is what keeps "see
// https://example.com for details" in a comment from reading as a redirect.
//
// Userinfo is skipped, because "https://shop.example.com@evil.tld/" points at
// evil.tld and reading the label before the '@' is the classic way a validator
// and an HTTP client disagree about where a URL goes.
func absoluteHostOf(v []byte) ([]byte, bool) {
	i := 0
	for i < len(v) && isSpaceByte(v[i]) {
		i++
	}
	// Backslashes are treated as slashes by browsers in the authority position:
	// "\/\/evil.tld" and "https:\\evil.tld" both navigate off-origin.
	norm := func(c byte) byte {
		if c == '\\' {
			return '/'
		}
		return c
	}
	for j := i; j < len(v); j++ {
		c := v[j]
		if c == ':' {
			if j+2 < len(v) && norm(v[j+1]) == '/' && norm(v[j+2]) == '/' {
				return hostAfter(v, j+3, norm)
			}
			break
		}
		if !isSchemeByte(c) {
			break
		}
	}
	if i+1 < len(v) && norm(v[i]) == '/' && norm(v[i+1]) == '/' {
		return hostAfter(v, i+2, norm)
	}
	return nil, false
}

// hostAfter returns the authority component starting at i, minus any userinfo.
func hostAfter(v []byte, i int, norm func(byte) byte) ([]byte, bool) {
	end := i
	for ; end < len(v); end++ {
		c := norm(v[end])
		if c == '/' || c == '?' || c == '#' {
			break
		}
	}
	auth := v[i:end]
	if len(auth) == 0 {
		return nil, false
	}
	// Userinfo: everything before the last '@' belongs to credentials, and the
	// host is what follows.
	for k := len(auth) - 1; k >= 0; k-- {
		if auth[k] == '@' {
			auth = auth[k+1:]
			break
		}
	}
	if len(auth) == 0 {
		return nil, false
	}
	return auth, true
}

func isSchemeByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'
}

func isSpaceByte(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

// lowerASCII lowercases a parameter name without allocating when it is already
// lowercase, which is the common case.
func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// SSRFParamRule reports an off-origin URL in a parameter the *server*
// dereferences: "url", "feed", "webhook", "image_url" and their namespaced
// forms.
//
// It is opt-in, and the reason is measured rather than cautious. Enabled by
// default it blocked a webhook registration and a WordPress comment author's
// website field on the benign corpus -- both ordinary operations, because
// handing an application a foreign URL to fetch is the entire point of those
// features. The request carries no evidence separating them from SSRF; only the
// embedder knows whether this application fetches user-supplied URLs by design,
// which is the Ownership test in CLAUDE.md §1.
//
// Enable it on an application that does not:
//
//	waf, err := gwaf.New(gwaf.WithRuleset(rules.Set{core.SSRFParamRule(1014)}))
//
// The navigation half of the same comparison -- "redirect_to", "next", "goto" --
// ships in the default set, because an application sending its own users to
// another origin has no ordinary reading.
func SSRFParamRule(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:    id,
		Phase: types.PhaseRequestHeaders,
		// Arguments only. This rule reads the parameter *name* as half its
		// evidence, so an unkeyed collection like the request URI can never
		// match it, and evaluating it there is pure cost.
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Transforms: decodeChain,
		Op:         offOriginFetchURL(),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityError,
		Confidence: types.High,
		Msg:        "Off-origin URL in a server-side fetch parameter",
		Tags:       []string{"ssrf", "owasp-a10"},
	}
}

// setOf builds a lookup set from a name list.
func setOf(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}
