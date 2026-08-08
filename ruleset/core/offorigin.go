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
// # Why this is one rule and not two
//
// Open redirect and server-side request forgery are the same request-side
// signal. The request carries a destination the attacker chose; the only
// difference is who dereferences it, the browser or the server. Replaying real
// WordPress CVEs, 27 of 70 remaining exploits were this exact shape and split
// evenly across the two labels -- "redirect=http://interact.sh" and
// "url=http://oast.example.com" are indistinguishable until something follows
// them.
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
// # Why it is opt-in
//
// A cross-origin destination is exactly what OAuth authorisation, payment
// gateway returns, and SSO flows send: "redirect_uri=https://app.example.com/cb"
// is the protocol working. gwaf cannot tell that from an attack using only the
// request, because the difference is whether the destination is one the operator
// trusts -- and the allow-list of trusted destinations is the embedder's, which
// puts this on the Policy side of the line in CLAUDE.md §1. Shipping it in the
// default set would block a working login flow on somebody's first deploy, so
// it is enabled deliberately:
//
//	waf, err := gwaf.New(gwaf.WithRuleset(append(core.Default(), core.OffOriginURLRule(1011))))
//
// The precise form needs the request's own Host to compare against, so that a
// destination on the site's own domain passes and only genuinely foreign ones
// fire. rules.EvalContext carries only Target and Key today, so an operator
// cannot see the Host header; widening that struct is the right fix and is a
// deliberate change to a frozen extension point rather than something to slip
// into a rule. Until then this fires on any absolute destination, which is why
// it is opt-in rather than merely low-confidence.
func OffOriginURLRule(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:      id,
		Phase:   types.PhaseRequestHeaders,
		Targets: argTargets,
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

// sinkParamNames are parameter names whose value the application follows.
//
// Enumerated rather than pattern-matched because the cost of a wrong entry is a
// blocked request: "author_url" and "site_url" hold URLs that are displayed, not
// followed, and must not be here. Matching is whole-word or underscore-suffix,
// so "return_url" hits and "author_url" does not.
var sinkParamNames = []string{
	"redirect", "redirect_to", "redirecturl", "redirect_url", "redirect_uri",
	"redirection", "redirectionurl", "redir", "return", "return_url", "returnurl",
	"return_to", "returnto", "next", "next_url", "continue", "goto", "target_url",
	"destination", "dest", "callback", "callback_url", "forward", "forwardurl",
	"url", "uri", "link", "fetch", "load", "proxy", "feed", "endpoint",
	"api_url", "source_url", "remote", "remote_url", "webhook", "image_url",
}

// isSinkParam reports whether key names a destination the application follows.
func isSinkParam(key string) bool {
	if key == "" {
		return false
	}
	// The transform chain lowercases values, not keys, and "URL" is as common a
	// parameter name as "url".
	key = lowerASCII(key)
	// Array-style keys arrive as "header_links[]" from PHP-shaped forms.
	if n := len(key); n > 2 && key[n-2] == '[' && key[n-1] == ']' {
		key = key[:n-2]
	}
	for _, n := range sinkParamNames {
		if key == n {
			return true
		}
		// A suffix after '_' or '-' is the same word in a namespaced parameter:
		// "tb_redirect_fail" and "swp_url" are destinations. The separator is
		// required so "author_url" -- a displayed profile field -- does not
		// match "url" while "return_url" does.
		if len(key) > len(n)+1 {
			i := len(key) - len(n)
			if key[i:] == n && (key[i-1] == '_' || key[i-1] == '-') {
				// Names that hold a URL for display rather than for following.
				switch key[:i-1] {
				case "author", "site", "home", "avatar", "gravatar", "profile", "blog":
					return false
				}
				return true
			}
		}
		// Prefixed forms: "redirect_to" already listed, but "tb_redirect_fail"
		// carries the sink word in the middle of a namespaced name.
		if len(n) >= 6 && containsWord(key, n) {
			return true
		}
	}
	return false
}

// containsWord reports whether key contains n delimited by '_' or '-'.
func containsWord(key, n string) bool {
	for i := 0; i+len(n) <= len(key); i++ {
		if key[i:i+len(n)] != n {
			continue
		}
		beforeOK := i == 0 || key[i-1] == '_' || key[i-1] == '-'
		j := i + len(n)
		afterOK := j == len(key) || key[j] == '_' || key[j] == '-'
		if beforeOK && afterOK {
			return true
		}
	}
	return false
}

// offOriginURL matches an absolute destination in a sink-named parameter.
//
// This implements rules.Operator directly rather than wrapping op.Func, because
// op.Func's predicate sees only the value and the parameter name is half the
// evidence here.
func offOriginURL() rules.Operator { return offOriginOp{} }

type offOriginOp struct{}

func (offOriginOp) Name() string { return "off_origin_url" }

func (offOriginOp) Eval(ctx *rules.EvalContext, value []byte) (rules.Match, bool) {
	// Argument *names* are themselves a target, and a name is not a destination.
	if ctx == nil || ctx.Target.Kind == types.TargetArgNames || !isSinkParam(ctx.Key) {
		return rules.Match{}, false
	}
	if hasAbsoluteHost(value) {
		return rules.WholeValue(value), true
	}
	return rules.Match{}, false
}

// Literals is an honest assertion: every form this matches -- "scheme://host",
// "//host", and the backslash variants browsers normalise -- contains two
// adjacent slash-or-backslash bytes, so a value without one cannot match.
func (offOriginOp) Literals() ([]string, bool) {
	return []string{"//", `\\`, `/\`, `\/`}, true
}

func (offOriginOp) Cost() types.Fuel { return types.CostLiteralMatch * 2 }

// hasAbsoluteHost reports whether v begins with an absolute URL carrying a host:
// "scheme://host" or the protocol-relative "//host".
//
// Anchored at the start on purpose. A destination parameter holds a destination,
// not a sentence containing one, and anchoring is what keeps "see
// https://example.com for details" in a comment from reading as a redirect.
func hasAbsoluteHost(v []byte) bool {
	i := 0
	for i < len(v) && isSpaceByte(v[i]) {
		i++
	}
	// Backslashes are treated as slashes by browsers in the authority position:
	// "\\/\\/evil.tld" and "https:\\\\evil.tld" both navigate off-origin.
	norm := func(c byte) byte {
		if c == '\\' {
			return '/'
		}
		return c
	}
	// scheme://
	for j := i; j < len(v); j++ {
		c := v[j]
		if c == ':' {
			if j+2 < len(v) && norm(v[j+1]) == '/' && norm(v[j+2]) == '/' {
				return hasHostAfter(v, j+3, norm)
			}
			break
		}
		if !isSchemeByte(c) {
			break
		}
	}
	// protocol-relative //host
	if i+1 < len(v) && norm(v[i]) == '/' && norm(v[i+1]) == '/' {
		return hasHostAfter(v, i+2, norm)
	}
	return false
}

// hasHostAfter reports whether a non-empty host follows the authority marker.
func hasHostAfter(v []byte, i int, norm func(byte) byte) bool {
	n := 0
	for ; i < len(v); i++ {
		c := norm(v[i])
		if c == '/' || c == '?' || c == '#' {
			break
		}
		n++
	}
	return n > 0
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
