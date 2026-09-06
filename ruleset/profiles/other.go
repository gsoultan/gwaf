// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package profiles

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/core"
	"github.com/gsoultan/gwaf/types"
)

// Drupal returns the exceptions a stock Drupal install needs.
//
// Drupal's shape is close enough to WordPress's to share the cause and
// different enough to need its own paths: node bodies carry raw markup, the
// JSON:API accepts the same content through a different route, and the
// configuration export endpoint returns YAML that contains anything a site
// administrator put in it.
func Drupal() []rules.Exception {
	return []rules.Exception{
		{
			RuleID: core.IDXSSSemantic,
			Path:   "/node/*",
			Target: types.TargetArgs,
			Key:    "body[0][value]",
			Note:   "node bodies carry raw markup; Drupal filters on render by text format",
		},
		{
			RuleID: core.IDShelliSemantic,
			Path:   "/node/*",
			Target: types.TargetArgs,
			Key:    "body[0][value]",
			Note:   "a code block in an article body is not an injection point",
		},
		{
			RuleID: core.IDPHPSemantic,
			Path:   "/node/*",
			Target: types.TargetArgs,
			Key:    "body[0][value]",
			Note:   "documentation nodes quote PHP; Drupal has not evaluated body PHP since 8.0",
		},
		{
			RuleID: core.IDXSSSemantic,
			Path:   "/jsonapi/*",
			Target: types.TargetArgs,
			Key:    "body",
			Note:   "the same content through JSON:API",
		},
	}
}

// Laravel returns the exceptions a typical Laravel application needs.
//
// Laravel itself transports far less attack-shaped text than a CMS, so this is
// short by design. What it does carry is a report/filter DSL in several popular
// packages, where a query fragment in a parameter is the feature rather than the
// bug.
func Laravel() []rules.Exception {
	return []rules.Exception{
		{
			RuleID: core.IDSQLiSemantic,
			Path:   "/api/*/reports",
			Target: types.TargetArgs,
			Key:    "query",
			Note:   "report builders accept a filter fragment by design; scope this to the routes that actually have one rather than leaving it site-wide",
		},
		{
			RuleID: core.IDSQLiSuspicious,
			Path:   "/api/*/reports",
			Target: types.TargetArgs,
			Key:    "query",
			Note:   "as above, for the lower-confidence tier",
		},
	}
}

// IssueTracker returns the exceptions an application whose purpose is to
// transport attack text needs — a bug tracker, a paste service, a code-snippet
// host, a security wiki.
//
// This is the one profile that is a category rather than a product, because the
// category is what matters: these applications exist to store the exact strings
// a WAF is built to block, and no request-level signal separates a payload being
// reported from a payload being delivered. The paths are examples and are meant
// to be edited; what is not negotiable is that such a field needs an exception
// rather than a weaker ruleset.
func IssueTracker() []rules.Exception {
	const note = "this application stores attack payloads as content by design; the field is displayed, never executed or queried"
	out := make([]rules.Exception, 0, 16)
	for _, r := range []types.RuleID{
		core.IDXSSSemantic, core.IDSQLiSemantic, core.IDShelliSemantic, core.IDPHPSemantic,

		// The Medium tier of the same four detections.
		//
		// These live in their own 5xxx band so that an exception written against
		// a default-tier rule can never accidentally silence the opt-in one --
		// which is exactly why a profile has to name them, and why exempting only
		// the semantic rules left this one half applied. An embedder running a
		// paste service at paranoia 2 still had a Rails backtrace, a pasted regex
		// and an HTML template refused, by 5010 and 5011, while the rules they
		// mirror were already exempt.
		//
		// The direction is the point: a lower bar fires more readily on prose, so
		// on an application whose purpose is to store attack text the Medium tier
		// is the *more* likely of the two to refuse the page, not the less.
		core.IDXSSSuspicious, core.IDSQLiSuspicious, core.IDShelliSuspicious,
		core.IDPHPSuspicious,
	} {
		for _, k := range []string{"description", "body"} {
			out = append(out, rules.Exception{
				RuleID: r, Path: "/rest/api/*", Target: types.TargetArgs, Key: k, Note: note,
			})
		}
	}
	return out
}
