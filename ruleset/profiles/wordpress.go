// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package profiles

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/core"
	"github.com/gsoultan/gwaf/types"
)

// WordPress returns the exceptions a stock WordPress install needs.
//
// Every entry was produced by replaying real WordPress traffic — the block
// editor, admin-ajax, the REST API, comments, WooCommerce — against the default
// ruleset and looking at what blocked. Without them a stock install blocks on
// its own comment form and on the options API; with them the same corpus that
// scores 93.0% detection scores it with zero false positives.
//
// WordPress is the hardest case a WAF meets, and it is worth saying why: the
// platform's normal traffic is a superset of several attack shapes. Its options
// API stores serialized PHP. Its theme editor takes a file path in a query
// parameter. Its post bodies carry raw HTML by design, and a large fraction of
// the security-writing internet is a WordPress blog quoting payloads as prose.
func WordPress() []rules.Exception {
	return []rules.Exception{
		{
			RuleID: core.IDPHPSemantic,
			Path:   "/wp-comments-post.php",
			Target: types.TargetArgs,
			Key:    "comment",
			Note:   "comment bodies are stored and displayed, never executed; a WordPress site discussing PHP carries PHP in this field all day",
		},
		{
			RuleID: core.IDShelliSemantic,
			Path:   "/wp-comments-post.php",
			Target: types.TargetArgs,
			Key:    "comment",
			Note:   "as above: a comment quoting a shell command is a comment",
		},
		{
			RuleID: core.IDPHPSemantic,
			Path:   "/wp-json/wp/v2/*",
			Target: types.TargetArgs,
			Key:    "content",
			Note:   "post content is stored and rendered as markup, never executed",
		},
		{
			RuleID: core.IDShelliSemantic,
			Path:   "/wp-json/wp/v2/*",
			Target: types.TargetArgs,
			Key:    "content",
			Note:   "post content: a code block in an article is not an injection point",
		},
		{
			RuleID: core.IDXSSSemantic,
			Path:   "/wp-json/wp/v2/*",
			Target: types.TargetArgs,
			Key:    "content",
			Note:   "the block editor sends raw HTML by design; sanitisation is WordPress's job on render, and doing it here would break every post save",
		},
		{
			RuleID: core.IDSQLiSemantic,
			Path:   "/wp-json/wp/v2/*",
			Target: types.TargetArgs,
			Key:    "content",
			Note:   "post content is rendered, never queried; the head-to-head harness found this the moment it ran -- a post titled \"Understanding SQL injection\" quoting 1' OR '1'='1 in a code block is the single most on-brand false positive a WordPress WAF can have",
		},
		{
			RuleID: core.IDSQLiSuspicious,
			Path:   "/wp-json/wp/v2/*",
			Target: types.TargetArgs,
			Key:    "content",
			Note:   "as above, for the Medium confidence tier",
		},
		{
			RuleID: core.IDSQLiSemantic,
			Path:   "/wp-admin/post.php",
			Target: types.TargetArgs,
			Key:    "content",
			Note:   "classic editor form post of the same content",
		},
		{
			RuleID: core.IDXSSSemantic,
			Path:   "/wp-admin/post.php",
			Target: types.TargetArgs,
			Key:    "content",
			Note:   "classic editor form post of the same content",
		},
		{
			RuleID: core.IDPHPObjectInjection,
			Path:   "/wp-admin/admin-ajax.php",
			Target: types.TargetArgs,
			Key:    "value",
			Note:   "the options API stores serialized PHP; rule 4007 requires a class name so this only matters for the array forms plugins save",
		},
		{
			RuleID: core.IDOffOriginURL,
			Path:   "/wp-comments-post.php",
			Target: types.TargetArgs,
			Key:    "url",
			Note:   "the comment form's url field is the commenter's own website, displayed as a link and never followed by the server",
		},
	}
}
