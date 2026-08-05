// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import "fmt"

// The CMS archetype: an application whose users author templates on purpose.
//
// This is the sharpest false-positive risk in the whole ruleset and the reason
// detect/ssti ships at High rather than Certain. A headless CMS, an email-
// campaign builder, a documentation site, a notification service — all of them
// accept template syntax as *content*, because rendering that syntax is the
// product. `{{ user.first_name }}` in a subject line is not an attack; it is
// the feature.
//
// The detector's design says the delimiters are worth nothing and only what
// sits inside them scores. This archetype is what tests that claim against
// something other than the detector author's imagination: every value here is
// template syntax a real editor would save, including the awkward ones —
// filters, loops, conditionals, nested access, and expressions that mention
// `config` and `request` without walking into them.
func emitCMS(emit func(request)) {
	// Template bodies people actually write, by engine.
	templates := []string{
		// Handlebars / Mustache.
		"Hello {{name}}, your order {{order.id}} shipped.",
		"{{#each items}}<li>{{this.title}} — {{this.price}}</li>{{/each}}",
		"{{#if premium}}Thanks for subscribing!{{else}}Upgrade today{{/if}}",
		"{{> header}}{{content}}{{> footer}}",
		"{{formatDate created_at 'YYYY-MM-DD'}}",

		// Liquid (Shopify, Jekyll).
		"{{ product.title | upcase }}",
		"{{ price | times: 100 | round }}",
		"{% for item in cart.items %}{{ item.sku }}{% endfor %}",
		"{% if customer.tags contains 'vip' %}VIP{% endif %}",
		"{{ 'now' | date: '%Y-%m-%d' }}",

		// Jinja / Twig, used as a template rather than as an escape.
		"{% for row in rows %}{{ row.id }}: {{ row.name }}{% endfor %}",
		"{{ user.email|default('none') }}",
		"{% block content %}{{ super() }}{% endblock %}",
		"{{ items|length }} results",
		"{% macro field(name) %}<input name=\"{{ name }}\">{% endmacro %}",

		// Angular / Vue interpolation stored as content.
		"{{ item.price | currency:'USD' }}",
		"{{ user.firstName }} {{ user.lastName }}",
		"{{ count }} of {{ total }}",
		"{{ isActive ? 'on' : 'off' }}",

		// ERB and Ruby interpolation in a docs page.
		"<%= link_to 'Home', root_path %>",
		"<%= @user.email %>",
		"<% if signed_in? %>Welcome<% end %>",
		`puts "hello #{name}"`,
		"#{Time.now.year}",

		// i18n catalogues, where braces are the entire feature.
		"{{count}} items remaining",
		"You have {{n}} unread {{n, plural, one {message} other {messages}}}",
		"Willkommen {{vorname}}!",
		"{{user}} さんの注文",

		// Values naming a framework object without walking into it, which the
		// detector must treat as ordinary.
		"{{ config }}",
		"{{ request }}",
		"See the config section for details",
		"The request object is documented at /docs/api",

		// Arithmetic that is a template rather than a probe.
		"{{ 2 * count }}",
		"{{ subtotal * tax_rate }}",
		"{{ total / items.length }}",
	}

	surfaces := []struct{ method, path, field string }{
		{"POST", "/api/v1/templates", "body"},
		{"PUT", "/api/v1/templates/tpl-042", "body"},
		{"POST", "/api/v1/campaigns/email", "subject"},
		{"POST", "/api/v1/notifications/templates", "message"},
		{"PUT", "/api/v1/pages/landing/blocks/hero", "html"},
		{"POST", "/api/v1/snippets", "content"},
		{"PATCH", "/api/v1/themes/default/layout", "source"},
		{"POST", "/api/v1/i18n/en-GB/strings", "value"},
	}

	for i, t := range templates {
		for j, s := range surfaces {
			for k, loc := range cmsLocales {
				emit(request{
					Name:   fmt.Sprintf("template %d on %s loc%d", i, s.path, k),
					Method: s.method,
					Target: s.path + "?locale=" + loc,
					Args:   map[string]string{"locale": loc},
					Headers: map[string]string{
						"Content-Type": "application/json",
						"User-Agent":   cmsAgents[(i+j+k)%len(cmsAgents)],
					},
					Body: fmt.Sprintf(`{%q:%q,"locale":%q,"draft":%v}`,
						s.field, t, loc, k%2 == 0),
				})
			}
			emit(request{
				Name:   fmt.Sprintf("template %d on %s", i, s.path),
				Method: s.method,
				Target: s.path,
				Headers: map[string]string{
					"Content-Type":  "application/json",
					"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlZGl0b3IifQ.sig",
					"User-Agent":    cmsAgents[(i+j)%len(cmsAgents)],
				},
				Body: fmt.Sprintf(`{%q:%q,"locale":%q,"draft":true}`,
					s.field, t, cmsLocales[(i+j)%len(cmsLocales)]),
			})
		}
	}

	// Rich-text content: markup a user typed on purpose, which is the XSS
	// detector's counterweight rather than the SSTI one.
	richText := []string{
		"<p>Hello <strong>world</strong></p>",
		"<h2>Getting started</h2><p>Run <code>npm install</code> first.</p>",
		"<ul><li>One</li><li>Two</li></ul>",
		"<blockquote>He said &quot;yes&quot;</blockquote>",
		"<a href=\"/docs/api\">API reference</a>",
		"<img src=\"/uploads/hero.png\" alt=\"Hero image\">",
		"<table><tr><td>a &lt; b</td></tr></table>",
		"Use the <code>&lt;script&gt;</code> tag to embed JavaScript.",
		"<p>if (a &lt; b) { return a; }</p>",
		"<pre>SELECT * FROM orders WHERE id = 1</pre>",
	}
	for i, r := range richText {
		emit(request{
			Name:   fmt.Sprintf("rich text %d", i),
			Method: "PUT",
			Target: fmt.Sprintf("/api/v1/articles/%d/content", 100+i),
			Headers: map[string]string{
				"Content-Type": "application/json",
				"User-Agent":   cmsAgents[i%len(cmsAgents)],
			},
			Body: fmt.Sprintf(`{"html":%q,"status":"draft"}`, r),
		})
	}

	// Editors searching their own content, which is where template syntax and
	// markup arrive as query arguments rather than bodies.
	for i, t := range templates[:20] {
		emit(request{
			Name:    fmt.Sprintf("search templates %d", i),
			Target:  "/api/v1/templates?q=" + urlEncode(t),
			Args:    map[string]string{"q": t},
			Headers: map[string]string{"User-Agent": cmsAgents[i%len(cmsAgents)]},
		})
	}

	// Media library paths, which carry dots and slashes traversal rules see.
	media := []string{
		"/uploads/2026/01/hero-image.png", "/uploads/docs/q4-report.v2.pdf",
		"/assets/fonts/Inter-Regular.woff2", "/uploads/user.avatar.jpg",
		// No "../" here on purpose. An earlier version listed
		// "/assets/../assets/logo.svg" as benign and calibration duly reported
		// rule 1001 over its ceiling -- but a relative traversal arriving in a
		// media endpoint's path parameter is the local-file-inclusion vector,
		// not ordinary traffic. The corpus entry was mislabelled, so it was
		// removed rather than the rule loosened.
		"/uploads/team/o'brien-headshot.jpg", "/uploads/2025/12/année-photo.jpg",
	}
	for i, m := range media {
		emit(request{
			Name:    fmt.Sprintf("media %d", i),
			Target:  "/api/v1/media?path=" + urlEncode(m),
			Args:    map[string]string{"path": m},
			Headers: map[string]string{"User-Agent": cmsAgents[i%len(cmsAgents)]},
		})
	}
}

var cmsAgents = []string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"contentful-cli/3.1.2",
	"strapi-admin/4.20.0",
	"Go-http-client/2.0",
}

var cmsLocales = []string{"en-GB", "en-US", "de-DE", "fr-FR", "ja-JP", "id-ID"}
