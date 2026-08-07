// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import (
	"fmt"
	"net/url"
)

// emitAdjacent emits benign traffic that sits deliberately close to a rule
// added in the SSRF / deserialization / Log4j pass.
//
// Every other archetype models an application and happens to exercise the
// ruleset. This one is the reverse: each request exists because a specific rule
// could plausibly match it, and the corpus is the only thing standing between a
// rule that detects an attack and a rule that detects a customer.
//
// That distinction is what killed "ldap://" and "jar:" from the SSRF scheme
// rule and "${env:" from the Log4j rule during review. Those literals matched
// nothing in the 10,386 requests that existed at the time, which proved only
// that the corpus had never seen an identity integration or a Java build. The
// requests below are that missing traffic, so the next person to widen one of
// these rules finds out from a failing build rather than from an incident.
func emitAdjacent(emit func(request)) {
	json := func(name, target, body string) {
		emit(request{Name: name, Method: "POST", Target: target,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    body})
	}

	// Directory integrations. "ldap://" is a real SSRF vector and also exactly
	// what an identity API stores when someone connects Active Directory.
	hosts := []string{"ldap.corp.example.com", "dc01.internal.example.net", "ad.example.org"}
	for i, h := range hosts {
		json(fmt.Sprintf("ldap integration %d", i+1), "/api/v1/integrations",
			fmt.Sprintf(`{"kind":"ldap","url":"ldap://%s:389","base_dn":"dc=corp,dc=example","bind_user":"svc-directory"}`, h))
		json(fmt.Sprintf("ldaps integration %d", i+1), "/api/v1/integrations",
			fmt.Sprintf(`{"kind":"ldaps","url":"ldaps://%s:636","verify_tls":true}`, h))
	}

	// Configuration placeholders. Log4j's lookup syntax is also the syntax half
	// the configuration-management world uses for variable interpolation.
	for i, v := range []string{"${env:HOME}", "${sys:user.region}", "${DB_PASSWORD}", "${{ matrix.os }}"} {
		json(fmt.Sprintf("config placeholder %d", i+1), "/api/v1/config",
			fmt.Sprintf(`{"key":"setting_%d","value":%q}`, i+1, v))
	}

	// Java build artifacts. "jar:" URLs are routine in CI output.
	for i := 1; i <= 3; i++ {
		json(fmt.Sprintf("build artifact %d", i), "/api/v1/builds",
			fmt.Sprintf(`{"artifact":"jar:file:///opt/build/app-%d.jar!/META-INF/MANIFEST.MF","status":"success"}`, i))
	}

	// Loopback targets. This is why LoopbackSSRFRule is opt-in rather than core:
	// a webhook registered against a development tunnel is ordinary traffic.
	for i, u := range []string{
		"http://localhost:3000/hooks/github",
		"http://127.0.0.1:8080/callback",
		"http://0.0.0.0:9000/health",
	} {
		json(fmt.Sprintf("dev webhook %d", i+1), "/api/v1/webhooks",
			fmt.Sprintf(`{"url":%q,"events":["push","pull_request"],"active":true}`, u))
	}

	// Twig macro imports. "_self" is idiomatic; "_self.env" is the escape.
	for i, t := range []string{
		`{% import _self as forms %}{{ forms.input('name') }}`,
		`{% macro input(name) %}<input name="{{ name }}">{% endmacro %}`,
		`{{ user.displayName|escape }} joined {{ team.name }}`,
	} {
		json(fmt.Sprintf("template body %d", i+1), "/api/v1/templates",
			fmt.Sprintf(`{"slug":"tpl-%d","body":%q}`, i+1, t))
	}

	// Prose that names the vocabulary without being it.
	for i, s := range []string{
		"The constructor takes a prototype object as its argument.",
		"We are migrating the PHP service to Go this quarter.",
		"See the deserialization notes before touching the session store.",
		"Metadata for the instance is in the runbook, not in the request.",
	} {
		json(fmt.Sprintf("engineering note %d", i+1), "/api/v1/notes",
			fmt.Sprintf(`{"text":%q,"author_id":%d}`, s, 100+i))
	}

	// Base64 payloads that are not serialized objects. A five-character prefix
	// match on "rO0AB" is only safe because it is anchored; these are the
	// traffic that would find out if the anchor were ever dropped.
	for i, b := range []string{
		"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
		"JVBERi0xLjQKJcfsj6IKNSAwIG9iago8PC9MZW5ndGggNiAwIFI+PgpzdHJlYW0K",
		"UEsDBBQAAAAIAJ1jV1cAAAAAAAAAAAAAAAAJAAAAbWV0YS54bWw=",
	} {
		json(fmt.Sprintf("binary upload %d", i+1), "/api/v1/attachments",
			fmt.Sprintf(`{"filename":"file-%d.bin","data":%q}`, i+1, b))
	}

	// File-storage traffic. This is the archetype the corpus did not have when
	// IDBackupArtifact was written, and its absence is exactly why that rule
	// ships at High while IDExposedArtifact ships at Certain: nobody serves
	// "/.git/config" deliberately, but "notes.bak" is a file somebody saved.
	for i, f := range []string{
		"quarterly-notes.bak", "schema-2026.sql", "draft.old",
		"budget.orig", "session.save", "export.dump",
	} {
		emit(request{Name: fmt.Sprintf("stored file %d", i+1), Method: "GET",
			Target: fmt.Sprintf("/api/v1/files/%s", f)})
	}

	// A multi-line text field. The CRLF rule matches a break *followed by a
	// header name*, and these are the ordinary newlines that prove a bare break
	// is not enough on its own.
	for i, t := range []string{
		"Line one.\nLine two.\nRegards,\nSam",
		"Steps:\r\n1. open the app\r\n2. tap settings\r\n3. sign out",
		"Address:\n12 Example Street\nSuite 4\nExampleton",
	} {
		json(fmt.Sprintf("multiline note %d", i+1), "/api/v1/notes",
			fmt.Sprintf(`{"text":%q,"author_id":%d}`, t, 300+i))
	}

	// URLs in parameters that are not remote file inclusion. The RFI predicate
	// needs a scheme *and* a script extension, and these have only the scheme.
	for i, u := range []string{
		"https://cdn.example.com/avatars/u1.png",
		"https://hooks.example.com/callback?id=9",
		"https://docs.example.com/guide/index.html",
	} {
		json(fmt.Sprintf("callback url %d", i+1), "/api/v1/integrations",
			fmt.Sprintf(`{"kind":"webhook","target":%q}`, u))
	}

	// Java and PHP vocabulary in prose, which the expression-language and
	// dynamic-eval rules must not read as an expression.
	for i, t := range []string{
		"The report runs java.lang.String.format on every row.",
		"We removed the last create_function call during the PHP 8 upgrade.",
		"Jackson needs default typing disabled; see the deserialization ticket.",
	} {
		json(fmt.Sprintf("technical note %d", i+1), "/api/v1/notes",
			fmt.Sprintf(`{"text":%q,"author_id":%d}`, t, 400+i))
	}

	// URL-encoded text containing "../".
	//
	// This is what every browser form, every JS client, and curl produce for a
	// value holding a relative path: "/" becomes "%2F" while "." is left alone.
	// Rule 1001 matched "..%2f" and turned that into a critical block. The
	// corpus had the same prose in a JSON body, where no encoding happens, so
	// the shape was invisible until a pentest control sent it as a query value.
	for i, v := range []string{
		"see ../shared/2026/q3-summary.pdf for details",
		"the file lives at ../docs/readme.md in the repo",
		"move it to ../archive/2025 when you are done",
	} {
		emit(request{Name: fmt.Sprintf("encoded relative path %d", i+1), Method: "GET",
			Target: "/api/v1/search?q=" + urlValue(v)})
	}

	// Colon-separated values that are not PHP serialization. The predicate
	// requires a digit run and the right delimiter, and these are what would
	// notice if that ever loosened into "contains a colon".
	for i, v := range []string{
		"a:2 ratio applies to the b:3 column",
		"o:1 is the override flag; s:4 is the shard",
		"timestamp 12:04:59, offset +07:00",
	} {
		json(fmt.Sprintf("notation note %d", i+1), "/api/v1/notes",
			fmt.Sprintf(`{"text":%q,"author_id":%d}`, v, 200+i))
	}
}

// urlValue encodes a value the way a browser form or an HTTP client does: "/"
// becomes "%2F" and "." is left alone. That asymmetry is exactly why "..%2f"
// cannot be treated as evasion.
func urlValue(s string) string { return url.QueryEscape(s) }
