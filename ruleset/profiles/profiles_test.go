// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package profiles_test

import (
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/profiles"
)

// TestEveryExceptionIsScopedAndExplained is the invariant that keeps a profile
// from becoming a compatibility mode. An exception with no rule is a switch, one
// with no path is site-wide, and one with no note is indistinguishable from a
// mistake six months later.
func TestEveryExceptionIsScopedAndExplained(t *testing.T) {
	for name, set := range map[string][]rules.Exception{
		"WordPress":    profiles.WordPress(),
		"Drupal":       profiles.Drupal(),
		"Laravel":      profiles.Laravel(),
		"IssueTracker": profiles.IssueTracker(),
	} {
		if len(set) == 0 {
			t.Errorf("%s: empty profile", name)
		}
		for i, x := range set {
			if err := x.Validate(); err != nil {
				t.Errorf("%s[%d]: %v", name, i, err)
			}
			if x.RuleID == 0 {
				t.Errorf("%s[%d]: no rule -- that suppresses everything", name, i)
			}
			if x.Path == "" {
				t.Errorf("%s[%d] rule %d: no path -- an exception the whole site pays for", name, i, x.RuleID)
			}
			if x.Key == "" {
				t.Errorf("%s[%d] rule %d: no key -- every field on the route is exempt", name, i, x.RuleID)
			}
			if len(strings.TrimSpace(x.Note)) < 20 {
				t.Errorf("%s[%d] rule %d: note is missing or too short to be a reason: %q",
					name, i, x.RuleID, x.Note)
			}
		}
	}
}

// TestProfileFixesFalsePositivesWithoutWeakeningDetection is the claim the whole
// package rests on: scoping costs nothing.
//
// The benign half is traffic a stock WordPress install generates and the default
// ruleset blocks. The attack half is the same payloads one field over and one
// path over -- if the exception leaked to either, it would be a switch wearing a
// scope.
func TestProfileFixesFalsePositivesWithoutWeakeningDetection(t *testing.T) {
	base, err := gwaf.New(gwaf.WithOrigins("blog.example.com"))
	if err != nil {
		t.Fatalf("gwaf.New(): %v", err)
	}
	// WithOrigins is required for the off-origin rule to say anything at all --
	// without a declared origin it cannot show any destination is foreign, which
	// is the fix for the v0.4.0 Host-header bypass.
	tuned, err := gwaf.New(
		gwaf.WithExceptions(profiles.WordPress()...),
		gwaf.WithOrigins("blog.example.com"),
	)
	if err != nil {
		t.Fatalf("gwaf.New(profile): %v", err)
	}

	send := func(w *gwaf.WAF, path, field, value string) bool {
		tx := w.NewTransaction()
		defer tx.Close()
		tx.SetRequestLine("POST", path, "HTTP/1.1")
		tx.SetRemoteAddr("192.0.2.1")
		tx.AddRequestHeader("Host", "blog.example.com")
		tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
		tx.AddArgument(field, value)
		if d := tx.ProcessRequestHeaders(); d.Blocked() {
			return true
		}
		return tx.ProcessRequestBody().Blocked()
	}

	benign := []struct{ path, field, value, why string }{
		{"/wp-comments-post.php", "comment", "In PHP you write <?php echo $name; ?> to print a variable", "comment quoting PHP"},
		{"/wp-comments-post.php", "comment", "run `tar -czf backup.tgz /var/www && echo done` to archive it", "comment quoting a shell command"},
		{"/wp-comments-post.php", "url", "https://bob.example.com", "the commenter's own website"},
		{"/wp-json/wp/v2/posts/1", "content", "<!-- wp:code --><pre><code>SELECT * FROM users WHERE id = 1 OR 1=1--</code></pre>", "a post about SQL injection"},
		{"/wp-json/wp/v2/posts/1", "content", "<!-- wp:paragraph --><p>Hello <strong>world</strong></p>", "ordinary block markup"},
	}
	for _, c := range benign {
		if !send(base, c.path, c.field, c.value) {
			t.Logf("note: default ruleset already allows %q -- the exception is redundant but harmless", c.why)
			continue
		}
		if send(tuned, c.path, c.field, c.value) {
			t.Errorf("profile did not clear the false positive: %s", c.why)
		}
	}

	// The same payloads where they are attacks. None of these may be suppressed.
	attacks := []struct{ path, field, value, why string }{
		{"/wp-comments-post.php", "author", "<?php system($_GET['c']); ?>", "same route, different field"},
		{"/wp-admin/admin-ajax.php", "comment", "<?php system($_GET['c']); ?>", "same field, different route"},
		{"/wp-json/wp/v2/posts/1", "title", "<script>alert(1)</script>", "post title is not post content"},
		{"/wp-comments-post.php", "redirect_to", "https://evil.tld/", "off-origin redirect is not the comment url field"},
	}
	for _, c := range attacks {
		if !send(tuned, c.path, c.field, c.value) {
			t.Errorf("exception leaked: %s (%s %s=%q)", c.why, c.path, c.field, c.value)
		}
	}
}
