// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package rules

import "github.com/gsoultan/gwaf/types"

// Exception suppresses one rule in one place.
//
// Every WAF eventually needs one, because every ruleset eventually meets an
// application that legitimately sends something the ruleset calls an attack: a
// CMS whose users author Jinja templates, a paste bin that returns private
// keys, an API that publishes MongoDB operators as its filter DSL. The question
// is never whether exceptions exist — it is how *narrow* they can be made.
//
// gwaf answers that by making the narrow form the easy one. An Exception is a
// conjunction: every field that is set must match, and every field left zero
// matches anything. So the tightest possible suppression is also the most
// specific literal:
//
//	rules.Exception{RuleID: 7002, Path: "/api/v1/query", Key: "filter[$gt]"}
//
// and the widest is the one that looks widest:
//
//	rules.Exception{RuleID: 7002}
//
// This ordering is deliberate. A tuning API where the blunt instrument is
// shorter to type is a tuning API that produces blunt instruments, and the
// working agreement in CLAUDE.md §6 — "prefer deleting a rule over adding an
// exception to it" — only means anything if the exception someone writes is the
// smallest one that works.
//
// Decision.Explain().NarrowestException() computes exactly that for a finding
// that already happened, so an operator does not have to derive it by hand.
type Exception struct {
	// RuleID is the rule to suppress. Zero matches every rule, which is almost
	// never what anyone wants; set it.
	RuleID types.RuleID

	// Path suppresses only for requests whose path matches. A trailing "*"
	// makes it a prefix, so "/admin/*" covers a subtree.
	Path string

	// Target restricts the suppression to one collection — arguments, headers,
	// the body. Zero matches any.
	Target types.TargetKind

	// Key restricts it to one named value: a header name, an argument name, a
	// JSON field path. Empty matches any.
	Key string

	// Note records why. It is carried through to audit output, because an
	// exception with no rationale is indistinguishable from a mistake six
	// months later.
	Note string
}

// Matches reports whether this exception suppresses a finding.
//
// Conjunctive: a field left zero matches anything, and every field that is set
// must match. An Exception with nothing set matches everything, which is why
// Validate rejects it.
//
// derivedFrom is the ID the matched rule was generated from, if any. An
// exception against an authored rule covers its generated counterparts,
// because they are the same detection at another phase -- see Rule.DerivedFrom.
func (e Exception) Matches(rule, derivedFrom types.RuleID, path string, target types.Target, key string) bool {
	if e.RuleID != 0 && e.RuleID != rule && e.RuleID != derivedFrom {
		return false
	}
	if e.Target != types.TargetInvalid && e.Target != target.Kind {
		return false
	}
	if e.Key != "" && e.Key != key {
		return false
	}
	if e.Path != "" && !matchPath(e.Path, path) {
		return false
	}
	return true
}

// Validate reports whether the exception is specific enough to be meaningful.
func (e Exception) Validate() error {
	if e.RuleID == 0 && e.Path == "" && e.Target == types.TargetInvalid && e.Key == "" {
		return ErrExceptionTooBroad
	}
	return nil
}

// matchPath compares a pattern against a path, honouring a trailing "*".
func matchPath(pattern, path string) bool {
	if n := len(pattern); n > 0 && pattern[n-1] == '*' {
		prefix := pattern[:n-1]
		return len(path) >= len(prefix) && path[:len(prefix)] == prefix
	}
	return pattern == path
}

// Exceptions is a set of exceptions, checked as a whole.
type Exceptions []Exception

// Suppresses reports whether any exception covers this finding.
func (xs Exceptions) Suppresses(rule, derivedFrom types.RuleID, path string, target types.Target, key string) (Exception, bool) {
	for _, e := range xs {
		if e.Matches(rule, derivedFrom, path, target, key) {
			return e, true
		}
	}
	return Exception{}, false
}
