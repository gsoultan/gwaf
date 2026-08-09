// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package profiles holds per-platform exception sets.
//
// # Why these exist
//
// gwaf's default ruleset is deliberately application-agnostic, and a handful of
// its rules are correct in general and wrong for one specific platform. That is
// not a defect in the rule. A WordPress comment field carrying
// "<?php echo $name; ?>" really is PHP; a Jira issue quoting "1' OR '1'='1"
// really is SQL injection. They are benign because of *where they land* — a
// field that is stored and displayed, never executed — and where a value lands
// is knowledge the application has and gwaf does not.
//
// Reading the bytes harder cannot recover it, because the bytes are the attack.
// Weakening the rule was measured and rejected: demoting the PHP open-tag signal
// removed the false positive and also dropped 32 real exploits, taking RCE from
// 84% to 43% and upload webshells from 100% to 40%. The narrow form costs
// nothing — the same corpus run with these profiles applied detects exactly what
// it detected without them.
//
// # What a profile is not
//
// It is not a "compatibility mode" and it does not turn rules off. Every entry
// names a rule, a path, a target and a field, and carries a Note saying why.
// An exception with no rationale is indistinguishable from a mistake six months
// later, which is why Exception.Note exists and why nothing here omits it.
//
// A profile is a starting point, not an audit. It covers the traffic the
// platform generates out of the box; a plugin, a theme or a custom endpoint can
// carry its own, and finding those is what detection-only mode is for.
//
// # Using one
//
//	waf, err := gwaf.New(gwaf.WithExceptions(profiles.WordPress()...))
//
// Profiles compose: an application running WordPress behind a Laravel API can
// pass both, because exceptions are scoped by path and a path belongs to one
// platform.
package profiles
