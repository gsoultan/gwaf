// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package signatures is an opt-in set of indicator rules: literal and regex
// matches for a named exploit, a tool, a file name or a keyword.
//
// # Why this is not in core
//
// core.Default detects by structure -- it parses the value as SQL, as shell, as
// a template -- and that is the technique gwaf exists to ship. A signature is
// the opposite trade: cheap, exact, and blind to anything it was not written
// for. Some things have no structure to parse, though. A request for
// "/goanywhere/licensing/accept" is CVE-2023-0669 because of what that path is,
// an upload named "report.lockbit" is ransomware staging because of what that
// extension is, and a header named "X-siis-session-id" is MOVEit because nothing
// else sends it. Those are indicators, and an indicator is a signature or it is
// nothing.
//
// The set also carries broader keyword rules -- "sleep(" in a parameter,
// "java.lang.Runtime" in a header -- that overlap the structural detectors and
// reach a little further at a real false-positive cost. Each says so in its
// confidence: the default minimum of High drops the Medium and Low entries, and
// an embedder that wants them raises nothing by accident.
//
// Nothing here loads unless it is asked for:
//
//	waf, err := gwaf.New(gwaf.WithRuleset(signatures.All()))
//
// # Where these came from
//
// gateon, gwaf's first embedder, carried this set in its own tree, and that was
// the wrong place for it: every rule answers "is this request an attack?" from
// the request alone, which is gwaf's question and not the embedder's. Moving
// them here is what lets a second embedder have them, and what lets one of them
// be deleted when a structural rule in core comes to cover everything it does.
// A replay of gwaf's own attack corpus found seven that core already covered in
// full; those were dropped and not moved.
//
// # Concurrency
//
// All and every rule it returns are safe for concurrent use. The operators are
// stateless after construction.
package signatures
