// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package leaks is an opt-in set of rules that find a secret where one should
// not be: a credential, a card number or a stack trace in a response, and a
// credential in a request.
//
// # Three sets, because they answer different questions
//
// Credentials is the response direction: a live API key, a card number or a
// database URL with its password, leaving the origin. Each credential is
// recognised by the prefix its issuer assigns, not by entropy, so a match is the
// credential and not a string that resembles one.
//
// Disclosure is the response direction too, and softer: a stack trace or a
// database error. It is Confidence Medium because some sites serve those on
// purpose, and the default minimum drops it.
//
// Inbound points the credential detectors at the request, and logs where the
// others block. A key pasted into a support ticket lands in a database, a
// backup and a search index; refusing the POST would not prevent that so much
// as hide it.
//
//	waf, err := gwaf.New(gwaf.WithRuleset(leaks.Credentials()))
//
// # What the response rules can see
//
// gwaf never buffers. A response rule inspects what the embedder passes to
// WriteResponseBody and nothing else, so an embedder that streams without
// passing the body gets no finding and no claim that the response was clean.
//
// core.Default already carries a private-key rule and coarse stack-trace and
// database-error rules for responses. Credentials does not repeat the first;
// Disclosure overlaps the other two and is the more specific of the pair.
//
// # Concurrency
//
// Every function here and every rule it returns is safe for concurrent use.
// The operators are stateless after construction.
package leaks
