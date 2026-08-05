// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package types

import "strings"

// TargetKind names a collection of request or response values a rule can
// inspect.
type TargetKind uint8

// Target kinds. The zero value is invalid so a forgotten field is a compile-time
// validation error rather than a rule that silently inspects the wrong data.
const (
	TargetInvalid TargetKind = iota

	TargetRequestMethod
	TargetRequestURI      // full request target, including query
	TargetRequestPath     // path only, query stripped
	TargetRequestProtocol // e.g. HTTP/1.1
	TargetRequestHeaders  // header values
	TargetRequestHeaderNames
	TargetArgs // query and body arguments, merged
	TargetArgNames
	TargetArgsGet // query arguments only
	TargetArgsPost
	TargetRequestBody
	TargetRequestCookies
	TargetRequestCookieNames
	TargetRemoteAddr

	TargetResponseStatus
	TargetResponseHeaders
	TargetResponseHeaderNames
	TargetResponseBody

	// TargetArgsJoined is the concatenation of every argument value in wire
	// order. It exists to catch payloads split across parameters, which defeat
	// per-value matching (docs/CONCEPT.md §10).
	//
	// Concatenation invents adjacency that was not in the original request, so
	// matches against this target carry a higher false-positive risk and the
	// compiler lowers their effective confidence by one tier.
	TargetArgsJoined

	targetKindCount
)

// Valid reports whether k is a defined target kind.
func (k TargetKind) Valid() bool { return k > TargetInvalid && k < targetKindCount }

// TargetKindCount returns the number of slots needed to index a table by
// TargetKind.
func TargetKindCount() int { return int(targetKindCount) }

// String implements fmt.Stringer.
func (k TargetKind) String() string {
	switch k {
	case TargetRequestMethod:
		return "REQUEST_METHOD"
	case TargetRequestURI:
		return "REQUEST_URI"
	case TargetRequestPath:
		return "REQUEST_PATH"
	case TargetRequestProtocol:
		return "REQUEST_PROTOCOL"
	case TargetRequestHeaders:
		return "REQUEST_HEADERS"
	case TargetRequestHeaderNames:
		return "REQUEST_HEADER_NAMES"
	case TargetArgs:
		return "ARGS"
	case TargetArgNames:
		return "ARGS_NAMES"
	case TargetArgsGet:
		return "ARGS_GET"
	case TargetArgsPost:
		return "ARGS_POST"
	case TargetRequestBody:
		return "REQUEST_BODY"
	case TargetRequestCookies:
		return "REQUEST_COOKIES"
	case TargetRequestCookieNames:
		return "REQUEST_COOKIE_NAMES"
	case TargetRemoteAddr:
		return "REMOTE_ADDR"
	case TargetResponseStatus:
		return "RESPONSE_STATUS"
	case TargetResponseHeaders:
		return "RESPONSE_HEADERS"
	case TargetResponseHeaderNames:
		return "RESPONSE_HEADER_NAMES"
	case TargetResponseBody:
		return "RESPONSE_BODY"
	case TargetArgsJoined:
		return "ARGS_JOINED"
	default:
		return "INVALID"
	}
}

// Phase returns the earliest phase at which k holds any data. The compiler uses
// it to reject rules that read data their phase cannot have yet — a rule
// inspecting REQUEST_BODY in PhaseRequestHeaders would silently never match,
// which is worse than failing to compile.
//
// Some collections are populated progressively rather than all at once. ARGS
// holds query arguments from the request-headers phase and gains body
// arguments in the request-body phase, matching CRS semantics so that rules
// carried over from a CRS deployment behave the same way. A phase-1 rule
// reading ARGS is therefore valid and inspects the query arguments; it simply
// does not see body arguments, which is why the core ruleset pairs its
// phase-1 injection rules with phase-2 counterparts.
func (k TargetKind) Phase() Phase {
	switch k {
	case TargetArgsPost, TargetRequestBody:
		return PhaseRequestBody
	case TargetArgsJoined:
		// The joined view concatenates every argument, so it is only meaningful
		// once the full set is known.
		return PhaseRequestBody
	case TargetResponseStatus, TargetResponseHeaders, TargetResponseHeaderNames:
		return PhaseResponseHeaders
	case TargetResponseBody:
		return PhaseResponseBody
	default:
		return PhaseRequestHeaders
	}
}

// Target selects the values a rule inspects. An empty Name selects every value
// in the collection; a non-empty Name selects one key, matched case-insensitively
// for header and cookie collections where the wire format is case-insensitive.
type Target struct {
	Kind TargetKind
	Name string
}

// Matches reports whether key belongs to t. It is only meaningful for keyed
// collections; unkeyed targets always match.
func (t Target) Matches(key string) bool {
	if t.Name == "" {
		return true
	}
	if t.Kind.caseInsensitiveKeys() {
		return strings.EqualFold(t.Name, key)
	}
	return t.Name == key
}

// MatchesBytes is Matches over a byte slice.
//
// It exists so the evaluation path never converts a key to a string. Body
// fields arrive as bytes from the parser, and converting each one would
// allocate per field per request — which is exactly the cost the arena and the
// zero-allocation SLO exist to remove.
func (t Target) MatchesBytes(key []byte) bool {
	if t.Name == "" {
		return true
	}
	if t.Kind.caseInsensitiveKeys() {
		return equalFoldBytes(t.Name, key)
	}
	return len(t.Name) == len(key) && t.Name == string(key)
}

// equalFoldBytes compares a string and a byte slice ignoring ASCII case,
// without allocating.
func equalFoldBytes(a string, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// caseInsensitiveKeys reports whether the wire format of this collection treats
// keys case-insensitively. Argument names are case-sensitive; header and cookie
// names are not.
func (k TargetKind) caseInsensitiveKeys() bool {
	switch k {
	case TargetRequestHeaders, TargetRequestHeaderNames,
		TargetResponseHeaders, TargetResponseHeaderNames,
		TargetRequestCookies, TargetRequestCookieNames:
		return true
	default:
		return false
	}
}

// String implements fmt.Stringer.
func (t Target) String() string {
	if t.Name == "" {
		return t.Kind.String()
	}
	return t.Kind.String() + ":" + t.Name
}
