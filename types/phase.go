// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package types

// Phase identifies a point in the request/response lifecycle at which rules are
// evaluated. Phases run in ascending order and each may terminate the
// transaction, so cheap phases are ordered before expensive ones: blocking at
// PhaseRequestHeaders means the body is never read, parsed, or transformed.
type Phase uint8

const (
	// PhaseRequestHeaders evaluates the request line, headers, and query
	// arguments. No body has been read at this point.
	PhaseRequestHeaders Phase = iota + 1

	// PhaseRequestBody evaluates the parsed request body.
	PhaseRequestBody

	// PhaseResponseHeaders evaluates the upstream status line and headers.
	PhaseResponseHeaders

	// PhaseResponseBody evaluates the upstream response body.
	PhaseResponseBody

	// PhaseLogging runs after the decision is final. Rules in this phase cannot
	// change the outcome; it exists for audit and telemetry.
	PhaseLogging
)

// phaseCount is the number of defined phases. Plans are indexed by phase, so
// this bounds those arrays.
const phaseCount = int(PhaseLogging) + 1

// PhaseCount returns the number of slots needed to index a table by Phase.
func PhaseCount() int { return phaseCount }

// Valid reports whether p is a defined phase.
func (p Phase) Valid() bool {
	return p >= PhaseRequestHeaders && p <= PhaseLogging
}

// String implements fmt.Stringer.
func (p Phase) String() string {
	switch p {
	case PhaseRequestHeaders:
		return "request_headers"
	case PhaseRequestBody:
		return "request_body"
	case PhaseResponseHeaders:
		return "response_headers"
	case PhaseResponseBody:
		return "response_body"
	case PhaseLogging:
		return "logging"
	default:
		return "invalid"
	}
}

// IsRequest reports whether p evaluates request data.
func (p Phase) IsRequest() bool {
	return p == PhaseRequestHeaders || p == PhaseRequestBody
}
