// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package rules

import (
	"errors"
	"fmt"

	"github.com/gsoultan/gwaf/types"
)

// Sentinel errors returned by Compile. Callers can match them with errors.Is
// even when several rules failed and the errors were joined.
var (
	// ErrInvalidRule reports a rule that cannot be compiled.
	ErrInvalidRule = errors.New("invalid rule")

	// ErrDuplicateID reports two rules sharing an ID. IDs appear in audit logs,
	// exceptions, and tuning guides, so a duplicate would make those ambiguous.
	ErrDuplicateID = errors.New("duplicate rule id")

	// ErrReservedID reports a rule placed in a range reserved for the core
	// ruleset, first-party bundles, or CRS.
	ErrReservedID = errors.New("rule id in reserved range")
)

// RuleError identifies which rule failed validation and why.
//
// Compile reports every problem it finds rather than stopping at the first, so
// a ruleset with several mistakes is fixed in one pass instead of one error at
// a time.
type RuleError struct {
	ID    types.RuleID
	Field string
	Err   error
	// Hint, when set, states the fix rather than only the problem.
	Hint string
}

// Error implements error.
func (e *RuleError) Error() string {
	msg := fmt.Sprintf("rule %s: %s: %v", e.ID, e.Field, e.Err)
	if e.Hint != "" {
		msg += "; " + e.Hint
	}
	return msg
}

// Unwrap allows errors.Is to reach the underlying sentinel.
func (e *RuleError) Unwrap() error { return e.Err }

func ruleErr(id types.RuleID, field string, err error, hint string) *RuleError {
	return &RuleError{ID: id, Field: field, Err: err, Hint: hint}
}
