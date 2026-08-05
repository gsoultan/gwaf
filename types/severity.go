// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package types

// Severity describes the impact of what a rule detects, independent of how
// confident the rule is that it detected it.
//
// Severity and Confidence are orthogonal and both are needed: a Certain match
// on a Notice-severity rule (an unusual but harmless header) should not block,
// while a Medium match on a Critical rule may warrant one. Conflating them is
// the mistake anomaly-score-only models make.
type Severity uint8

const (
	// SeverityNotice is informational; no action expected.
	SeverityNotice Severity = iota

	// SeverityWarning is suspicious but not independently actionable.
	SeverityWarning

	// SeverityError indicates a probable attack.
	SeverityError

	// SeverityCritical indicates an attack that would compromise the origin.
	SeverityCritical
)

// Valid reports whether s is a defined severity.
func (s Severity) Valid() bool { return s <= SeverityCritical }

// String implements fmt.Stringer.
func (s Severity) String() string {
	switch s {
	case SeverityNotice:
		return "notice"
	case SeverityWarning:
		return "warning"
	case SeverityError:
		return "error"
	case SeverityCritical:
		return "critical"
	default:
		return "invalid"
	}
}

// Score returns the anomaly score contribution for this severity. The values
// match the CRS convention so that anomaly thresholds carry over from existing
// deployments without retuning.
func (s Severity) Score() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityError:
		return 4
	case SeverityWarning:
		return 3
	default:
		return 2
	}
}

// ParseSeverity maps a textual severity to a Severity. The bool reports whether
// s named a defined severity.
func ParseSeverity(s string) (Severity, bool) {
	switch s {
	case "notice":
		return SeverityNotice, true
	case "warning":
		return SeverityWarning, true
	case "error":
		return SeverityError, true
	case "critical":
		return SeverityCritical, true
	default:
		return 0, false
	}
}
