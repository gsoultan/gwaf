// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package types

// Confidence states how likely a rule match is a true positive.
//
// It replaces the paranoia-level dial found in CRS-derived rulesets. Paranoia
// level is a global knob that conflates detection aggressiveness with the
// evidence required to block, and it has no meaning for a semantic detector
// that derives a score from a parse result. Confidence is per-rule and
// composes with per-route policies instead. See docs/RULES.md §8.
//
// Confidence is not an opinion. docs/CONCEPT.md §8 requires it to be measured
// against the benign corpus: MaxFPRate below is the ceiling CI enforces for
// each tier, and a rule whose measured false-positive rate exceeds its declared
// tier fails the build.
type Confidence uint8

const (
	// Heuristic is research-grade. Expect false positives; detection-only
	// unless the deployment has been tuned for it.
	Heuristic Confidence = iota

	// Low is a heuristic signal that will need tuning on real traffic.
	Low

	// Medium fires on unusual but legitimate traffic often enough to matter.
	Medium

	// High has rare, well-understood false positives. Default blocking tier.
	High

	// Certain has no known false positives and is safe to block anywhere.
	Certain
)

// confidenceCount is the number of defined confidence tiers.
const confidenceCount = int(Certain) + 1

// Valid reports whether c is a defined tier.
func (c Confidence) Valid() bool { return int(c) < confidenceCount }

// String implements fmt.Stringer.
func (c Confidence) String() string {
	switch c {
	case Heuristic:
		return "heuristic"
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Certain:
		return "certain"
	default:
		return "invalid"
	}
}

// AtLeast reports whether c is at least as confident as min. Policies use this
// to select the rules they are willing to run.
func (c Confidence) AtLeast(min Confidence) bool { return c >= min }

// MaxFPRate returns the highest false-positive rate, as a fraction of benign
// requests, that a rule declaring this confidence may exhibit.
//
// These are the thresholds `gwaf calibrate` enforces. They are deliberately
// strict at the top: Certain means "safe to block anywhere", and one false
// positive in ten thousand benign requests is already visible at scale.
func (c Confidence) MaxFPRate() float64 {
	switch c {
	case Certain:
		return 0.0001 // 1 in 10,000
	case High:
		return 0.001 // 1 in 1,000
	case Medium:
		return 0.01 // 1 in 100
	case Low:
		return 0.05
	default:
		return 1.0 // Heuristic is ungated by design.
	}
}

// ParseConfidence maps a textual tier to a Confidence. The bool reports whether
// s named a defined tier.
func ParseConfidence(s string) (Confidence, bool) {
	switch s {
	case "heuristic":
		return Heuristic, true
	case "low":
		return Low, true
	case "medium":
		return Medium, true
	case "high":
		return High, true
	case "certain":
		return Certain, true
	default:
		return 0, false
	}
}

// ConfidenceFromParanoiaLevel maps a CRS paranoia level (1-4) onto a minimum
// confidence, so existing CRS knowledge and configuration keep working through
// the SecLang adapter. Out-of-range levels clamp to the nearest valid tier.
//
// Higher paranoia admits less precise rules, so the mapping is inverted.
func ConfidenceFromParanoiaLevel(pl int) Confidence {
	switch {
	case pl <= 1:
		return High
	case pl == 2:
		return Medium
	case pl == 3:
		return Low
	default:
		return Heuristic
	}
}
