// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package rules

// ActionKind enumerates the built-in outcomes of a rule match.
type ActionKind uint8

// Action kinds.
const (
	// ActionScore contributes to the transaction's anomaly score. The policy
	// threshold decides whether the accumulated score blocks.
	ActionScore ActionKind = iota

	// ActionBlock terminates the transaction immediately.
	ActionBlock

	// ActionAllow terminates rule evaluation and permits the request. It exists
	// for explicit allowlisting and is deliberately hard to reach: it must be
	// scoped, since an over-broad allow silently disables protection.
	ActionAllow

	// ActionLog records the match without influencing the outcome.
	ActionLog
)

// String implements fmt.Stringer.
func (k ActionKind) String() string {
	switch k {
	case ActionScore:
		return "score"
	case ActionBlock:
		return "block"
	case ActionAllow:
		return "allow"
	case ActionLog:
		return "log"
	default:
		return "invalid"
	}
}

// Outcome is what an Action asks the engine to do. It is data rather than a
// callback so that the engine, not the action, owns control flow — an action
// cannot skip phases, mutate the transaction, or block on I/O.
type Outcome struct {
	Kind ActionKind

	// Score is the anomaly contribution for ActionScore. Zero means the rule's
	// severity decides.
	Score int

	// Status is the HTTP status for ActionBlock. Zero means the policy default.
	Status int
}

// Terminal reports whether this outcome ends rule evaluation.
func (o Outcome) Terminal() bool {
	return o.Kind == ActionBlock || o.Kind == ActionAllow
}

// Action runs when a rule matches.
//
// Action is one of the five public extension points (docs/RULES.md §4) and is
// frozen under semver at v1.0. Implementations must be concurrent-safe and must
// not block: one instance is shared across transactions and Run executes on the
// request path.
type Action interface {
	// Name returns a stable identifier for reports and declarative formats.
	Name() string

	// Run returns what the engine should do about the match.
	Run(ctx *EvalContext, m Match) Outcome
}

// Built-in actions. These are values rather than constructors where they carry
// no configuration, so a rule literal reads as data.
var (
	// Block terminates the transaction with the policy's default status.
	Block Action = fixedAction{name: "block", out: Outcome{Kind: ActionBlock}}

	// Log records the match without affecting the outcome.
	Log Action = fixedAction{name: "log", out: Outcome{Kind: ActionLog}}

	// Allow terminates evaluation and permits the request.
	Allow Action = fixedAction{name: "allow", out: Outcome{Kind: ActionAllow}}

	// Score contributes the rule's severity-derived score to the anomaly total.
	Score Action = fixedAction{name: "score", out: Outcome{Kind: ActionScore}}
)

// BlockWithStatus returns an Action that blocks with a specific HTTP status.
func BlockWithStatus(status int) Action {
	return fixedAction{name: "block", out: Outcome{Kind: ActionBlock, Status: status}}
}

// ScoreBy returns an Action contributing a fixed anomaly score.
func ScoreBy(n int) Action {
	return fixedAction{name: "score", out: Outcome{Kind: ActionScore, Score: n}}
}

// fixedAction is an Action whose outcome does not depend on the match.
type fixedAction struct {
	name string
	out  Outcome
}

func (a fixedAction) Name() string                    { return a.name }
func (a fixedAction) Run(*EvalContext, Match) Outcome { return a.out }
