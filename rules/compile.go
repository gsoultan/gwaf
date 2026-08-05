// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package rules

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/gsoultan/gwaf/internal/prefilter"
	"github.com/gsoultan/gwaf/types"
)

// Options controls compilation.
type Options struct {
	// UserRulesOnly rejects rules outside the embedder-owned ID range. It is
	// set when compiling rules supplied by an application so that a typo cannot
	// shadow a core or CRS rule ID and silently change what a tuning guide
	// refers to.
	UserRulesOnly bool
}

// CompiledRule is the immutable, evaluation-ready form of a Rule.
//
// It is exported so that explain output and compile reports can reference it,
// but it is constructed only by Compile.
type CompiledRule struct {
	Rule *Rule

	// group is the transform-chain group this rule belongs to.
	group *ChainGroup

	// groupIdx is this rule's index within its group. Prefilter candidate sets
	// are indexed by it, which keeps bitsets proportional to one group rather
	// than the whole ruleset.
	groupIdx int

	// unconditional reports that the operator declared no required literals, so
	// the rule must be evaluated for every value in its phase.
	unconditional bool
}

// Unconditional reports whether this rule runs regardless of input.
func (c *CompiledRule) Unconditional() bool { return c.unconditional }

// Actions returns the rule's actions, resolving the empty case to the default.
// The engine uses this rather than Rule.Actions so the default is applied in
// exactly one place.
func (c *CompiledRule) Actions() []Action { return c.Rule.effectiveActions() }

// ChainGroup holds the rules that share one transform chain, together with the
// prefilter built from their literals.
//
// Grouping by chain is what makes prefiltering correct as well as fast. An
// operator states its required literals in terms of the value it will actually
// see — that is, after transformation. A rule matching "unionselect" under a
// whitespace-stripping chain would never fire if the prefilter scanned the raw
// bytes, because the raw request says "UNION SELECT". Scanning the transformed
// value with an automaton built from the same chain's literals keeps the two in
// agreement.
//
// It is also the common-subexpression elimination described in
// docs/CONCEPT.md §1.3: every rule sharing a chain pays for that chain once per
// value, not once per rule.
type ChainGroup struct {
	// Transforms is the chain every rule in this group applies.
	Transforms []Transform

	// Rules are the group's rules, in evaluation order. Prefilter candidate
	// indices address this slice.
	Rules []*CompiledRule

	// Automaton maps literal occurrences in the transformed value to indices
	// into Rules. It is nil when every rule in the group is unconditional.
	Automaton *prefilter.Automaton

	// Unconditional lists indices into Rules that must run regardless.
	Unconditional []int
}

// sortGroupsByChain orders a phase's groups so that chains sharing a prefix are
// adjacent.
//
// This is what makes prefix reuse possible in the evaluator. The core ruleset's
// chains are [lowercase], [url_decode], [url_decode lowercase normalize_path],
// and [url_decode lowercase remove_whitespace]: applied independently that is
// eight transform applications per value, and applied in sorted order, each
// resuming where the previous left off, it is five. The saving is structural
// rather than a micro-optimisation, and it grows with the ruleset — a chain
// added to an existing family costs only its own last step.
func sortGroupsByChain(groups []*ChainGroup) {
	slices.SortStableFunc(groups, func(a, b *ChainGroup) int {
		for i := 0; i < len(a.Transforms) && i < len(b.Transforms); i++ {
			if c := strings.Compare(a.Transforms[i].Name(), b.Transforms[i].Name()); c != 0 {
				return c
			}
		}
		return len(a.Transforms) - len(b.Transforms)
	})
}

// phasePlan holds everything needed to evaluate one phase.
type phasePlan struct {
	groups []*ChainGroup
	rules  []*CompiledRule // every rule in the phase, for reporting
	// maxGroupRules sizes the candidate bitset.
	maxGroupRules int
	// maxChainLen sizes the evaluator's per-depth staging buffers, which is
	// what lets one group resume where the previous one left off.
	maxChainLen int
}

// maxChainLen returns the longest transform chain among the groups.
func maxChainLen(groups []*ChainGroup) int {
	n := 0
	for _, g := range groups {
		n = max(n, len(g.Transforms))
	}
	return n
}

// Ruleset is a compiled, immutable, concurrency-safe plan.
//
// Compilation is total: either every rule compiled or Compile returned an
// error. There is no partially loaded ruleset and no silently skipped rule,
// which is what makes a swap at runtime safe.
type Ruleset struct {
	phases [maxPhases]phasePlan
	all    []*CompiledRule
	byID   map[types.RuleID]*CompiledRule
	report Report
}

// maxPhases sizes the phase-indexed array. Phase values start at 1.
const maxPhases = int(types.PhaseLogging) + 1

// Report summarizes what Compile produced. It is the data behind `gwaf lint`
// and is what makes the cost of unconditional rules visible at build time
// rather than in a production latency graph. See docs/RULES.md §5.
type Report struct {
	// Rules is the total number compiled.
	Rules int

	// Prefiltered is the number that will only be evaluated when their literals
	// appear in the input.
	Prefiltered int

	// Unconditional lists rules that run on every request in their phase.
	Unconditional []UnconditionalRule

	// Literals is the number of distinct literals in the prefilter.
	Literals int

	// AutomatonStates is the total prefilter state count across groups, a proxy
	// for prefilter memory.
	AutomatonStates int

	// ChainGroups is the number of distinct transform chains. Each one is
	// applied once per value, so this is the per-value normalization cost —
	// the figure to watch when adding rules with novel transform chains.
	ChainGroups int
}

// UnconditionalRule identifies a rule that cannot be prefiltered, and why.
type UnconditionalRule struct {
	ID       types.RuleID
	Phase    types.Phase
	Operator string
	Reason   string
}

// Compile validates rules and builds an executable plan.
//
// Every problem found is reported, not just the first, so a ruleset with
// several mistakes can be fixed in one pass.
func Compile(set Set, opts Options) (*Ruleset, error) {
	if err := validate(set, opts); err != nil {
		return nil, err
	}

	// Sort by (phase, ID). Evaluation order is therefore a property of the
	// ruleset rather than of how it was assembled: two runs over the same
	// request always produce the same decision, which is what makes rules
	// testable and audit logs trustworthy. See docs/RULES.md §6.
	sorted := slices.Clone(set)
	slices.SortStableFunc(sorted, func(a, b Rule) int {
		if a.Phase != b.Phase {
			return int(a.Phase) - int(b.Phase)
		}
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		default:
			return 0
		}
	})

	rs := &Ruleset{
		all:  make([]*CompiledRule, 0, len(sorted)),
		byID: make(map[types.RuleID]*CompiledRule, len(sorted)),
	}

	// Chains are interned per phase so that rules sharing a chain end up in one
	// group and the chain is applied once per value rather than once per rule.
	type groupKey struct {
		phase types.Phase
		chain string
	}
	groups := make(map[groupKey]*ChainGroup)
	builders := make(map[*ChainGroup]*prefilter.Builder)
	literals := make(map[string]struct{})

	for i := range sorted {
		r := &sorted[i]
		plan := &rs.phases[r.Phase]

		key := groupKey{phase: r.Phase, chain: chainKey(r.Transforms)}
		g, ok := groups[key]
		if !ok {
			g = &ChainGroup{Transforms: r.Transforms}
			groups[key] = g
			plan.groups = append(plan.groups, g)
		}

		cr := &CompiledRule{
			Rule:     r,
			group:    g,
			groupIdx: len(g.Rules),
		}

		lits, required := r.Op.Literals()
		switch {
		case required && len(lits) > 0:
			b, ok := builders[g]
			if !ok {
				b = prefilter.NewBuilder()
				builders[g] = b
			}
			for _, lit := range lits {
				if lit == "" {
					continue
				}
				literals[lit] = struct{}{}
				b.Add(lit, uint32(cr.groupIdx))
			}
			rs.report.Prefiltered++
		default:
			cr.unconditional = true
			g.Unconditional = append(g.Unconditional, cr.groupIdx)
			rs.report.Unconditional = append(rs.report.Unconditional, UnconditionalRule{
				ID:       r.ID,
				Phase:    r.Phase,
				Operator: r.Op.Name(),
				Reason:   unconditionalReason(required),
			})
		}

		g.Rules = append(g.Rules, cr)
		plan.rules = append(plan.rules, cr)
		plan.maxGroupRules = max(plan.maxGroupRules, len(g.Rules))
		rs.all = append(rs.all, cr)
		rs.byID[r.ID] = cr
	}

	for g, b := range builders {
		a := b.Build()
		g.Automaton = a
		rs.report.AutomatonStates += a.States()
	}

	rs.report.Rules = len(rs.all)
	rs.report.Literals = len(literals)
	for p := range rs.phases {
		sortGroupsByChain(rs.phases[p].groups)
		rs.report.ChainGroups += len(rs.phases[p].groups)
		rs.phases[p].maxChainLen = maxChainLen(rs.phases[p].groups)
	}
	return rs, nil
}

// chainKey returns a stable identity for a transform chain, so that two rules
// declaring the same normalization share one group and one application.
func chainKey(chain []Transform) string {
	if len(chain) == 0 {
		return ""
	}
	var b strings.Builder
	for i, t := range chain {
		if i > 0 {
			b.WriteByte('|')
		}
		b.WriteString(t.Name())
	}
	return b.String()
}

// unconditionalReason explains why a rule could not be prefiltered, in terms
// the rule author can act on.
func unconditionalReason(required bool) string {
	if !required {
		return "operator declares no required literals"
	}
	return "operator declared required literals but supplied none"
}

// validate checks every rule and joins the failures.
func validate(set Set, opts Options) error {
	var errs []error
	seen := make(map[types.RuleID]int, len(set))

	for i := range set {
		r := &set[i]

		if r.ID == 0 {
			errs = append(errs, ruleErr(r.ID, "ID", ErrInvalidRule,
				"rule IDs must be non-zero; embedder rules start at 1000000"))
			continue
		}
		if prev, dup := seen[r.ID]; dup {
			errs = append(errs, ruleErr(r.ID, "ID", ErrDuplicateID,
				fmt.Sprintf("also defined at index %d", prev)))
			continue
		}
		seen[r.ID] = i

		if opts.UserRulesOnly && !r.ID.IsUser() {
			errs = append(errs, ruleErr(r.ID, "ID", ErrReservedID,
				fmt.Sprintf("%s range is reserved; use %d or above",
					r.ID.Namespace(), types.UserMin)))
		}

		if !r.Phase.Valid() {
			errs = append(errs, ruleErr(r.ID, "Phase", ErrInvalidRule,
				"set a phase, e.g. types.PhaseRequestHeaders"))
		}

		if len(r.Targets) == 0 {
			errs = append(errs, ruleErr(r.ID, "Targets", ErrInvalidRule,
				"a rule with no targets inspects nothing and can never match"))
		}
		for _, t := range r.Targets {
			if !t.Kind.Valid() {
				errs = append(errs, ruleErr(r.ID, "Targets", ErrInvalidRule,
					fmt.Sprintf("unknown target kind %d", t.Kind)))
				continue
			}
			// A rule must not read data its phase cannot have yet: inspecting
			// REQUEST_BODY during PhaseRequestHeaders would silently never
			// match, which is worse than failing to compile.
			if r.Phase.Valid() && t.Kind.Phase() > r.Phase {
				errs = append(errs, ruleErr(r.ID, "Targets", ErrInvalidRule,
					fmt.Sprintf("%s is not available until phase %s, but rule runs in %s",
						t.Kind, t.Kind.Phase(), r.Phase)))
			}
		}

		if r.Op == nil {
			errs = append(errs, ruleErr(r.ID, "Op", ErrInvalidRule,
				"every rule needs an operator"))
		}

		for j, t := range r.Transforms {
			if t == nil {
				errs = append(errs, ruleErr(r.ID, "Transforms", ErrInvalidRule,
					fmt.Sprintf("nil transform at index %d", j)))
			}
		}
		for j, a := range r.Actions {
			if a == nil {
				errs = append(errs, ruleErr(r.ID, "Actions", ErrInvalidRule,
					fmt.Sprintf("nil action at index %d", j)))
			}
		}

		if !r.Severity.Valid() {
			errs = append(errs, ruleErr(r.ID, "Severity", ErrInvalidRule,
				"severity out of range"))
		}
		if !r.Confidence.Valid() {
			errs = append(errs, ruleErr(r.ID, "Confidence", ErrInvalidRule,
				"confidence out of range"))
		}
	}

	return errors.Join(errs...)
}

// Report returns the compile summary.
func (rs *Ruleset) Report() Report { return rs.report }

// Len returns the number of compiled rules.
func (rs *Ruleset) Len() int { return len(rs.all) }

// All returns every compiled rule, in evaluation order.
//
// It exists for tooling that has to reason about the whole ruleset — the
// calibration harness, the linter, a control plane listing what is loaded —
// rather than about one request.
func (rs *Ruleset) All() []*CompiledRule { return rs.all }

// ByID returns the compiled rule with the given ID.
func (rs *Ruleset) ByID(id types.RuleID) (*CompiledRule, bool) {
	cr, ok := rs.byID[id]
	return cr, ok
}

// PhaseRules returns the rules compiled for a phase, in evaluation order.
func (rs *Ruleset) PhaseRules(p types.Phase) []*CompiledRule {
	if !p.Valid() {
		return nil
	}
	return rs.phases[p].rules
}

// MaxChainLen returns the longest transform chain in a phase, so the evaluator
// can size its staging buffers once.
func (rs *Ruleset) MaxChainLen(p types.Phase) int {
	if int(p) >= len(rs.phases) {
		return 0
	}
	return rs.phases[p].maxChainLen
}

// Groups returns the transform-chain groups for a phase. The engine walks these
// rather than the flat rule list: each group's chain is applied once per value,
// then its automaton selects the candidates to evaluate.
func (rs *Ruleset) Groups(p types.Phase) []*ChainGroup {
	if !p.Valid() {
		return nil
	}
	return rs.phases[p].groups
}

// MaxGroupRules returns the largest group size in a phase, which bounds the
// candidate bitset the evaluator needs.
func (rs *Ruleset) MaxGroupRules(p types.Phase) int {
	if !p.Valid() {
		return 0
	}
	return rs.phases[p].maxGroupRules
}
