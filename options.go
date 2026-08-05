// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf

import (
	"log/slog"

	"github.com/gsoultan/gwaf/internal/budget"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/schema"
	"github.com/gsoultan/gwaf/types"
)

// Mode selects whether decisions are enforced.
type Mode uint8

const (
	// Blocking enforces decisions. This is the default: the core ruleset ships
	// only Certain and High confidence rules, which is what makes blocking by
	// default defensible. A WAF that silently protects nothing is worse than no
	// WAF, because the operator believes they are covered.
	Blocking Mode = iota

	// DetectionOnly evaluates rules and reports decisions without enforcing
	// them. It is the rollout path, not the destination.
	DetectionOnly
)

// String implements fmt.Stringer.
func (m Mode) String() string {
	if m == DetectionOnly {
		return "detection_only"
	}
	return "blocking"
}

// FailMode selects what happens when gwaf cannot complete its analysis —
// budget exhaustion, a limit breach, or an internal error.
//
// There is no safe default here, which is why the embedder must own it:
// availability versus security is a deployment decision, not a library one.
type FailMode uint8

const (
	// FailClosed rejects requests that could not be fully analysed. Correct
	// when a missed attack is worse than a dropped request.
	FailClosed FailMode = iota

	// FailOpen permits requests that could not be fully analysed. Correct when
	// availability dominates. It is loud: every occurrence emits a decision
	// with ReasonBudget or ReasonLimit.
	FailOpen
)

// String implements fmt.Stringer.
func (f FailMode) String() string {
	if f == FailOpen {
		return "fail_open"
	}
	return "fail_closed"
}

// Limits bound the input gwaf will analyse.
//
// These are enforced before parsing, as a cheap pre-check. They are both a
// denial-of-service defence and a latency guarantee: they bound worst-case work
// per request independently of ruleset size.
//
// Exceeding a limit is a decision, never a truncation. Half-inspecting an
// oversized body is indistinguishable from a bypass, so the request is rejected
// (or allowed, per FailMode) rather than partially analysed.
type Limits struct {
	// MaxBodySize is the largest request body inspected, in bytes.
	MaxBodySize int

	// MaxArgs is the largest number of arguments inspected.
	MaxArgs int

	// MaxHeaders is the largest number of headers inspected.
	MaxHeaders int

	// MaxValueLen is the largest single value inspected, in bytes.
	//
	// Exceeding it is a decision, never a truncation: a value too large to
	// inspect is not a value shown to be clean. Set it large enough for the
	// traffic you actually serve — base64 file content in a JSON or protobuf
	// field, and long bearer tokens in query parameters, since browsers cannot
	// set headers on WebSocket or EventSource connections.
	MaxValueLen int

	// MaxArenaSize bounds per-transaction working memory, in bytes.
	MaxArenaSize int
}

// DefaultLimits are sized for typical API traffic while keeping the worst case
// well inside the memory SLO in CLAUDE.md §2.
func DefaultLimits() Limits {
	return Limits{
		MaxBodySize: 1 << 20, // 1 MiB
		MaxArgs:     1000,
		MaxHeaders:  200,
		// Sized so a base64-encoded file that fits MaxBodySize also fits a
		// single field: base64 expands by 4/3, so the ceiling has to exceed the
		// body limit rather than sit under it. A smaller value here would
		// reject ordinary upload traffic, and truncating instead would create
		// a padding bypass.
		MaxValueLen:  2 << 20, // 2 MiB
		MaxArenaSize: 4 << 20, // 4 MiB
	}
}

// config holds resolved options. It is immutable once a WAF is constructed.
type config struct {
	mode      Mode
	failMode  FailMode
	limits    Limits
	fuelLimit budget.Fuel
	threshold int
	minConf   types.Confidence
	logger    *slog.Logger
	ruleset   rules.Set
	blockCode int
	onDecide  func(Decision)

	schema     *schema.Schema
	exceptions rules.Exceptions

	// err carries a validation failure from an option that can fail, so New
	// reports it. Options are void functions -- the signature is frozen for
	// third parties -- so the error travels in the config rather than the
	// return.
	err error

	// coreDisabled drops the first-party ruleset. Opting out is deliberately
	// explicit so that shipping an inert WAF is a choice someone made, not a
	// configuration mistake.
	coreDisabled bool
}

func defaultConfig() config {
	return config{
		mode:      Blocking,
		failMode:  FailClosed,
		limits:    DefaultLimits(),
		fuelLimit: budget.DefaultLimit,
		threshold: 5, // matches the CRS inbound default so thresholds carry over
		minConf:   types.High,
		logger:    slog.Default(),
		blockCode: 403,
	}
}

// Option configures a WAF. Options are applied in order; later ones win.
type Option func(*config)

// WithMode selects blocking or detection-only.
func WithMode(m Mode) Option {
	return func(c *config) { c.mode = m }
}

// WithFailMode selects what happens when analysis cannot complete.
func WithFailMode(f FailMode) Option {
	return func(c *config) { c.failMode = f }
}

// WithLimits sets input limits. Zero-valued fields fall back to the defaults,
// so a caller can override one limit without restating the rest.
func WithLimits(l Limits) Option {
	return func(c *config) {
		d := DefaultLimits()
		if l.MaxBodySize <= 0 {
			l.MaxBodySize = d.MaxBodySize
		}
		if l.MaxArgs <= 0 {
			l.MaxArgs = d.MaxArgs
		}
		if l.MaxHeaders <= 0 {
			l.MaxHeaders = d.MaxHeaders
		}
		if l.MaxValueLen <= 0 {
			l.MaxValueLen = d.MaxValueLen
		}
		if l.MaxArenaSize <= 0 {
			l.MaxArenaSize = d.MaxArenaSize
		}
		c.limits = l
	}
}

// WithFuelLimit sets the per-transaction work ceiling. A non-positive value
// disables metering, which is intended for offline tooling — calibration,
// corpus replay — and must not be used for serving traffic.
func WithFuelLimit(f budget.Fuel) Option {
	return func(c *config) { c.fuelLimit = f }
}

// WithThreshold sets the anomaly score at or above which a request is blocked.
func WithThreshold(n int) Option {
	return func(c *config) { c.threshold = n }
}

// WithMinConfidence sets the least-trustworthy rule tier that will be
// evaluated. It replaces the global paranoia-level dial: "only run rules at
// least this trustworthy" is a statement that can be defined precisely, where
// "paranoia level 3" cannot. See docs/RULES.md §8.
func WithMinConfidence(c0 types.Confidence) Option {
	return func(c *config) { c.minConf = c0 }
}

// WithParanoiaLevel maps a CRS paranoia level (1-4) onto a minimum confidence,
// so existing CRS configuration and operator knowledge keep working.
func WithParanoiaLevel(pl int) Option {
	return func(c *config) { c.minConf = types.ConfidenceFromParanoiaLevel(pl) }
}

// WithLogger sets the logger. The library never constructs a global logger and
// never writes to one it was not given.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithRuleset adds rules. It may be called more than once; sets accumulate.
func WithRuleset(set rules.Set) Option {
	return func(c *config) { c.ruleset = append(c.ruleset, set...) }
}

// WithSchema supplies an API description.
//
// The schema is both a validator and a compiler input. Requests outside it are
// rejected before any rule runs, and values inside it that validate as a
// constrained type — an integer, a UUID, a declared enum — skip rule evaluation
// entirely, because such a value provably cannot carry a payload.
//
// The better an API is specified, the faster and the more precise gwaf gets.
// See docs/CONCEPT.md §6 and §9.
func WithSchema(s *schema.Schema) Option {
	return func(c *config) { c.schema = s }
}

// WithoutCoreRuleset omits the first-party ruleset, leaving only rules the
// embedder supplies.
//
// Use it when you are replacing detection wholesale — a migration running
// gwaf alongside another engine, or a test exercising specific rules. A WAF
// with no rules blocks nothing, so this is an explicit opt-out rather than a
// consequence of forgetting to configure something.
func WithoutCoreRuleset() Option {
	return func(c *config) { c.coreDisabled = true }
}

// WithBlockStatus sets the HTTP status reported for blocked requests when a
// rule does not specify one.
func WithBlockStatus(code int) Option {
	return func(c *config) { c.blockCode = code }
}

// OnDecision registers a callback invoked for every terminal decision. It runs
// on the request path, so it must not block.
func OnDecision(fn func(Decision)) Option {
	return func(c *config) { c.onDecide = fn }
}

// WithException suppresses one rule in one place.
//
// Exceptions are conjunctive and the narrow form is the short one: every field
// set must match, every field left zero matches anything. Decision.Explain()
// computes the tightest exception that would have allowed a request it blocked,
// so the correct fix is the one an operator can copy rather than derive.
//
//	waf, err := gwaf.New(gwaf.WithException(rules.Exception{
//	    RuleID: 7002,
//	    Path:   "/api/v1/query",
//	    Key:    "filter[$gt]",
//	    Note:   "this endpoint publishes Mongo operators as its filter DSL",
//	}))
//
// An exception with nothing set is refused rather than honoured: it would
// disable every rule everywhere, and a configuration that does that by accident
// should not be expressible.
//
// CLAUDE.md §6 prefers deleting a rule over excepting it. A rule needing
// exceptions on many routes is a rule that is wrong, not one that needs tuning.
func WithException(x rules.Exception) Option {
	return func(c *config) {
		if err := x.Validate(); err != nil {
			if c.err == nil {
				c.err = err
			}
			return
		}
		c.exceptions = append(c.exceptions, x)
	}
}
