// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package conformance runs go-ftw test cases against gwaf.
//
// # What this measures, and why it is worth measuring
//
// Every detection number gwaf publishes is measured against a corpus gwaf wrote.
// That is the right way to develop a detector and the wrong way to prove one:
// a suite written by the same people who wrote the rules tests what they thought
// of. go-ftw is the OWASP Core Rule Set's own test format, and its corpus is
// thousands of cases written by other people, over twenty years, against rules
// gwaf did not implement — which makes it the least self-selecting evidence
// available.
//
// # Two modes, because there are two different claims
//
// Running the same YAML two ways answers two questions that get conflated:
//
//   - ModeDetection asks "does gwaf block what CRS says should be blocked?" It
//     runs gwaf's own ruleset and ignores rule IDs entirely, because gwaf's IDs
//     are not CRS's and never will be. This is the parity claim.
//   - ModeRuleID asks "does gwaf running CRS rules fire the same rule IDs?" It
//     loads real CRS .conf files through the seclang bridge, which preserves the
//     original IDs, and compares them exactly. This is the bridge-fidelity
//     claim, and it is the stricter of the two.
//
// Reporting one and implying the other is how a conformance number becomes
// marketing, so the runner keeps them apart and the report names which ran.
//
// # In-process, not over a socket
//
// go-ftw normally drives a live server over HTTP. This runner builds the request
// and feeds it through gwaf directly. That is deliberate: a test that goes over
// a socket measures the socket too — a 400 from net/http for a malformed
// encoding reads as "gwaf missed it" when gwaf never saw it, which is a real
// failure mode this project has already hit once. In-process, the only variable
// is gwaf.
//
// Stages needing a live origin (follow_redirect, save_cookie, a response
// section) are reported as skipped rather than silently passed.
package conformance

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gsoultan/gwaf"
)

// Mode selects which claim the run measures.
type Mode int

const (
	// ModeDetection ignores rule IDs and asks only whether gwaf blocked. Use
	// with gwaf's own ruleset.
	ModeDetection Mode = iota

	// ModeRuleID compares the exact rule IDs that fired. Only meaningful with a
	// ruleset that preserves CRS IDs, which means one loaded through seclang.
	ModeRuleID
)

// File is one go-ftw YAML document.
//
// The field names are the schema's, not Go's, because the whole point is to read
// files somebody else wrote. Fields gwaf cannot honour are still parsed, so a
// stage that needs them can be reported as skipped rather than misread.
type File struct {
	Meta   Meta   `yaml:"meta"`
	RuleID uint32 `yaml:"rule_id"`
	Tests  []Test `yaml:"tests"`
}

// Meta describes the file.
type Meta struct {
	Author      string `yaml:"author"`
	Description string `yaml:"description"`
	Enabled     *bool  `yaml:"enabled"`
	Name        string `yaml:"name"`
}

// Test is one named case.
type Test struct {
	TestTitle string   `yaml:"test_title"`
	TestID    uint32   `yaml:"test_id"`
	Desc      string   `yaml:"desc"`
	Stages    []Stage  `yaml:"stages"`
	Tags      []string `yaml:"tags"`
}

// Title returns the most specific name the file gave this test.
func (t Test) Title() string {
	switch {
	case t.TestTitle != "":
		return t.TestTitle
	case t.TestID != 0:
		return strconv.FormatUint(uint64(t.TestID), 10)
	default:
		return t.Desc
	}
}

// Stage is one request and what is expected of it.
type Stage struct {
	Description string `yaml:"description"`
	Input       Input  `yaml:"input"`
	Output      Output `yaml:"output"`
}

// Input is the request to send.
type Input struct {
	DestAddr       string            `yaml:"dest_addr"`
	Port           int               `yaml:"port"`
	Protocol       string            `yaml:"protocol"`
	URI            string            `yaml:"uri"`
	Version        string            `yaml:"version"`
	Method         string            `yaml:"method"`
	Headers        map[string]string `yaml:"headers"`
	Data           string            `yaml:"data"`
	EncodedData    string            `yaml:"encoded_data"`
	RawRequest     string            `yaml:"raw_request"`
	EncodedRequest string            `yaml:"encoded_request"`

	// Fields that require a live origin. Parsed so the runner can say why a
	// stage was skipped instead of quietly getting it wrong.
	FollowRedirect bool  `yaml:"follow_redirect"`
	SaveCookie     bool  `yaml:"save_cookie"`
	StopMagic      *bool `yaml:"stop_magic"`
}

// Output is what the stage expects.
type Output struct {
	Status           int    `yaml:"status"`
	ResponseContains string `yaml:"response_contains"`
	LogContains      string `yaml:"log_contains"`
	NoLogContains    string `yaml:"no_log_contains"`
	Log              Log    `yaml:"log"`
	ExpectError      *bool  `yaml:"expect_error"`
}

// Log names the rule IDs a stage expects, or expects not to see.
type Log struct {
	ExpectIDs    []uint32 `yaml:"expect_ids"`
	NoExpectIDs  []uint32 `yaml:"no_expect_ids"`
	MatchRegex   string   `yaml:"match_regex"`
	NoMatchRegex string   `yaml:"no_match_regex"`
}

// expectsBlock reports whether the stage says the request should be detected.
//
// FTW expresses this several ways and they have to agree: an expected rule ID, a
// log assertion, or a 403. The reading is deliberately conservative — a stage
// that only says "no_expect_ids" is asserting the *absence* of a detection, so
// it expects a pass.
func (o Output) expectsBlock() bool {
	if len(o.Log.ExpectIDs) > 0 || o.Log.MatchRegex != "" || o.LogContains != "" {
		return true
	}
	return o.Status == 403
}

// expectsPass reports whether the stage asserts the request is clean. A stage
// can assert neither, in which case it is informational and the runner says so.
func (o Output) expectsPass() bool {
	if len(o.Log.NoExpectIDs) > 0 || o.Log.NoMatchRegex != "" || o.NoLogContains != "" {
		return true
	}
	return o.Status == 200
}

// Result is what happened to one stage.
type Result struct {
	File    string
	Test    string
	Stage   int
	Passed  bool
	Skipped bool
	Reason  string
}

// Report is the outcome of a run.
type Report struct {
	Mode    Mode
	Passed  int
	Failed  int
	Skipped int
	Results []Result
}

// Rate returns the fraction of *executed* stages that passed.
//
// Skipped stages are excluded from the denominator rather than counted as
// passes, because a suite that skips half its cases and reports 100% is lying.
// The skip count is printed beside the rate for the same reason.
func (r Report) Rate() float64 {
	run := r.Passed + r.Failed
	if run == 0 {
		return 0
	}
	return float64(r.Passed) / float64(run)
}

// String renders the report the way a CI log should read it.
func (r Report) String() string {
	mode := "detection (rule IDs ignored)"
	if r.Mode == ModeRuleID {
		mode = "rule-id (exact CRS IDs)"
	}
	return fmt.Sprintf("conformance [%s]: %d/%d passed (%.1f%%), %d skipped",
		mode, r.Passed, r.Passed+r.Failed, 100*r.Rate(), r.Skipped)
}

// Failures returns only the stages that failed, for a CI log that should print
// what broke rather than everything that did not.
func (r Report) Failures() []Result {
	var out []Result
	for _, res := range r.Results {
		if !res.Passed && !res.Skipped {
			out = append(out, res)
		}
	}
	return out
}

// Run executes every stage of every test in files against waf.
func Run(waf *gwaf.WAF, files map[string]File, mode Mode) Report {
	rep := Report{Mode: mode}
	for name, f := range files {
		if f.Meta.Enabled != nil && !*f.Meta.Enabled {
			continue
		}
		for _, t := range f.Tests {
			for i, st := range t.Stages {
				res := runStage(waf, st, mode)
				res.File, res.Test, res.Stage = name, t.Title(), i+1
				switch {
				case res.Skipped:
					rep.Skipped++
				case res.Passed:
					rep.Passed++
				default:
					rep.Failed++
				}
				rep.Results = append(rep.Results, res)
			}
		}
	}
	return rep
}

// runStage sends one request and judges the outcome.
func runStage(waf *gwaf.WAF, st Stage, mode Mode) Result {
	if why, skip := unsupported(st); skip {
		return Result{Skipped: true, Reason: why}
	}

	d, fired := inspect(waf, st.Input)

	if mode == ModeRuleID {
		return judgeByRuleID(st.Output, fired)
	}
	return judgeByDetection(st.Output, d)
}

// unsupported reports stages this runner cannot honour, and why.
//
// Saying so is the point. A conformance suite that silently passes what it
// cannot run reports a number about a smaller suite than the one it claims.
func unsupported(st Stage) (string, bool) {
	switch {
	case st.Input.RawRequest != "" || st.Input.EncodedRequest != "":
		return "raw_request: byte-level framing needs a socket, not a transaction", true
	case st.Input.FollowRedirect:
		return "follow_redirect: needs a live origin", true
	case st.Input.SaveCookie:
		return "save_cookie: needs state across stages", true
	case st.Output.ResponseContains != "":
		return "response_contains: needs a live origin's response", true
	case !st.Output.expectsBlock() && !st.Output.expectsPass():
		return "stage asserts neither a detection nor a pass", true
	}
	return "", false
}

// ruleScopedPass reports a stage whose pass-assertion names a specific CRS rule
// rather than asserting the request is clean overall.
//
// This is a correction to an earlier reading that inflated the false-positive
// count. "no_expect_ids: [932230]" asserts that *rule 932230* does not fire; it
// does not assert that nothing fires. CRS writes these as tuning cases — a
// payload that legitimately trips other rules while proving one specific rule
// does not over-match. Reading it as "this request must pass" turned a stage
// where gwaf correctly blocked a shell command into a reported false positive.
//
// Detection mode ignores rule IDs by design, so the assertion is unanswerable
// there and the stage is skipped. Rule-ID mode answers it exactly, which is
// where it belongs.
func ruleScopedPass(out Output) bool {
	if out.Status == 200 {
		return false // an explicit "nothing should block" is answerable
	}
	return len(out.Log.NoExpectIDs) > 0 || out.Log.NoMatchRegex != "" || out.NoLogContains != ""
}

// inspect runs one input through gwaf and returns the decision plus every rule
// that fired.
func inspect(waf *gwaf.WAF, in Input) (gwaf.Decision, map[uint32]bool) {
	tx := waf.NewTransaction()
	defer tx.Close()

	method := in.Method
	if method == "" {
		method = "GET"
	}
	uri := in.URI
	if uri == "" {
		uri = "/"
	}
	version := in.Version
	if version == "" {
		version = "HTTP/1.1"
	}

	tx.SetRequestLine(method, uri, version)
	for k, v := range in.Headers {
		tx.AddRequestHeader(k, v)
	}

	d := tx.ProcessRequestHeaders()
	body := in.Data
	if body == "" {
		body = in.EncodedData
	}
	if !d.Blocked() && body != "" {
		tx.SetRequestBody([]byte(body))
		d = tx.ProcessRequestBody()
	}
	// Response phases. The CRS harness reflects a body back: a test posts
	// {"body":"..."} to /reflect and the origin echoes it, which is how the
	// RESPONSE-95x families exercise leak detection. Honouring that convention
	// is what gives gwaf's response-phase rules a chance — without it those
	// stages were reported as gwaf missing something it was never shown, which
	// is the runner's fault rather than a detection gap.
	if !d.Blocked() {
		if reflected, ok := reflectedBody(in); ok {
			tx.SetResponseStatus(200)
			tx.AddResponseHeader("Content-Type", "text/html")
			if rd := tx.ProcessResponseHeaders(); !rd.Blocked() {
				if wd := tx.WriteResponseBody(reflected); !wd.Blocked() {
					d = tx.ProcessResponseBody()
				} else {
					d = wd
				}
			} else {
				d = rd
			}
		}
	}

	if !d.Blocked() {
		d = tx.Decision()
	}

	fired := map[uint32]bool{}
	for _, m := range tx.Matches() {
		fired[uint32(m.RuleID)] = true
	}
	if id := uint32(d.RuleID()); id != 0 {
		fired[id] = true
	}
	return d, fired
}

// judgeByDetection answers the parity question: blocked or not.
func judgeByDetection(out Output, d gwaf.Decision) Result {
	if out.expectsBlock() {
		if d.Blocked() {
			return Result{Passed: true}
		}
		return Result{Reason: "expected a detection, request was allowed"}
	}
	if d.Blocked() {
		// A stage whose only pass-assertion is "rule N must not fire" is not
		// asserting the request is clean. CRS writes these as tuning cases, and
		// several carry a real shell command or a real traversal — gwaf blocking
		// one is a *different* rule doing its job, not a false positive.
		//
		// Detection mode cannot tell the two apart, because it does not have CRS
		// rule IDs. So the block is reported with the ambiguity named rather than
		// filed as a false positive it may not be. Rule-ID mode answers it exactly.
		if ruleScopedPass(out) {
			return Result{Reason: fmt.Sprintf(
				"blocked by rule %d (%s) where CRS expects only a specific rule "+
					"not to fire -- ambiguous without CRS IDs", d.RuleID(), d.Message())}
		}
		return Result{Reason: fmt.Sprintf(
			"false positive: expected a clean pass, blocked by rule %d (%s)",
			d.RuleID(), d.Message())}
	}
	return Result{Passed: true}
}

// judgeByRuleID answers the bridge question: exactly which rules fired.
func judgeByRuleID(out Output, fired map[uint32]bool) Result {
	var missing, unexpected []string
	for _, id := range out.Log.ExpectIDs {
		if !fired[id] {
			missing = append(missing, strconv.FormatUint(uint64(id), 10))
		}
	}
	for _, id := range out.Log.NoExpectIDs {
		if fired[id] {
			unexpected = append(unexpected, strconv.FormatUint(uint64(id), 10))
		}
	}
	switch {
	case len(missing) > 0 && len(unexpected) > 0:
		return Result{Reason: "missing " + strings.Join(missing, ",") +
			"; unexpected " + strings.Join(unexpected, ",")}
	case len(missing) > 0:
		return Result{Reason: "rules did not fire: " + strings.Join(missing, ",")}
	case len(unexpected) > 0:
		return Result{Reason: "rules fired that should not: " + strings.Join(unexpected, ",")}
	}
	return Result{Passed: true}
}

// reflectedBody extracts the content the CRS harness echoes back as a response.
//
// The convention is a JSON body of the form {"body":"..."} posted to a
// reflecting endpoint; the harness returns that string, and the RESPONSE-95x
// tests assert on what a leak-detection rule makes of it. Parsed by hand rather
// than with encoding/json because the payloads are deliberately malformed --
// they carry unescaped quotes and control bytes, which is the point of them --
// and a strict parser would reject exactly the cases worth running.
func reflectedBody(in Input) ([]byte, bool) {
	body := in.Data
	if body == "" {
		body = in.EncodedData
	}
	const key = `"body"`
	i := strings.Index(body, key)
	if i < 0 {
		return nil, false
	}
	rest := body[i+len(key):]
	// Skip the colon and any spacing.
	j := 0
	for j < len(rest) && (rest[j] == ':' || rest[j] == ' ' || rest[j] == '\t') {
		j++
	}
	if j >= len(rest) || rest[j] != '"' {
		return nil, false
	}
	rest = rest[j+1:]
	// Take everything up to the last quote, which is the closing one for a
	// value that may itself contain quotes.
	k := strings.LastIndexByte(rest, '"')
	if k < 0 {
		return nil, false
	}
	return []byte(rest[:k]), true
}
