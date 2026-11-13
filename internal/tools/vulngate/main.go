// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Command vulngate is the narrow exception mechanism behind `make vuln`.
//
// govulncheck has no ignore list, and that is mostly a virtue: CLAUDE.md §4 says
// fix findings, do not annotate them away. The one case it cannot handle is an
// advisory with no fixed version. GO-2026-6875 and GO-2026-6872 describe
// defaults in Echo's own reverse-proxy and rate-limiter middleware, which the
// gwaf Echo adapter never uses, yet they list core response methods every Echo
// program calls, and no Echo release fixes them. A gate that stays red on a
// finding nobody can act on is a gate people learn to ignore.
//
// So an exception is allowed only when all of these hold, and the gate fails the
// moment one stops holding:
//
//   - it names one advisory ID in one module, with a written reason;
//   - the advisory still has no fixed version (once one ships, upgrade);
//   - the advisory is still reported (a stale exception is removed, not kept).
//
// Every other finding that govulncheck reports as called fails the gate exactly
// as `govulncheck ./...` would. vulngate runs `govulncheck -format json ./...`
// in the module itself, so a scan that fails to run fails the gate.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

func main() {
	module := flag.String("module", "", "module directory being judged, as listed in the allow file")
	allowPath := flag.String("allow", "", "path to the exception file")
	tool := flag.String("govulncheck", "", "path to the govulncheck binary")
	flag.Parse()
	if *module == "" || *allowPath == "" || *tool == "" {
		fmt.Fprintln(os.Stderr, "vulngate: -module, -allow and -govulncheck are required")
		os.Exit(2)
	}
	f, err := os.Open(*allowPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vulngate: %v\n", err)
		os.Exit(2)
	}
	allow, err := parseAllow(f, *module)
	f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "vulngate: %s: %v\n", *allowPath, err)
		os.Exit(2)
	}
	problems, err := scan(*tool, *module, allow)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vulngate: %v\n", err)
		os.Exit(2)
	}
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		os.Exit(1)
	}
	fmt.Printf("vulngate %s: no called vulnerabilities beyond %d documented exception(s)\n", *module, len(allow))
}

// scan runs govulncheck over the module and judges its JSON stream. With
// -format json govulncheck exits zero whatever it finds, so a non-zero exit
// means the scan itself failed, and that fails the gate.
func scan(tool, module string, allow map[string]string) ([]string, error) {
	cmd := exec.Command(tool, "-format", "json", "./...")
	cmd.Dir = module
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting govulncheck: %w", err)
	}
	problems, judgeErr := judge(out, allow)
	// Drain whatever judge did not read, so a decode error cannot leave
	// govulncheck blocked on a full pipe and Wait hung on it.
	_, _ = io.Copy(io.Discard, out)
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("govulncheck in %s: %w", module, err)
	}
	return problems, judgeErr
}

// parseAllow reads "<module> <OSV-ID> <reason...>" lines for one module.
// Blank lines and lines starting with '#' are comments. A line with no reason
// is an error: an exception nobody can explain is not an exception.
func parseAllow(r io.Reader, module string) (map[string]string, error) {
	allow := map[string]string{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("line %d: want \"<module> <OSV-ID> <reason>\", got %q", n, line)
		}
		if fields[0] == module {
			allow[fields[1]] = strings.Join(fields[2:], " ")
		}
	}
	return allow, sc.Err()
}

type message struct {
	Config  *json.RawMessage `json:"config"`
	OSV     *osvEntry        `json:"osv"`
	Finding *finding         `json:"finding"`
}

type osvEntry struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type finding struct {
	OSV          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []frame `json:"trace"`
}

type frame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Function string `json:"function"`
}

// called reports whether govulncheck traced the finding to a function, which is
// the level at which `govulncheck ./...` fails.
func (f *finding) called() bool {
	return len(f.Trace) > 0 && f.Trace[0].Function != ""
}

// judge returns one line per problem: a called finding with no exception, an
// exception whose advisory now has a fix, or an exception that matched nothing.
func judge(r io.Reader, allow map[string]string) ([]string, error) {
	dec := json.NewDecoder(r)
	summaries := map[string]string{}
	called := map[string]*finding{}
	sawConfig := false
	for {
		var m message
		if err := dec.Decode(&m); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("reading govulncheck output: %w", err)
		}
		switch {
		case m.Config != nil:
			sawConfig = true
		case m.OSV != nil:
			summaries[m.OSV.ID] = m.OSV.Summary
		case m.Finding != nil && m.Finding.called():
			if _, seen := called[m.Finding.OSV]; !seen {
				called[m.Finding.OSV] = m.Finding
			}
		}
	}
	// No config message means govulncheck did not run, and an empty scan must
	// never read as a clean one (CLAUDE.md §6).
	if !sawConfig {
		return nil, errors.New("no govulncheck output: the scan did not run")
	}

	var problems []string
	for id, f := range called {
		reason, excepted := allow[id]
		switch {
		case !excepted:
			problems = append(problems, fmt.Sprintf("%s: %s (in %s@%s, fixed in %s)",
				id, summaries[id], f.Trace[0].Module, f.Trace[0].Version, orNone(f.FixedVersion)))
		case f.FixedVersion != "":
			problems = append(problems, fmt.Sprintf("%s: a fix now exists (%s); upgrade and delete the exception (%s)",
				id, f.FixedVersion, reason))
		}
	}
	for id := range allow {
		if _, ok := called[id]; !ok {
			problems = append(problems, fmt.Sprintf("%s: excepted but no longer reported; delete the stale exception", id))
		}
	}
	sort.Strings(problems)
	return problems, nil
}

func orNone(v string) string {
	if v == "" {
		return "N/A"
	}
	return v
}
