// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Command gwaf-seclang converts ModSecurity rule files into gwaf rules.
//
// Two modes, and the reporting one matters first:
//
//	gwaf-seclang report crs/*.conf              # what would come across, and what would not
//	gwaf-seclang convert -pkg crs crs/*.conf    # Go source
//
// Report before convert, because the number worth knowing before a migration is
// not how many rules arrive — it is which ones do not, and why. A conversion
// that silently drops a third of a ruleset is worse than no conversion, since
// the operator believes they migrated.
//
// It lives in the seclang module rather than in cmd/gwaf because it links a
// regex engine, and the core module carries no dependency an embedder did not
// ask for. That applies to a build-time tool as much as to the request path.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gsoultan/gwaf/seclang"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "report":
		err = run(os.Args[2:], false)
	case "convert":
		err = run(os.Args[2:], true)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "gwaf-seclang: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "gwaf-seclang: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gwaf-seclang -- convert ModSecurity rules to gwaf

  report   read the files and print what would and would not come across
  convert  emit Go source for the rules that would

  -pkg     package name for generated source (default "rules")
  -prefix  offset added to every imported rule ID, so imported rules cannot
           collide with rules you wrote or with gwaf's core ruleset
  -conf    confidence tier for imported rules: heuristic, low, medium, high,
           certain. Required, and deliberately so -- a SecLang rule arrives
           with a severity and a paranoia level and no measured false-positive
           rate, so picking a tier for you would assert something nobody has
           checked. Run 'gwaf calibrate' afterwards.
  -strict  fail on the first directive that cannot be translated faithfully

Read the report before trusting the conversion. What did not come across is
the part that matters.
`)
}

func run(args []string, generate bool) error {
	fs := flag.NewFlagSet("seclang", flag.ExitOnError)
	pkg := fs.String("pkg", "rules", "package name for generated source")
	prefix := fs.Uint("prefix", 0, "offset added to every imported rule ID")
	conf := fs.String("conf", "", "confidence tier for imported rules")
	strict := fs.Bool("strict", false, "fail on the first untranslatable directive")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("no input files")
	}

	tier, err := confidenceOf(*conf)
	if err != nil {
		return err
	}
	opts := seclang.Options{Prefix: uint32(*prefix), DefaultConfidence: tier}

	// Passed as separate sources rather than concatenated. SecLang is stateful
	// across files -- SecDefaultAction set in one applies to the next, and
	// SecRuleRemoveById routinely appears after the include that defined the
	// rule it removes -- and ParseSources compiles them in order for exactly
	// that reason, while still reporting each skip against the file it came
	// from.
	srcs := make([]seclang.Source, 0, fs.NArg())
	for _, name := range fs.Args() {
		b, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		srcs = append(srcs, seclang.Source{Name: name, Data: b})
	}
	opts.DataFiles = dataFileResolver(fs.Args())

	parse := seclang.ParseSources
	if *strict {
		parse = seclang.ParseSourcesStrict
	}
	set, rep, err := parse(srcs, opts)
	if err != nil {
		return err
	}

	if !generate {
		fmt.Println(rep.String())
		return nil
	}

	out, err := seclang.Generate(*pkg, set, rep)
	if err != nil {
		return err
	}
	// The report goes to stderr so stdout is only ever source, and a shell
	// redirect produces a file that compiles.
	fmt.Fprintln(os.Stderr, rep.String())
	_, err = os.Stdout.Write(out)
	return err
}

// dataFileResolver resolves @pmFromFile phrase lists against the directories
// holding the rule files, which is where ModSecurity looks and where a CRS
// release puts them: rules/*.data sits next to rules/*.conf.
//
// The library takes this as a function rather than opening files itself, so the
// only process that reads from disk is the one the user ran deliberately.
func dataFileResolver(inputs []string) func(string) ([]byte, error) {
	seen := map[string]bool{}
	var dirs []string
	for _, in := range inputs {
		d := filepath.Dir(in)
		if !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}

	return func(name string) ([]byte, error) {
		// A path with separators is taken as written, relative to each rule
		// directory; a bare name is looked up in all of them.
		for _, d := range dirs {
			if b, err := os.ReadFile(filepath.Join(d, name)); err == nil {
				return b, nil
			}
		}
		if b, err := os.ReadFile(name); err == nil {
			return b, nil
		}
		return nil, fmt.Errorf("not found in %s", strings.Join(dirs, ", "))
	}
}

func confidenceOf(s string) (seclang.Confidence, error) {
	switch strings.ToLower(s) {
	case "heuristic":
		return seclang.Heuristic, nil
	case "low":
		return seclang.Low, nil
	case "medium":
		return seclang.Medium, nil
	case "high":
		return seclang.High, nil
	case "certain":
		return seclang.Certain, nil
	case "":
		return 0, fmt.Errorf("-conf is required: an imported rule has no measured " +
			"false-positive rate, so gwaf will not pick a confidence tier for you")
	default:
		return 0, fmt.Errorf("unknown confidence %q", s)
	}
}
