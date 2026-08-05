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

	// Files are concatenated rather than each parsed alone, because SecLang is
	// stateful across them: SecDefaultAction set in one file applies to the
	// next, and SecRuleRemoveById routinely appears after the include that
	// defined the rule it removes.
	var src []byte
	for _, name := range fs.Args() {
		b, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		src = append(src, []byte("# ---- "+name+"\n")...)
		src = append(src, b...)
		src = append(src, '\n')
	}
	name := strings.Join(fs.Args(), ", ")

	parse := seclang.Parse
	if *strict {
		parse = seclang.ParseStrict
	}
	set, rep, err := parse(name, src, opts)
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
