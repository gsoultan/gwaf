package headtohead

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/test/conformance"
)

// TestCRSGapAnalysis reports what gwaf misses on the CRS regression corpus,
// grouped by the CRS rule family the test file belongs to.
//
// The head-to-head reports one number per engine, which says who wins and
// nothing about where. This says where, because the corpus is 4025 cases and a
// gap worth closing is a *family* of them rather than a scattering.
//
// Not a gate: it prints and passes. Many families are out of scope by design --
// scanner detection is a user-agent list, protocol enforcement is the
// embedder's parser -- and the point is to tell those apart from the ones that
// are gwaf's own job.
func TestCRSGapAnalysis(t *testing.T) {
	testDir := os.Getenv("CRS_TESTS")
	if testDir == "" {
		t.Skip("CRS_TESTS not set")
	}
	files, err := conformance.LoadTests(testDir)
	if err != nil {
		t.Fatalf("load tests: %v", err)
	}

	waf, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	e := gwafEngine{waf: waf}

	type stat struct{ hit, miss int }
	byFamily := map[string]*stat{}
	examples := map[string][]string{}

	for name, f := range files {
		if f.Meta.Enabled != nil && !*f.Meta.Enabled {
			continue
		}
		fam := familyOf(name)
		s := byFamily[fam]
		if s == nil {
			s = &stat{}
			byFamily[fam] = s
		}
		for _, tc := range f.Tests {
			for _, st := range tc.Stages {
				if st.Input.RawRequest != "" || st.Input.EncodedRequest != "" {
					continue
				}
				if !(len(st.Output.Log.ExpectIDs) > 0 || st.Output.Status == 403) {
					continue // only attack stages
				}
				if e.Blocks(st) {
					s.hit++
					continue
				}
				s.miss++
				if want := os.Getenv("GAP_FAMILY"); want != "" && fam == want && len(examples[fam]) < 40 {
					u := st.Input.URI
					if len(u) > 150 {
						u = u[:150]
					}
					b := st.Input.Data
					if len(b) > 110 {
						b = b[:110]
					}
					examples[fam] = append(examples[fam], "\n    URI="+u+"  BODY="+b)
				} else if len(examples[fam]) < 3 && os.Getenv("GAP_FAMILY") == "" {
					examples[fam] = append(examples[fam], tc.Title())
				}
			}
		}
	}

	fams := make([]string, 0, len(byFamily))
	for k := range byFamily {
		fams = append(fams, k)
	}
	sort.Slice(fams, func(i, j int) bool {
		return byFamily[fams[i]].miss > byFamily[fams[j]].miss
	})

	t.Logf("%-46s %6s %6s %7s", "CRS family", "hit", "miss", "rate")
	for _, k := range fams {
		s := byFamily[k]
		if s.hit+s.miss == 0 {
			continue
		}
		t.Logf("%-46s %6d %6d %6.1f%%   %s", k, s.hit, s.miss,
			100*float64(s.hit)/float64(s.hit+s.miss),
			strings.Join(examples[k], " | "))
	}
}

// familyOf reduces a test file name to its CRS rule family.
func familyOf(name string) string {
	base := name
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(base, ".yaml")
	// "942100" -> "942", the rule family; keep named files as they are.
	if len(base) >= 3 && base[0] >= '0' && base[0] <= '9' {
		return base[:3]
	}
	return base
}
