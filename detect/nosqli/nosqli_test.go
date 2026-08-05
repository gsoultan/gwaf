// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package nosqli

import (
	"strings"
	"testing"
)

func TestOperatorInjectionIsDetected(t *testing.T) {
	cases := []struct {
		name string
		want Signal
	}{
		// The authentication bypass, in every shape it arrives.
		{"$ne", SignalQueryOperator},
		{"$gt", SignalQueryOperator},
		{"$gte", SignalQueryOperator},
		{"$regex", SignalQueryOperator},
		{"$exists", SignalQueryOperator},
		{"$nin", SignalQueryOperator},
		{"$elemMatch", SignalQueryOperator},

		// Nested, as the JSON parser reports it.
		{"password.$ne", SignalQueryOperator},
		{"user.profile.email.$regex", SignalQueryOperator},

		// Bracket notation: Express, PHP, and Rails all expand this into a
		// nested object before the database sees it.
		{"password[$ne]", SignalQueryOperator},
		{"user[$gt]", SignalQueryOperator},
		{"filter[age][$gte]", SignalQueryOperator},

		// Code execution inside the database engine.
		{"$where", SignalEvalOperator},
		{"$function", SignalEvalOperator},
		{"$accumulator", SignalEvalOperator},
		{"$expr", SignalEvalOperator},
		{"query.$where", SignalEvalOperator},

		// Logical operators used to rewrite the query shape.
		{"$or", SignalQueryOperator},
		{"$and", SignalQueryOperator},
		{"$nor", SignalQueryOperator},
	}

	d := New()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := d.Analyze([]byte(c.name))
			if !v.Detected() {
				t.Errorf("not detected: score=%d signals=%v", v.Score, v.Signals)
			}
			if v.Signals&c.want == 0 {
				t.Errorf("signals = %v, want %v set", v.Signals, c.want)
			}
		})
	}
}

// TestBenignNamesPass is the counterweight, and it is the larger table on
// purpose. A detector that blocks every $-prefixed key would score perfectly on
// the table above and be unusable.
func TestBenignNamesPass(t *testing.T) {
	names := []string{
		// Ordinary parameter names.
		"username", "password", "page", "per_page", "sort", "order",
		"user.profile.email", "items[0].price", "filter[age]",
		"X-Request-Id", "utm_source", "q", "id",

		// JSON Schema and JSON reference. An API that accepts or echoes a
		// schema document sends every one of these.
		"$schema", "$ref", "$id", "$defs", "$comment", "$anchor",
		"$vocabulary", "$dynamicRef", "$dynamicAnchor",
		"components.schemas.Order.$ref",

		// OData system query options. A published standard with a large
		// installed base; blocking these is a bigger outage than the attack.
		"$filter", "$select", "$top", "$skip", "$orderby", "$expand",
		"$count", "$format", "$search", "$apply", "$compute",

		// Serialisation and framework internals that get round-tripped.
		"$values", "$$hashKey", "$async", "$meta",

		// Mutation operators alone are suspicious, not conclusive: an
		// application proxying a partial update sends these itself.
		"$set", "$inc", "$push", "$unset", "$addToSet",

		// Ambiguous: Json.NET writes $type for polymorphic payloads.
		"$type",

		// Dollars that are not operators at all.
		"$", "$$", "price$", "total_$usd", "$custom_field", "$$$",
	}

	d := New()
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			if v := d.Analyze([]byte(n)); v.Detected() {
				t.Errorf("false positive: score=%d signals=%v", v.Score, v.Signals)
			}
		})
	}
}

// TestMaximalMunch checks that a token is read to its end. "$in" is a prefix of
// "$inc", and reading the short one first would misclassify a mutation operator
// as a query operator — and, worse, report it at a confidence it has not earned.
func TestMaximalMunch(t *testing.T) {
	d := New()

	if v := d.Analyze([]byte("$inc")); v.Signals != SignalUpdateOperator {
		t.Errorf("$inc signals = %v, want update_operator only", v.Signals)
	}
	if v := d.Analyze([]byte("$in")); v.Signals != SignalQueryOperator {
		t.Errorf("$in signals = %v, want query_operator", v.Signals)
	}
	if v := d.Analyze([]byte("$nor")); v.Signals != SignalQueryOperator {
		t.Errorf("$nor signals = %v, want query_operator", v.Signals)
	}
	if v := d.Analyze([]byte("$not")); v.Signals != SignalQueryOperator {
		t.Errorf("$not signals = %v, want query_operator", v.Signals)
	}
}

// TestCorroboration checks that weak signals combine. Neither a mutation
// operator nor an ambiguous one fires alone; together they are a document the
// attacker shaped.
func TestCorroboration(t *testing.T) {
	d := New()

	if v := d.Analyze([]byte("$set")); v.Detected() {
		t.Error("$set fired alone")
	}
	if v := d.Analyze([]byte("$type")); v.Detected() {
		t.Error("$type fired alone")
	}
	if v := d.Analyze([]byte("a[$set][$type]")); !v.Detected() {
		t.Errorf("$set + $type did not corroborate: score=%d", v.Score)
	}
}

// TestCaseSensitivity records a deliberate limit. MongoDB rejects "$NE", so
// matching it would add surface with no corresponding attack.
func TestCaseSensitivity(t *testing.T) {
	d := New()
	for _, n := range []string{"$NE", "$Ne", "$WHERE", "$Where"} {
		if v := d.Analyze([]byte(n)); v.Detected() {
			t.Errorf("%q detected, but the database would reject it", n)
		}
	}
}

func TestSpanPointsAtTheOperator(t *testing.T) {
	d := New()
	v := d.Analyze([]byte("password[$ne]"))
	if !v.Detected() {
		t.Fatal("not detected")
	}
	got := "password[$ne]"[v.Span.Off : v.Span.Off+v.Span.Len]
	if got != "$ne" {
		t.Errorf("span covers %q, want %q", got, "$ne")
	}
}

func TestEmptyAndBounds(t *testing.T) {
	d := New()
	if v := d.Analyze(nil); v.Detected() {
		t.Error("nil detected")
	}
	if v := d.Analyze([]byte{}); v.Detected() {
		t.Error("empty detected")
	}
	// A name far past the scan bound must still terminate and stay bounded.
	long := strings.Repeat("a", maxScan*4) + "$ne"
	if v := d.Analyze([]byte(long)); v.Detected() {
		t.Error("an operator past the scan bound was reported")
	}
	// A token longer than any real operator is not one.
	if v := d.Analyze([]byte("$" + strings.Repeat("x", maxTokenLen*2))); v.Detected() {
		t.Error("an over-long token was classified")
	}
}

// TestLiteralsCoverEveryDetection is the claim the prefilter depends on, and it
// is enforced rather than asserted: if Analyze reports a name, at least one
// declared literal must appear in it, or the prefilter would exclude the value
// and the rule would silently never fire.
//
// This is the same failure that chain grouping was built to fix — a rule that
// compiles, lints clean, and never matches anything.
func TestLiteralsCoverEveryDetection(t *testing.T) {
	// The union of every mask: what the two core rules declare together.
	all := SignalQueryOperator | SignalEvalOperator |
		SignalUpdateOperator | SignalAmbiguousOperator
	o := Operator(all).(*operator)
	lits, ok := o.Literals()
	if !ok {
		t.Fatal("operator declares no literals, so it cannot be prefiltered")
	}

	covered := func(name string) bool {
		for _, l := range lits {
			if strings.Contains(name, l) {
				return true
			}
		}
		return false
	}

	// Every token the classifier recognises, spelled out. Kept explicit so a
	// new operator added to classify without a literal fails here.
	tokens := []string{
		"$where", "$function", "$accumulator", "$expr",
		"$ne", "$eq", "$gt", "$gte", "$lt", "$lte", "$in", "$nin",
		"$regex", "$options", "$exists", "$mod", "$all", "$size",
		"$elemMatch", "$not", "$or", "$and", "$nor",
		"$bitsAllSet", "$bitsAnySet", "$bitsAllClear", "$bitsAnyClear",
		"$geoWithin", "$geoIntersects", "$near", "$nearSphere",
		"$jsonSchema",
		"$set", "$unset", "$inc", "$mul", "$rename", "$push", "$pull",
		"$pullAll", "$addToSet", "$pop", "$each", "$position", "$slice",
		"$sort", "$currentDate", "$setOnInsert", "$bit",
		"$type",
	}
	for _, tok := range tokens {
		if classify(tok) == 0 {
			t.Errorf("%q is in the literal list but classify does not know it", tok)
		}
		if !covered(tok) {
			t.Errorf("%q is classified but no literal covers it: unprefilterable", tok)
		}
	}
}

// FuzzLiteralsAreExhaustive is the harness behind the same claim. Any input the
// detector reports must contain a declared literal.
func FuzzLiteralsAreExhaustive(f *testing.F) {
	for _, s := range []string{
		"$ne", "password[$ne]", "a.$where", "$set", "$$hashKey", "$filter",
		"user", "", "$", "$$$$", "$regex$where", "\x00$ne",
	} {
		f.Add(s)
	}

	d := New()
	all := SignalQueryOperator | SignalEvalOperator |
		SignalUpdateOperator | SignalAmbiguousOperator
	o := Operator(all).(*operator)
	lits, _ := o.Literals()

	f.Fuzz(func(t *testing.T, name string) {
		if !d.Analyze([]byte(name)).Detected() {
			return
		}
		for _, l := range lits {
			if strings.Contains(name, l) {
				return
			}
		}
		t.Fatalf("detected %q but no literal covers it: the prefilter would drop it", name)
	})
}

func BenchmarkAnalyzeBenign(b *testing.B) {
	d := New()
	name := []byte("user.profile.email")
	b.ReportAllocs()
	for b.Loop() {
		d.Analyze(name)
	}
}

func BenchmarkAnalyzeAttack(b *testing.B) {
	d := New()
	name := []byte("password[$ne]")
	b.ReportAllocs()
	for b.Loop() {
		d.Analyze(name)
	}
}
