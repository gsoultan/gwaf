// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package interpret

import "testing"

// TestBestFitReading covers characters that fold onto ASCII punctuation when the
// origin narrows them — NFKC in .NET and Java, best-fit in Windows — sent as the
// characters themselves rather than as a %u escape.
//
// ClassPercentU already claimed U+FF1C arrives as '<'. Claiming it for only one
// spelling was the gap: "＜script＞" walked through the pentest harness while
// "%uFF1Cscript%uFF1E" was blocked.
func TestBestFitReading(t *testing.T) {
	for _, tt := range []struct{ src, want string }{
		{"＜script＞alert(1)＜/script＞", "<script>alert(1)</script>"},
		{"＜img src=x onerror=alert(1)＞", "<img src=x onerror=alert(1)>"},
		{"1＇ OR ＇1＇=＇1", "1' OR '1'='1"},
		{"．．／．．／etc／passwd", "../../etc/passwd"},
	} {
		t.Run(tt.src, func(t *testing.T) {
			got, ok := readingFor(tt.src, ClassBestFit)
			if !ok {
				t.Fatalf("no best-fit reading for %q (classes %v)", tt.src, Detect([]byte(tt.src)))
			}
			if got != tt.want {
				t.Errorf("= %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBestFitSeesThroughPercentEncoding is the half that made the reading
// actually work.
//
// Readings are enumerated before the transform chain runs, so a value that
// arrived over a query string is still wearing its escapes: "＜" on the wire is
// "%EF%BC%9C". Folding only the raw bytes meant the reading fired in a unit test
// and never once in a request, which the pentest harness showed by blocking
// "%uFF1Cscript%uFF1E" and letting "%EF%BC%9Cscript%EF%BC%9E" straight through.
func TestBestFitSeesThroughPercentEncoding(t *testing.T) {
	for _, tt := range []struct{ src, want string }{
		{"%EF%BC%9Cscript%EF%BC%9E", "<script>"},
		{"%EF%BC%8E%EF%BC%8E%EF%BC%8Fetc", "../etc"},
		{"1%EF%BC%87 OR 1=1", "1' OR 1=1"},
	} {
		t.Run(tt.src, func(t *testing.T) {
			got, ok := readingFor(tt.src, ClassBestFit)
			if !ok {
				t.Fatalf("no best-fit reading for %q (classes %v)", tt.src, Detect([]byte(tt.src)))
			}
			if got != tt.want {
				t.Errorf("= %q, want %q", got, tt.want)
			}
		})
	}
}

// TestEntitiesSurvivePercentEncoding is the same blind spot in the entity class,
// and it was there for the same reason: readings are built before the transform
// chain, so a value from a query string still wears its escapes and "&#60;" is
// "%26%2360%3B". The literal-'&' scan found nothing, which is every entity
// payload a browser ever sends.
func TestEntitiesSurvivePercentEncoding(t *testing.T) {
	for _, tt := range []struct{ src, want string }{
		{"%26%2360%3Bscript%26%2362%3B", "<script>"},
		{"%26lt%3Bimg src=x%26gt%3B", "<img src=x>"},
		{"%26%23x3c%3Bscript%26%23x3e%3B", "<script>"},
	} {
		t.Run(tt.src, func(t *testing.T) {
			got, ok := readingFor(tt.src, ClassHTMLEntity)
			if !ok {
				t.Fatalf("no entity reading for %q (classes %v)", tt.src, Detect([]byte(tt.src)))
			}
			if got != tt.want {
				t.Errorf("= %q, want %q", got, tt.want)
			}
		})
	}
}

// TestEscapedMarkupStaysEscaped keeps the CMS case working through the new
// percent-aware path. "Use the <code>&lt;script&gt;</code> tag" is how every
// documentation page writes about script tags, and decoding the entities next to
// the raw tag turns correct escaping into a blocked request.
func TestEscapedMarkupStaysEscaped(t *testing.T) {
	for _, src := range []string{
		"Use the <code>&lt;script&gt;</code> tag",
		"Use%20the%20%3Ccode%3E%26lt%3Bscript%26gt%3B%3C%2Fcode%3E%20tag",
	} {
		if _, ok := readingFor(src, ClassHTMLEntity); ok {
			t.Errorf("built an entity reading for escaped markup: %q", src)
		}
	}
}

// TestBestFitLeavesOrdinaryTextAlone is the constraint that keeps the reading
// narrow enough to ship. Fullwidth letters and digits are ordinary Japanese,
// Chinese and Korean input; folding them would be inventing text nobody sent,
// and only punctuation is ever ambiguous in the way that matters.
func TestBestFitLeavesOrdinaryTextAlone(t *testing.T) {
	for _, src := range []string{
		"全角文字のテスト：カタカナとひらがな",
		"価格は１２３４円です",
		"한국어 검색어 테스트",
		"Ｈｅｌｌｏ ｗｏｒｌｄ",
		"naïve café résumé",
		"an em—dash and “curly quotes”",
	} {
		if Detect([]byte(src)).Has(ClassBestFit) {
			// Claiming the class is not itself wrong, but the folded reading must
			// not differ from the original for text that carries no foldable
			// punctuation.
			got, _ := readingFor(src, ClassBestFit)
			if got != src {
				t.Errorf("folded ordinary text %q into %q", src, got)
			}
		}
	}
}
