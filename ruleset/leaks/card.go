// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package leaks

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// cardNumber matches a payment card number in a value.
//
// The usual regex for this, `\b4[0-9]{12}(?:[0-9]{3})?\b`, is wrong in both
// directions at once. It misses every brand that is not Visa — Mastercard, Amex, Discover,
// JCB, Diners, UnionPay — so a rule advertised as "card number in response"
// covers roughly half the cards in circulation. And it matches any sixteen
// digits beginning with a 4, so an order id, a timestamp in microseconds or an
// account number blocks the response at Critical severity. A data-leak control
// that blocks a page because the order number started with a 4 is a control that
// gets switched off, which is the worse failure of the two.
//
// What actually identifies a card is structure, not shape: an issuer prefix from
// a known range, a length that range permits, and a Luhn check digit. All three
// together are cheap and reject essentially everything that is not a card.
//
// It is stateless and safe for concurrent use.
type cardNumber struct{}

// CardNumber returns an operator matching payment card numbers: an assigned
// issuer prefix, a length that issuer uses, and a valid Luhn check digit, with
// space or hyphen grouping tolerated. It is the operator behind IDCardNumber,
// exported so an embedder can point it at a target of its own choosing.
//
// It declares no literals, so a rule using it is unconditional and runs on
// every value it targets.
func CardNumber() rules.Operator { return &cardNumber{} }

// Name implements rules.Operator.
func (o *cardNumber) Name() string { return "cardPAN" }

// maxPANDigits is the longest card number ISO/IEC 7812 permits. A digit run
// longer than this is an identifier of some other kind, and treating it as a
// window to search for a card inside would reintroduce the false positives this
// operator exists to remove.
const maxPANDigits = 19

// minPANDigits is the shortest number any supported brand issues.
const minPANDigits = 13

// Eval implements rules.Operator.
//
// Separators are tolerated because a leaked card is as likely to be rendered
// "4111 1111 1111 1111" in an invoice as stored bare in JSON.
func (o *cardNumber) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	var digits [maxPANDigits]byte

	for i := 0; i < len(value); {
		if !isDigit(value[i]) {
			i++
			continue
		}
		// A run is only a candidate at its own start. A digit before it means
		// this is the middle of a longer run; a separator before it means the
		// same only when that separator is itself joining digits, which is what
		// distinguishes "1111 2222 3333 4444" from the space in "signature
		// 341111111111111".
		if i > 0 && isDigit(value[i-1]) {
			i++
			continue
		}
		if i > 1 && isPANSeparator(value[i-1]) && isDigit(value[i-2]) {
			i++
			continue
		}
		n, end := collectPANDigits(value, i, digits[:])
		if n >= minPANDigits && n <= maxPANDigits &&
			panBrandAllowsLength(digits[:n]) && luhnValid(digits[:n]) {
			return rules.Match{Span: types.SpanOf(i, end-i)}, true
		}
		i = end
		// Step past whatever terminated the run so the next iteration does not
		// re-enter it from the second digit.
		for i < len(value) && (isDigit(value[i]) || isPANSeparator(value[i])) {
			i++
		}
	}
	return rules.Match{}, false
}

// collectPANDigits reads a separated digit run starting at off, writing its
// digits into dst. It returns how many digits it found — more than len(dst) if
// the run overruns, which disqualifies it — and where the run ended.
func collectPANDigits(value []byte, off int, dst []byte) (n, end int) {
	i := off
	for i < len(value) {
		switch {
		case isDigit(value[i]):
			if n < len(dst) {
				dst[n] = value[i] - '0'
			}
			n++
			if n > len(dst) {
				// Too long to be a card. Consume the rest so the caller skips it
				// whole rather than looking for a card inside it.
				for i < len(value) && (isDigit(value[i]) || isPANSeparator(value[i])) {
					i++
				}
				return n, i
			}
			i++
			end = i
		case isPANSeparator(value[i]) && i+1 < len(value) && isDigit(value[i+1]):
			// A separator only continues the run if a digit follows it; a
			// trailing hyphen belongs to whatever comes next.
			i++
		default:
			return n, end
		}
	}
	return n, end
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// isPANSeparator reports the characters a card number is grouped with when
// written for a human.
func isPANSeparator(b byte) bool { return b == ' ' || b == '-' }

// panRange is one issuer allocation: a prefix range compared over its first
// `digits` digits, and the card lengths that range is issued at.
//
// A table rather than a chain of conditions, because this is reference data —
// it changes when a network opens a new BIN range, and a reader checking it
// against the network's published list should be able to read down a column.
type panRange struct {
	digits         int // how many leading digits the range compares
	lo, hi         int // inclusive prefix range over those digits
	minLen, maxLen int // card lengths this range is issued at
}

// panRanges are the issuer allocations this operator recognises.
//
// Maestro (50, 56-69) is deliberately absent: its range overlaps most national
// debit schemes and admits twelve-digit numbers, so including it would put back
// the false positives this operator exists to remove. A Maestro card is not
// detected, and that is a stated gap rather than a silent one.
var panRanges = [...]panRange{
	{1, 4, 4, 13, 13},           // Visa
	{1, 4, 4, 16, 16},           // Visa
	{1, 4, 4, 19, 19},           // Visa
	{2, 51, 55, 16, 16},         // Mastercard
	{4, 2221, 2720, 16, 16},     // Mastercard, 2-series
	{2, 34, 34, 15, 15},         // American Express
	{2, 37, 37, 15, 15},         // American Express
	{4, 6011, 6011, 16, 19},     // Discover
	{2, 65, 65, 16, 19},         // Discover
	{3, 644, 649, 16, 19},       // Discover
	{6, 622126, 622925, 16, 19}, // Discover / UnionPay co-brand
	{4, 3528, 3589, 16, 19},     // JCB
	{2, 36, 36, 14, 19},         // Diners Club
	{2, 38, 39, 14, 19},         // Diners Club
	{3, 300, 305, 14, 19},       // Diners Club
	{2, 62, 62, 16, 19},         // China UnionPay
}

// panBrandAllowsLength reports whether digits open with an issuer prefix that is
// actually assigned, at a length that issuer uses.
//
// The pairing matters as much as the prefix: Amex is 15 digits and Mastercard is
// 16, so a 16-digit number starting 34 is not an Amex card with a typo — it is
// not a card.
//
// This runs once per candidate digit run, which on a page full of numeric ids is
// once per id, so the table is not walked naively: the leading digit rejects
// most values before the loop, and the prefix values the loop compares are
// computed once rather than per row.
func panBrandAllowsLength(digits []byte) bool {
	n := len(digits)
	if !panLeadingDigits[digits[0]] {
		return false
	}
	// prefix[k] is the first k digits read as a number, for the k values the
	// table compares. Indexed from 1 so the write is bounded by len(prefix)
	// directly rather than by a constant that happens to be one less: the
	// bound is then obvious to a reader and provable to a static analyser,
	// which the arithmetic form was not.
	var prefix [maxPANPrefixDigits + 1]int
	p := 0
	for i := 1; i < len(prefix) && i <= n; i++ {
		p = p*10 + int(digits[i-1])
		prefix[i] = p
	}
	for _, r := range panRanges {
		if n < r.minLen || n > r.maxLen {
			continue
		}
		if v := prefix[r.digits]; v >= r.lo && v <= r.hi {
			return true
		}
	}
	return false
}

// maxPANPrefixDigits is the widest prefix any row in panRanges compares.
const maxPANPrefixDigits = 6

// panLeadingDigits is the set of first digits any assigned range starts with.
// Half of all numeric ids fail here for the cost of one array lookup.
var panLeadingDigits = func() [256]bool {
	var set [256]bool
	for _, r := range panRanges {
		lead := r.lo
		for lead >= 10 {
			lead /= 10
		}
		set[lead] = true
	}
	return set
}()

// luhnValid runs the ISO/IEC 7812 check digit over digits.
func luhnValid(digits []byte) bool {
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		v := int(digits[i])
		if double {
			if v *= 2; v > 9 {
				v -= 9
			}
		}
		sum += v
		double = !double
	}
	return sum%10 == 0
}

// Literals implements rules.Operator.
//
// A card number has no required substring — every brand, length and check digit
// combination differs — so there is nothing honest to prefilter on. Saying so
// puts this rule in the compile report's Unconditional list, which is the right
// place for a cost that is paid on every value the rule targets.
func (o *cardNumber) Literals() ([]string, bool) { return nil, false }

// Cost implements rules.Operator.
//
// One pass over the value with no allocation and no backtracking: cheaper than
// the regex it replaces, which was charged per byte at the regex rate.
func (o *cardNumber) Cost() types.Fuel { return types.CostCustomOperator }
