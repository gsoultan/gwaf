// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf

import (
	"github.com/gsoultan/gwaf/types"
)

// Derived collections.
//
// ARGS_GET, ARGS_POST, ARGS_JOINED, REQUEST_COOKIES and REQUEST_COOKIE_NAMES
// were defined in types, accepted by the compiler, linted clean, and mapped
// from their SecLang names by the bridge -- and no transaction ever recorded a
// value under any of them. A rule on one compiled, loaded, and could never
// match. Every CRS rule reading REQUEST_COOKIES was inert, and so was every
// embedder rule on a cookie, with nothing anywhere saying so.
//
// They are views over values already recorded rather than values recorded at
// each source, for two reasons. A view cannot disagree with the collection it
// is cut from: ARGS_GET holds exactly the query readings ARGS holds -- the ';'
// reading, the joined duplicates, the schema-inert marks -- because it is the
// same entries, not a second parse. And a view costs nothing to build when no
// rule reads it, which is the common case: the core ruleset reads none of them,
// so the benign-request SLOs see one bitmask test per kind and no more.
//
// The views share spans with the values they are cut from. Nothing is copied
// except ARGS_JOINED, which is new bytes by definition.

// queryCut returns the index in values where query data ends.
//
// Everything recorded before the header phase ran is request-line and header
// data -- including arguments an embedder supplied with AddArgument at that
// point, which is how the query is handed over when it is parsed elsewhere --
// and everything after it is body data. A body recorded before the header
// phase ran ends the query where it begins.
func (tx *Transaction) queryCut() int {
	end := tx.queryEnd
	if end < 0 {
		end = len(tx.values)
	}
	if tx.bodyStart >= 0 && tx.bodyStart < end {
		end = tx.bodyStart
	}
	return end
}

// deriveHeaderViews records ARGS_GET and the cookie collections. It reports
// false when the request carries more cookies than MaxArgs: dropping the rest
// would be a padding bypass, so the caller refuses the request per the fail
// mode instead, exactly as it does for too many arguments.
func (tx *Transaction) deriveHeaderViews() bool {
	if tx.headerViewsDone {
		return true
	}
	tx.headerViewsDone = true
	end := tx.queryCut()
	if tx.rs.Reads(types.TargetArgsGet) {
		tx.copyArgs(0, end, types.TargetArgsGet)
	}
	if tx.rs.Reads(types.TargetRequestCookies) || tx.rs.Reads(types.TargetRequestCookieNames) {
		return tx.recordCookies(end)
	}
	return true
}

// deriveBodyViews records ARGS_POST and ARGS_JOINED.
func (tx *Transaction) deriveBodyViews() {
	if tx.bodyViewsDone {
		return
	}
	tx.bodyViewsDone = true
	end := len(tx.values)
	if tx.rs.Reads(types.TargetArgsPost) {
		tx.copyArgs(tx.queryCut(), end, types.TargetArgsPost)
	}
	if tx.rs.Reads(types.TargetArgsJoined) {
		tx.joinArgs(end)
	}
}

// copyArgs records every ARGS entry in values[from:to] again under kind.
func (tx *Transaction) copyArgs(from, to int, kind types.TargetKind) {
	for i := from; i < to; i++ {
		v := tx.values[i]
		if v.Target.Kind != types.TargetArgs {
			continue
		}
		tx.appendValue(types.Target{Kind: kind, Name: v.Target.Name},
			tx.spans[i].key, tx.spans[i].data, v.Inert)
	}
}

// joinArgs records ARGS_JOINED: every ARGS value in values[:end], in the order
// recorded, concatenated with no separator.
//
// No separator because the evasion it exists for is a payload split mid-token:
// "a=UNI&b=ON SEL&c=ECT" is "UNION SELECT" only when nothing is put between the
// pieces. The view includes every reading ARGS holds, not only the wire values,
// since those are the values the per-argument rules were given too.
//
// A joined value over MaxValueLen is reported as oversize rather than cut short,
// for the reason noteOversize gives: inspecting a prefix and calling the rest
// clean is a padding bypass.
func (tx *Transaction) joinArgs(end int) {
	total := 0
	for i := range end {
		if tx.values[i].Target.Kind == types.TargetArgs {
			total += int(tx.spans[i].data.Len)
		}
	}
	if total == 0 {
		return
	}
	if total > tx.waf.cfg.limits.MaxValueLen {
		tx.noteOversize(types.TargetArgsJoined.String(), total)
		return
	}
	span, dst, ok := tx.arena.Alloc(total)
	if !ok {
		return
	}
	// Sources are re-resolved after the allocation, because Alloc may have
	// moved the arena and every slice cut before it would then point at the
	// abandoned copy.
	n := 0
	for i := range end {
		if tx.values[i].Target.Kind == types.TargetArgs {
			n += copy(dst[n:], tx.arena.Resolve(tx.spans[i].data))
		}
	}
	tx.appendValue(types.Target{Kind: types.TargetArgsJoined}, types.Span{}, span, false)
}

// recordCookies splits every Cookie header in values[:end] into
// REQUEST_COOKIES (keyed by name) and REQUEST_COOKIE_NAMES.
//
// Pairs are split on ';' and trimmed of optional whitespace, and nothing is
// decoded: decoding belongs to the transform chain, as it does for query
// arguments. A pair with no '=' is recorded with the whole pair as both its name
// and its value, because origins disagree -- a browser sends it as a nameless
// cookie, some parsers read it as a name with no value -- and a value an
// attacker chose is worth inspecting under either reading. Several Cookie
// headers, which is how HTTP/2 sends them, are each split in turn.
func (tx *Transaction) recordCookies(end int) bool {
	count := 0
	for i := range end {
		v := tx.values[i]
		if v.Target.Kind != types.TargetRequestHeaders || !isCookieHeader(v.Key) {
			continue
		}
		base := tx.spans[i].data
		data := v.Data
		for start := 0; start <= len(data); {
			stop := start
			for stop < len(data) && data[stop] != ';' {
				stop++
			}
			if !tx.recordCookiePair(base, data, start, stop, &count) {
				return false
			}
			start = stop + 1
		}
	}
	return true
}

// recordCookiePair records one "name=value" piece of a Cookie header, given as
// data[start:stop] within the header value whose arena span is base.
func (tx *Transaction) recordCookiePair(base types.Span, data []byte, start, stop int, count *int) bool {
	start, stop = trimOWSRange(data, start, stop)
	if start == stop {
		return true
	}
	*count++
	if *count > tx.waf.cfg.limits.MaxArgs {
		return false
	}
	nameEnd, valStart := stop, start
	for j := start; j < stop; j++ {
		if data[j] == '=' {
			nameEnd, valStart = j, j+1
			break
		}
	}
	nameStart, nameEnd := trimOWSRange(data, start, nameEnd)
	valStart, valEnd := trimOWSRange(data, valStart, stop)
	name := subSpan(base, nameStart, nameEnd)
	value := subSpan(base, valStart, valEnd)
	tx.appendValue(types.Target{Kind: types.TargetRequestCookies}, name, value, false)
	tx.appendValue(types.Target{Kind: types.TargetRequestCookieNames}, name, name, false)
	return true
}

// isCookieHeader reports whether a header name is Cookie, in any case, without
// converting it to a string.
func isCookieHeader(name []byte) bool {
	const want = "cookie"
	if len(name) != len(want) {
		return false
	}
	for i := range len(want) {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != want[i] {
			return false
		}
	}
	return true
}

// trimOWSRange narrows data[start:stop] past leading and trailing spaces and
// tabs.
func trimOWSRange(data []byte, start, stop int) (int, int) {
	for start < stop && (data[start] == ' ' || data[start] == '\t') {
		start++
	}
	for stop > start && (data[stop-1] == ' ' || data[stop-1] == '\t') {
		stop--
	}
	return start, stop
}

// subSpan is the span of base[start:stop].
func subSpan(base types.Span, start, stop int) types.Span {
	return types.Span{Off: base.Off + uint32(start), Len: uint32(stop - start)}
}
