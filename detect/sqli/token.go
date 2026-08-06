// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package sqli

// kind classifies one lexical token.
type kind uint8

const (
	tkEOF kind = iota
	tkNumber
	tkString       // a closed quoted literal
	tkUnterminated // a quote that was opened and never closed
	tkIdent        // a bare word that is not a SQL keyword
	tkKeyword      // a SQL keyword
	tkOperator     // = < > ! + - * / % | & ^ ~
	tkLogic        // and or xor ||
	tkComment      // -- # /* */
	tkSemi
	tkLParen
	tkRParen
	tkComma
	tkDot
	tkOther
)

// token is one lexeme. Text aliases the input rather than copying, so
// tokenizing allocates nothing.
type token struct {
	kind kind
	text []byte
	off  int
}

// maxTokens bounds the token stream. A value that needs more than this to
// tokenize is not a query an origin would run; the bound keeps a pathological
// input from driving unbounded work, and the scorer never needs deep context.
const maxTokens = 256

// keywords are the SQL words whose presence changes the grammar.
//
// Deliberately narrow. Every word here is one that ordinary prose can contain,
// so recognising a word is never on its own evidence of anything — the scorer
// requires structure. Adding a word costs false positives and buys nothing
// unless some signal actually reads it.
var keywords = map[string]bool{
	"select": true, "union": true, "insert": true, "update": true,
	"delete": true, "drop": true, "from": true, "where": true,
	"table": true, "database": true, "into": true, "values": true,
	"set": true, "all": true, "distinct": true, "having": true,
	"group": true, "order": true, "by": true, "limit": true,
	"exec": true, "execute": true, "declare": true, "cast": true,
	"convert": true, "case": true, "when": true, "then": true,
	"else": true, "end": true, "null": true, "like": true,
	"truncate": true, "alter": true, "create": true, "grant": true,
	"waitfor": true, "delay": true, "shutdown": true, "sleep": true,
	"benchmark": true, "procedure": true, "outfile": true, "dumpfile": true,
	"load_file": true, "information_schema": true, "sysobjects": true,
	"is": true, "not": true, "in": true, "between": true, "exists": true,
}

// logicWords are the boolean connectors that let an injected condition attach
// to the query it is breaking into.
var logicWords = map[string]bool{
	"or": true, "and": true, "xor": true,
}

// dangerFuncs are functions whose only purpose in injected input is to prove
// execution or exfiltrate. A call to one of these is high-confidence on its own.
var dangerFuncs = map[string]bool{
	"sleep": true, "benchmark": true, "load_file": true, "pg_sleep": true,
	"extractvalue": true, "updatexml": true, "dbms_pipe": true,
	"waitfor": true, "randomblob": true, "char": true, "chr": true,
	"exec": true, "execute": true, "xp_cmdshell": true, "openrowset": true,
}

// dmlKeywords are the statements that matter after a statement separator.
var dmlKeywords = map[string]bool{
	"select": true, "insert": true, "update": true, "delete": true,
	"drop": true, "create": true, "alter": true, "truncate": true,
	"exec": true, "execute": true, "grant": true, "shutdown": true,
}

// context is the assumption a tokenization run makes about where in a query the
// input was interpolated.
//
// This is what makes quote-breaking detectable. "1' OR 1=1--" read literally is
// a number and an unterminated string, which is odd but not obviously an
// attack. Read as if it were interpolated *inside* a single-quoted literal, the
// leading quote **closes** that literal and the rest is a boolean condition and
// a comment that truncates the rest of the query — which is unambiguous.
//
// Every input is tokenized under each context and the strongest verdict wins,
// because the firewall does not know which one the origin will produce.
type context uint8

const (
	ctxNone      context = iota // the value is the whole expression
	ctxSingle                   // interpolated inside '...'
	ctxDouble                   // interpolated inside "..."
	ctxBacktick                 // interpolated inside `...` (MySQL identifier)
	contextCount = 4
)

// tokenize lexes src under the given context, appending to dst.
//
// It never allocates: token text aliases src, and dst is a caller-owned buffer
// reused across values.
func tokenize(dst []token, src []byte, ctx context) []token {
	dst = dst[:0]
	i := 0

	// Under a quoted context the value begins inside a literal, so everything
	// up to the first matching quote is data rather than code.
	switch ctx {
	case ctxSingle:
		i = closeQuote(src, '\'')
	case ctxDouble:
		i = closeQuote(src, '"')
	case ctxBacktick:
		i = closeQuote(src, '`')
	}
	if i < 0 {
		// The quote never closes, so this context cannot apply.
		return dst[:0]
	}

	for i < len(src) && len(dst) < maxTokens {
		c := src[i]

		switch {
		case isSpace(c):
			i++

		case c == '-' && i+1 < len(src) && src[i+1] == '-':
			dst = append(dst, token{kind: tkComment, text: src[i:], off: i})
			i = len(src)

		case c == '#':
			dst = append(dst, token{kind: tkComment, text: src[i:], off: i})
			i = len(src)

		case c == '/' && i+1 < len(src) && src[i+1] == '*' &&
			i+2 < len(src) && src[i+2] == '!':
			// MySQL executable comment. /*!...*/ runs in every version and
			// /*!NNNNN...*/ runs from version NNNNN, so the body is code, not a
			// comment: a tokenizer that swallowed it whole would never see the
			// UNION SELECT inside "/*!50000UNION*/ /*!50000SELECT*/", which is
			// the versionedmorekeywords / modsecurityversioned evasion. Skip the
			// "/*!" and any version digits; the body then tokenizes as SQL and
			// the closing "*/" is consumed by the tkComment-close case below.
			i += 3
			for i < len(src) && isDigit(src[i]) {
				i++
			}

		case c == '*' && i+1 < len(src) && src[i+1] == '/':
			// The close of an executable comment, treated as whitespace. A bare
			// "*/" is not valid SQL on its own, so skipping it never hides
			// structure a benign value depended on.
			i += 2

		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := indexFrom(src, i+2, "*/")
			if end < 0 {
				dst = append(dst, token{kind: tkComment, text: src[i:], off: i})
				i = len(src)
			} else {
				// An inline comment is whitespace to the parser, which is
				// exactly why it is used to split keywords: UNION/**/SELECT.
				dst = append(dst, token{kind: tkComment, text: src[i : end+2], off: i})
				i = end + 2
			}

		case c == '\'' || c == '"' || c == '`':
			start := i
			end := closeQuoteFrom(src, i+1, c)
			if end < 0 {
				dst = append(dst, token{kind: tkUnterminated, text: src[start:], off: start})
				i = len(src)
			} else {
				dst = append(dst, token{kind: tkString, text: src[start+1 : end], off: start})
				i = end + 1
			}

		case c >= '0' && c <= '9':
			start := i
			for i < len(src) && (isDigit(src[i]) || src[i] == '.' ||
				src[i] == 'x' || src[i] == 'X' || isHexLetter(src[i])) {
				i++
			}
			dst = append(dst, token{kind: tkNumber, text: src[start:i], off: start})

		case isIdentStart(c):
			start := i
			for i < len(src) && isIdentPart(src[i]) {
				i++
			}
			word := src[start:i]
			lower := lowerWord(word)
			k := tkIdent
			switch {
			case logicWords[lower]:
				k = tkLogic
			case keywords[lower]:
				k = tkKeyword
			}
			dst = append(dst, token{kind: k, text: word, off: start})

		case c == ';':
			dst = append(dst, token{kind: tkSemi, text: src[i : i+1], off: i})
			i++
		case c == '(':
			dst = append(dst, token{kind: tkLParen, text: src[i : i+1], off: i})
			i++
		case c == ')':
			dst = append(dst, token{kind: tkRParen, text: src[i : i+1], off: i})
			i++
		case c == ',':
			dst = append(dst, token{kind: tkComma, text: src[i : i+1], off: i})
			i++
		case c == '.':
			dst = append(dst, token{kind: tkDot, text: src[i : i+1], off: i})
			i++

		case c == '|' && i+1 < len(src) && src[i+1] == '|':
			// In several dialects "||" is boolean OR; in others it concatenates.
			// Either way it joins an injected fragment to the query.
			dst = append(dst, token{kind: tkLogic, text: src[i : i+2], off: i})
			i += 2

		case isOperator(c):
			start := i
			for i < len(src) && isOperator(src[i]) {
				i++
			}
			dst = append(dst, token{kind: tkOperator, text: src[start:i], off: start})

		default:
			dst = append(dst, token{kind: tkOther, text: src[i : i+1], off: i})
			i++
		}
	}
	return dst
}

// closeQuote returns the index just past the first q in src, or -1.
func closeQuote(src []byte, q byte) int {
	for i := 0; i < len(src); i++ {
		if src[i] == '\\' {
			i++
			continue
		}
		if src[i] == q {
			return i + 1
		}
	}
	return -1
}

// closeQuoteFrom returns the index of the closing quote at or after start.
func closeQuoteFrom(src []byte, start int, q byte) int {
	for i := start; i < len(src); i++ {
		if src[i] == '\\' {
			i++
			continue
		}
		// A doubled quote is an escaped quote in standard SQL, not a close.
		if src[i] == q {
			if i+1 < len(src) && src[i+1] == q {
				i++
				continue
			}
			return i
		}
	}
	return -1
}

func indexFrom(src []byte, start int, sub string) int {
	for i := start; i+len(sub) <= len(src); i++ {
		if string(src[i:i+len(sub)]) == sub {
			return i
		}
	}
	return -1
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHexLetter(c byte) bool {
	return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '@' || c == '$'
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || isDigit(c)
}

func isOperator(c byte) bool {
	switch c {
	case '=', '<', '>', '!', '+', '-', '*', '/', '%', '|', '&', '^', '~':
		return true
	}
	return false
}

// lowerWord returns an ASCII-lowercased copy of a short word.
//
// Words are bounded by maxWordLen so the fixed buffer never escapes to the
// heap; a longer word cannot be a SQL keyword anyway.
const maxWordLen = 32

func lowerWord(w []byte) string {
	if len(w) > maxWordLen {
		return ""
	}
	var buf [maxWordLen]byte
	for i := range w {
		c := w[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}
	return string(buf[:len(w)])
}
