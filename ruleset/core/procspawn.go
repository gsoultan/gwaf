// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
)

// processSpawn reports a call to an API whose only purpose is to run a command.
//
// # What this covers that nothing else did
//
// Java was already handled — detect/javaser reads Runtime.getRuntime().exec and
// ProcessBuilder structurally — and Node.js got rule 4021. Every other language
// was open. Probing the process-spawning API of each in turn:
//
//	system('ver')                              PHP        missed
//	passthru('id') / shell_exec / popen        PHP        missed
//	os.system('id') / subprocess.check_output  Python     missed
//	system(paste('id'), intern = T)            R          missed
//	"id".execute()                             Groovy     missed
//	Runtime.getRuntime().exec("id")            Java       caught
//
// Four of those are live corpus exploits, and they were not an encoding problem
// or a scheduling problem — the payload is a plain call to a documented API and
// nothing was looking for it.
//
// # Why detect/phpi declines these, and why that is right for phpi
//
// It requires a danger call to be *attached to surrounding PHP*, on the
// reasoning that "an isolated call is a code snippet someone pasted into a text
// field". That is a good rule for a PHP detector reading PHP structure: a bare
// system('id') carries no PHP around it to read.
//
// It is the wrong frame here. This rule is not asking "is this PHP" — it is
// asking "does this value name a way to start a process", which is a question
// about the API, not about the language wrapped around it. That is why the same
// payload is a miss for phpi and a finding for this.
//
// # Two tiers, because the names differ in how ordinary they are
//
// "passthru(", "shell_exec(", "proc_open(", "os.system(" and the rest name one
// thing and nothing else. No sentence contains them; no API takes them as data.
// They carry the verdict alone.
//
// Note what is *not* in that tier: a module name. "subprocess." and
// "child_process" match a documentation link and a sentence about shelling out,
// and rule 4021 says so in its own documentation -- which did not stop this
// rule's first draft from listing both, and the benign cases written for 4021
// are what caught it. The subprocess API is listed by call instead, and
// child_process is left to 4021, which pairs it properly.
//
// "system(" and "exec(" do not. "exec" is a SQL keyword, a Makefile directive
// and a shell builtin; "system(" appears in documentation about this very
// attack. They need a quoted argument — the command being run — which is what
// separates "call system() to run a command" from "system('ver')".
//
// Measured against the 10,480-request benign corpus, none of these tokens
// appears even once, so the pairing is headroom rather than the thing holding
// the rate down. The corpus is one adopter's traffic (boundaries.md), which is
// why this is High rather than Certain.
func processSpawn() rules.Operator {
	// Self-evidencing: each names a process-spawning API and nothing else.
	strong := []string{
		"passthru(", "shell_exec(", "proc_open(", "pcntl_exec(",
		"popen(", "os.system(", "os.popen(", "os.execv",
		"commands.getoutput(", "getruntime().exec", "processbuilder(",
		".execute()", "shellexecute(", "createprocess(", "posix_spawn(",
		// The subprocess API by call, never by module name. "subprocess." on
		// its own matches a docs link and a sentence about shelling out --
		// which is exactly what rule 4021's own documentation says a module
		// name must never be, and this rule had it wrong in its first draft
		// until the benign cases written for 4021 caught it.
		"subprocess.run(", "subprocess.call(", "subprocess.popen(",
		"subprocess.check_output(", "subprocess.check_call(",
		"subprocess.getoutput(", "win32process.create",
	}

	return op.Func("process_spawn", func(v []byte) bool {
		for _, s := range strong {
			if indexOfFold(v, s) >= 0 {
				return true
			}
		}
		return false
	}).WithLiterals(
		// Honest: every branch requires one of these as a substring. The weak
		// tier's own names are included because the pairing narrows *within* a
		// match rather than replacing it.
		"passthru(", "shell_exec(", "proc_open(", "pcntl_exec(",
		"popen(", "os.system(", "os.popen(", "os.execv",
		"commands.getoutput(", "getruntime().exec", "processbuilder(",
		".execute()", "shellexecute(", "createprocess(", "posix_spawn(",
		"subprocess.run(", "subprocess.call(", "subprocess.popen(",
		"subprocess.check_output(", "subprocess.check_call(",
		"subprocess.getoutput(", "win32process.create",
	)
}

// nestedCallAt reports whether the argument is itself a call.
//
// R's spelling is system(paste('id'), intern = T) -- the command is built by a
// call rather than written as a literal, so there is no quote to find. A call
// as an argument is construction either way, and it is what separates
// "system(paste(" from "call system() to run a command", where the parenthesis
// closes immediately, and from "the system(config) initializes", where the
// argument is a bare identifier.
func nestedCallAt(v []byte) bool {
	i := 0
	for i < len(v) && isSpaceByte(v[i]) {
		i++
	}
	start := i
	for i < len(v) && (v[i] >= 'a' && v[i] <= 'z' || v[i] >= 'A' && v[i] <= 'Z' ||
		v[i] >= '0' && v[i] <= '9' || v[i] == '_' || v[i] == '.') {
		i++
	}
	if i == start {
		return false
	}
	for i < len(v) && isSpaceByte(v[i]) {
		i++
	}
	return i < len(v) && v[i] == '('
}

// quotedArgumentAt reports whether a quoted, non-empty argument opens here.
//
// Leading whitespace and one level of escaping are skipped, because a payload
// arriving inside JSON or a PHP string reaches this as system(\'ver\') rather
// than system('ver') — which is exactly how the corpus spells it.
func quotedArgumentAt(v []byte) bool {
	i := 0
	for i < len(v) && isSpaceByte(v[i]) {
		i++
	}
	if i < len(v) && v[i] == '\\' {
		i++
	}
	if i >= len(v) {
		return false
	}
	q := v[i]
	if q != '\'' && q != '"' && q != '`' {
		return false
	}
	// Non-empty: system('') runs nothing and is not a finding.
	j := i + 1
	if j < len(v) && v[j] == '\\' {
		j++
	}
	return j < len(v) && v[j] != q
}

// processSpawnSuspicious is the Medium half: the spellings that are also
// ordinary words.
//
// "system(", "exec(" and "spawn(" name the same capability as the tier above and
// do not carry the same weight. "exec" is a SQL keyword, a make directive and a
// shell builtin; "system(" is what every article about this attack contains.
// Pairing them with the quoted command or nested call that a real invocation
// carries removes the prose, and does not make them Certain.
//
// The tier is not a judgement call here, it is a decision this repository had
// already made and written a test for. TestMediumTierIsOptInAndReachable names
// "system('id')" as "an executing call with no surrounding PHP... a shape
// ordinary data takes, which is exactly why the default declines to block it".
// The first version of rule 4023 blocked it at High and that test caught it.
//
// So the split follows the line already drawn: an API that names one thing is
// High and ships enabled, and a word that also means something else is Medium
// and reachable through WithMinConfidence.
func processSpawnSuspicious() rules.Operator {
	weak := []string{"system(", "exec(", "spawn("}

	return op.Func("process_spawn_suspicious", func(v []byte) bool {
		for _, s := range weak {
			i := indexOfFold(v, s)
			if i < 0 {
				continue
			}
			// The argument has to be there. A call being *made* has a command in
			// it; a call being *discussed* does not.
			rest := v[i+len(s):]
			if quotedArgumentAt(rest) || nestedCallAt(rest) {
				return true
			}
		}
		return false
	}).WithLiterals("system(", "exec(", "spawn(")
}
