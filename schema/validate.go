// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package schema

import "strings"

// Violation describes why a value failed validation.
type Violation uint8

// Violations.
const (
	ViolationNone Violation = iota
	ViolationType
	ViolationEnum
	ViolationFormat
	ViolationLength
	ViolationUndeclared
	ViolationMissing
)

// String implements fmt.Stringer.
func (v Violation) String() string {
	switch v {
	case ViolationType:
		return "type_mismatch"
	case ViolationEnum:
		return "not_in_enum"
	case ViolationFormat:
		return "format_mismatch"
	case ViolationLength:
		return "too_long"
	case ViolationUndeclared:
		return "undeclared_parameter"
	case ViolationMissing:
		return "missing_required_parameter"
	default:
		return "none"
	}
}

// Validate checks value against a field declaration.
//
// Validation is byte-oriented and allocation-free: it runs on every value of
// every request against a schema, so it must not be more expensive than the
// rule evaluation it is meant to replace.
//
// A field declaring KindUnknown validates everything. An unspecified field must
// never be treated as constrained, because Inert would then claim a value is
// provably safe on the strength of an assertion nobody made.
func Validate(f Field, value []byte) Violation {
	if f.MaxLength > 0 && len(value) > f.MaxLength {
		return ViolationLength
	}

	switch f.Kind {
	case KindInteger:
		if !isInteger(value) {
			return ViolationType
		}
	case KindNumber:
		if !isNumber(value) {
			return ViolationType
		}
	case KindBoolean:
		if !isBoolean(value) {
			return ViolationType
		}
	case KindEnum:
		if !inEnum(f.Enum, value) {
			return ViolationEnum
		}
	case KindString:
		if !matchesFormat(f.Format, value) {
			return ViolationFormat
		}
	}
	return ViolationNone
}

// isInteger reports whether value is a decimal integer with an optional sign.
//
// Nothing beyond digits and a leading sign is admitted — not whitespace, not a
// leading plus followed by nothing, not an empty string. The Inert claim rests
// on this being exact: if a value passes here it contains only bytes from
// "0123456789+-", which cannot spell any injection payload.
func isInteger(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	i := 0
	if value[0] == '+' || value[0] == '-' {
		i = 1
	}
	if i == len(value) {
		return false
	}
	for ; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// isNumber reports whether value is a JSON number: optional sign, digits, an
// optional fraction, and an optional exponent.
func isNumber(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	i := 0
	if value[i] == '+' || value[i] == '-' {
		i++
	}

	digits := 0
	for i < len(value) && value[i] >= '0' && value[i] <= '9' {
		i++
		digits++
	}
	if i < len(value) && value[i] == '.' {
		i++
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			i++
			digits++
		}
	}
	if digits == 0 {
		return false
	}

	if i < len(value) && (value[i] == 'e' || value[i] == 'E') {
		i++
		if i < len(value) && (value[i] == '+' || value[i] == '-') {
			i++
		}
		expDigits := 0
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			i++
			expDigits++
		}
		if expDigits == 0 {
			return false
		}
	}
	return i == len(value)
}

// isBoolean accepts the spellings that appear on the wire.
func isBoolean(value []byte) bool {
	switch string(value) {
	case "true", "false", "TRUE", "FALSE", "True", "False", "1", "0":
		return true
	default:
		return false
	}
}

func inEnum(allowed []string, value []byte) bool {
	for _, a := range allowed {
		if a == string(value) {
			return true
		}
	}
	return false
}

// matchesFormat checks a string field's declared shape.
func matchesFormat(f Format, value []byte) bool {
	switch f {
	case FormatUUID:
		return isUUID(value)
	case FormatDateTime:
		return isDateTime(value)
	case FormatDate:
		return isDate(value)
	case FormatEmail:
		return isEmail(value)
	case FormatHexadecimal:
		return isHex(value)
	case FormatBase64:
		return isBase64(value)
	case FormatIPv4:
		return isIPv4(value)
	default:
		return true
	}
}

// isUUID checks the canonical 8-4-4-4-12 hyphenated form.
func isUUID(v []byte) bool {
	if len(v) != 36 {
		return false
	}
	for i, c := range v {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHexDigit(c) {
				return false
			}
		}
	}
	return true
}

// isDateTime checks RFC 3339, which is what OpenAPI's date-time means.
//
// The 'T' separator is required. RFC 3339 §5.6 permits applications to accept a
// space instead, and this deliberately does not: a date-time field is declared
// inert, meaning rules are skipped for values that pass here, and that claim is
// only worth making if the admitted character set contains nothing an attack
// needs. A space is such a byte. Being stricter than the specification costs a
// client an unusual spelling; being looser costs the inert claim its meaning.
//
// The fuzz harness in schema_test.go enforces exactly this: it fails the build
// if any inert field validates a value containing a byte from the attack
// vocabulary. It found the space, which is why this comment exists.
func isDateTime(v []byte) bool {
	// Minimum: 1970-01-01T00:00:00Z
	if len(v) < 20 {
		return false
	}
	if !isDate(v[:10]) || (v[10] != 'T' && v[10] != 't') {
		return false
	}
	rest := v[11:]
	if len(rest) < 8 || !isDigits(rest[0:2]) || rest[2] != ':' ||
		!isDigits(rest[3:5]) || rest[5] != ':' || !isDigits(rest[6:8]) {
		return false
	}
	rest = rest[8:]

	// Optional fractional seconds.
	if len(rest) > 0 && rest[0] == '.' {
		rest = rest[1:]
		n := 0
		for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
			n++
		}
		if n == 0 {
			return false
		}
		rest = rest[n:]
	}

	// Zone: Z, or +hh:mm / -hh:mm.
	switch {
	case len(rest) == 1 && (rest[0] == 'Z' || rest[0] == 'z'):
		return true
	case len(rest) == 6 && (rest[0] == '+' || rest[0] == '-'):
		return isDigits(rest[1:3]) && rest[3] == ':' && isDigits(rest[4:6])
	default:
		return false
	}
}

// isDate checks YYYY-MM-DD.
func isDate(v []byte) bool {
	return len(v) == 10 &&
		isDigits(v[0:4]) && v[4] == '-' &&
		isDigits(v[5:7]) && v[7] == '-' &&
		isDigits(v[8:10])
}

// isEmail is a shape check, not RFC 5322 conformance.
//
// It rejects the characters an injection payload needs — whitespace, quotes,
// angle brackets, semicolons — rather than trying to accept every address the
// specification permits. A firewall's job here is to bound the character set,
// not to be an address parser.
func isEmail(v []byte) bool {
	if len(v) < 3 || len(v) > 254 {
		return false
	}
	at := -1
	for i, c := range v {
		switch {
		case c == '@':
			if at >= 0 {
				return false
			}
			at = i
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_' || c == '+':
		default:
			return false
		}
	}
	if at <= 0 || at == len(v)-1 {
		return false
	}
	domain := v[at+1:]
	return len(domain) >= 3 && indexByteIn(domain, '.') > 0
}

func isHex(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	for _, c := range v {
		if !isHexDigit(c) {
			return false
		}
	}
	return true
}

// isBase64 accepts the standard alphabet with optional padding.
//
// Note that a base64 field is not Inert: the alphabet includes '+' and '/', and
// the decoded content is unknown to the schema.
func isBase64(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	pad := 0
	for i, c := range v {
		switch {
		case c == '=':
			pad++
			if pad > 2 || i < len(v)-2 {
				return false
			}
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			if pad > 0 {
				return false
			}
		case c == '+' || c == '/' || c == '-' || c == '_':
			if pad > 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func isIPv4(v []byte) bool {
	parts := 0
	i := 0
	for parts < 4 {
		start := i
		n := 0
		for i < len(v) && v[i] >= '0' && v[i] <= '9' {
			n = n*10 + int(v[i]-'0')
			i++
			if i-start > 3 {
				return false
			}
		}
		if i == start || n > 255 {
			return false
		}
		parts++
		if parts < 4 {
			if i >= len(v) || v[i] != '.' {
				return false
			}
			i++
		}
	}
	return i == len(v)
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isDigits(v []byte) bool {
	for _, c := range v {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(v) > 0
}

func indexByteIn(v []byte, c byte) int {
	for i := range v {
		if v[i] == c {
			return i
		}
	}
	return -1
}

// ParseFormat maps a textual OpenAPI format name to a Format, so frontends do
// not each invent their own mapping.
func ParseFormat(s string) (Format, bool) {
	switch strings.ToLower(s) {
	case "", "none":
		return FormatNone, true
	case "uuid", "guid":
		return FormatUUID, true
	case "date-time", "datetime":
		return FormatDateTime, true
	case "date":
		return FormatDate, true
	case "email", "idn-email":
		return FormatEmail, true
	case "hex", "hexadecimal":
		return FormatHexadecimal, true
	case "base64", "byte":
		return FormatBase64, true
	case "ipv4":
		return FormatIPv4, true
	default:
		return FormatNone, false
	}
}
