// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package types

import "strconv"

// RuleID is a rule's stable public identifier.
//
// IDs are numeric because the entire WAF tooling ecosystem — CRS documentation,
// tuning guides, audit logs, published bypass writeups — assumes they are. In
// particular the CRS range is preserved verbatim through the SecLang adapter so
// that existing CRS knowledge transfers unchanged after migration.
type RuleID uint32

// Reserved ID ranges. The compiler rejects user rules outside UserMin..UserMax.
const (
	// CoreMin..CoreMax is the gwaf core ruleset.
	CoreMin RuleID = 1
	CoreMax RuleID = 99_999

	// BundleMin..BundleMax is first-party optional bundles.
	BundleMin RuleID = 100_000
	BundleMax RuleID = 899_999

	// CRSMin..CRSMax holds OWASP CRS rules, preserved verbatim.
	CRSMin RuleID = 900_000
	CRSMax RuleID = 999_999

	// UserMin..UserMax is the namespace available to embedders.
	UserMin RuleID = 1_000_000
	UserMax RuleID = ^RuleID(0)
)

// Namespace identifies which ID range a RuleID falls in.
type Namespace uint8

// Namespace values.
const (
	NamespaceInvalid Namespace = iota
	NamespaceCore
	NamespaceBundle
	NamespaceCRS
	NamespaceUser
)

// String implements fmt.Stringer.
func (n Namespace) String() string {
	switch n {
	case NamespaceCore:
		return "core"
	case NamespaceBundle:
		return "bundle"
	case NamespaceCRS:
		return "crs"
	case NamespaceUser:
		return "user"
	default:
		return "invalid"
	}
}

// Namespace returns the range id belongs to. ID 0 is not a valid rule ID and
// reports NamespaceInvalid.
func (id RuleID) Namespace() Namespace {
	switch {
	case id == 0:
		return NamespaceInvalid
	case id <= CoreMax:
		return NamespaceCore
	case id <= BundleMax:
		return NamespaceBundle
	case id <= CRSMax:
		return NamespaceCRS
	default:
		return NamespaceUser
	}
}

// IsUser reports whether id is in the embedder-owned range.
func (id RuleID) IsUser() bool { return id.Namespace() == NamespaceUser }

// String implements fmt.Stringer.
func (id RuleID) String() string { return strconv.FormatUint(uint64(id), 10) }
