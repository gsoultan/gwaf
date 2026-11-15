#!/usr/bin/env bash
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT
#
# Fails when any commit in a range is authored or committed by an AI tool's
# identity, or carries an AI co-author trailer.
#
# The commit-msg hook in .githooks strips attribution trailers, but it never
# looked at who a commit is authored by. Cloud agent sessions author commits as
# "Claude <noreply@anthropic.com>" unless told otherwise, GitHub links that
# address to an account and lists it as a contributor, and eight such commits
# reached main that way, inside the v0.6.6 to v0.6.8 tags. A hook runs only on
# the machine that has it configured; this runs on every pull request and push.
#
# Usage: .github/check-commit-identity.sh <base> <head>

set -euo pipefail

base=${1:?usage: $0 <base> <head>}
head=${2:?usage: $0 <base> <head>}
# [.] rather than a backslash escape: awk -v processes escapes and warns on this one.
pattern='@anthropic[.]com|^Claude$'

bad=$(git log --format='%h%x09%an%x09%ae%x09%cn%x09%ce' "$base..$head" |
	awk -F '\t' -v re="$pattern" '$2 ~ re || $3 ~ re || $4 ~ re || $5 ~ re')
trailers=$(git log --format='%h%x09%(trailers:key=Co-authored-by,valueonly,separator=%x2C )' "$base..$head" |
	grep -iE $'\t.*(claude|anthropic)' || true)

if [ -n "$bad$trailers" ]; then
	echo "Commits credited to an AI identity (author, committer or Co-authored-by):"
	[ -n "$bad" ] && printf '%s\n' "$bad"
	[ -n "$trailers" ] && printf '%s\n' "$trailers"
	echo
	echo "Set git config user.name/user.email to a person and rewrite these commits."
	exit 1
fi
echo "commit identity: $(git rev-list --count "$base..$head") commits checked, none credited to an AI identity"
