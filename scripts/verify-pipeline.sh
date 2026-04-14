#!/usr/bin/env bash
# Verify that the /mika pipeline produced required artifacts before PR creation.
#
# Checks (in order):
#   1. Backward-compat: a plan doc exists somewhere in docs/plans/*.md
#   2. Backward-compat: source changes exist beyond the plan doc
#   3. Bucket-comparison: reject docs-only or code-only PRs
#
# Buckets (applied to the union of committed/staged/unstaged diffs vs base):
#   docs    = docs/plans/** or docs/solutions/**
#   source  = everything NOT under docs/, .github/, or .claude/worktrees/
#   other   = the rest (.github/, docs/adr/, docs/brainstorms/, README.md, ...)
#
# Decisions:
#   docs && source           -> pass
#   docs && !source          -> REJECT (docs-only PR)
#   !docs && source          -> REJECT (code-only PR)
#   !docs && !source         -> warn + pass (pure config or no diff)
#
# Exempt trailers (any commit in the base..HEAD range):
#   Pipeline-Exempt: docs-only  -> bypass docs-only rejection
#   Pipeline-Exempt: code-only  -> bypass code-only rejection
#
# Usage:
#   ./scripts/verify-pipeline.sh              # local (compares to main)
#   ./scripts/verify-pipeline.sh origin/main  # CI (compares to origin/main or base SHA)
#
# Exit codes:
#   0 - all checks passed (possibly with warnings)
#   1 - missing artifacts or pathological split

set -euo pipefail
cd "$(dirname "$0")/.."

BASE_REF="${1:-main}"
MERGE_BASE=$(git merge-base "$BASE_REF" HEAD 2>/dev/null || echo "$BASE_REF")

# Collect all changed files: committed + staged + unstaged
COMMITTED=$(git diff "$MERGE_BASE" HEAD --name-only 2>/dev/null || true)
STAGED=$(git diff --cached --name-only 2>/dev/null || true)
UNSTAGED=$(git diff --name-only 2>/dev/null || true)
ALL=$(printf '%s\n%s\n%s' "$COMMITTED" "$STAGED" "$UNSTAGED" | sort -u | grep -v '^$' || true)

ERRORS=0

# -----------------------------------------------------------------------------
# Bucket-comparison (docs-only / code-only rejection)
#
# Note: the former "backward-compat" block (unconditional plan-doc and source
# presence checks) was removed. Those checks are strictly subsumed by the
# bucket logic below — docs/plans presence is covered by DOCS_BUCKET, source
# presence by SOURCE_BUCKET, and the exempt trailers provide the escape hatch.
# Running them in addition double-counted errors and shadowed the "warn+allow"
# branches (other-only, no-diff, exempt-trailer) so they never reached exit 0.
# Capture PLAN here purely for the final "passed" message.
# -----------------------------------------------------------------------------

PLAN=$(echo "$ALL" | grep '^docs/plans/.*\.md$' || true)

DOCS_BUCKET=$(echo "$ALL" | grep -E '^docs/(plans|solutions)/' || true)
SOURCE_BUCKET=$(echo "$ALL" \
  | grep -v -E '^docs/' \
  | grep -v -E '^\.github/' \
  | grep -v -E '^\.claude/worktrees/' \
  || true)

# OTHER = ALL minus DOCS_BUCKET minus SOURCE_BUCKET
if [[ -n "$ALL" ]]; then
  EXCLUDE=$(printf '%s\n%s\n' "$DOCS_BUCKET" "$SOURCE_BUCKET" | grep -v '^$' || true)
  if [[ -n "$EXCLUDE" ]]; then
    OTHER_BUCKET=$(echo "$ALL" | grep -v -F -x -f <(echo "$EXCLUDE") || true)
  else
    OTHER_BUCKET="$ALL"
  fi
else
  OTHER_BUCKET=""
fi

# Exempt trailers: scan commit messages in base..HEAD
COMMIT_BODIES=$(git log --format=%B "${MERGE_BASE}..HEAD" 2>/dev/null || true)
EXEMPT_DOCS_ONLY=0
EXEMPT_CODE_ONLY=0
if echo "$COMMIT_BODIES" | grep -qx 'Pipeline-Exempt: docs-only'; then
  EXEMPT_DOCS_ONLY=1
fi
if echo "$COMMIT_BODIES" | grep -qx 'Pipeline-Exempt: code-only'; then
  EXEMPT_CODE_ONLY=1
fi

if [[ -n "$DOCS_BUCKET" && -z "$SOURCE_BUCKET" ]]; then
  if [[ "$EXEMPT_DOCS_ONLY" == "1" ]]; then
    echo "warn: docs-only PR allowed by Pipeline-Exempt: docs-only trailer" >&2
  else
    echo "REJECT: docs-only PR: plan/solution present but no source changes" >&2
    ERRORS=$((ERRORS + 1))
  fi
fi

if [[ -z "$DOCS_BUCKET" && -n "$SOURCE_BUCKET" ]]; then
  if [[ "$EXEMPT_CODE_ONLY" == "1" ]]; then
    echo "warn: code-only PR allowed by Pipeline-Exempt: code-only trailer" >&2
  else
    echo "REJECT: code-only PR: source changes present but no plan/solution doc" >&2
    ERRORS=$((ERRORS + 1))
  fi
fi

if [[ -z "$DOCS_BUCKET" && -z "$SOURCE_BUCKET" ]]; then
  if [[ -n "$OTHER_BUCKET" ]]; then
    echo "warn: no docs or source changes, only config/other files" >&2
  else
    echo "warn: no diff against $BASE_REF" >&2
  fi
fi

# -----------------------------------------------------------------------------

if [[ $ERRORS -gt 0 ]]; then
  echo "Verification FAILED: $ERRORS missing artifact(s)." >&2
  exit 1
fi

echo "Pipeline verification passed. Plan: ${PLAN:-<none>}"
