#!/usr/bin/env bash
# drive.sh — one backlog item, end to end: worktree -> worker -> gate -> PR -> merge.
#
# Usage:
#   scripts/orchestration/drive.sh <issue-number>     # run one item
#   scripts/orchestration/drive.sh next               # claim the lowest open issue and run it
#
# The worker CLI is $WORKER_CMD (default: agy -p --dangerously-skip-permissions),
# run inside the worktree with the rendered worker-prompt.md on stdin.
# The gate is re-run by the driver itself; a worker's word is not enough.
#
# Conventions baked in (from the loop recipe, 2026-10/11):
#   - worktrees under ~/.cache/ag-worktrees/, cut from origin/main
#   - CARGO_TARGET_DIR shared with the main checkout; incremental cleared between items
#   - CI on PRs is CodeRabbit only (SKIPPED): merge right after create, once CLEAN
#   - squash-merge, delete branch, ff the main checkout
#   - PR body ends with the Nebraska line
set -euo pipefail

REPO="${AG_REPO:-$HOME/source/repos/AdmiralGrace}"
WT_ROOT="$HOME/.cache/ag-worktrees"
TEMPLATE="$REPO/scripts/orchestration/worker-prompt.md"
WORKER_CMD="${WORKER_CMD:-agy -p --dangerously-skip-permissions}"
export CARGO_TARGET_DIR="$REPO/target"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

[ $# -eq 1 ] || { echo "usage: drive.sh <issue-number>|next" >&2; exit 2; }

cd "$REPO"
git fetch origin --prune

ISSUE="$1"
if [ "$ISSUE" = next ]; then
  # lowest open issue not already claimed by a lane
  ISSUE=$(gh issue list --repo CryptoJones/AdmiralGrace --state open --limit 200 --json number \
    --jq 'sort_by(.number)[].number' | while read -r n; do
      mkdir "$WT_ROOT/claims" 2>/dev/null || true
      mkdir "$WT_ROOT/claims/$n" 2>/dev/null && { echo "$n"; break; }
    done)
  [ -n "$ISSUE" ] || { echo "no unclaimed open issue"; exit 0; }
else
  mkdir -p "$WT_ROOT/claims"
  mkdir "$WT_ROOT/claims/$ISSUE" || { echo "issue #$ISSUE already claimed"; exit 1; }
fi

TITLE=$(gh issue view "$ISSUE" --repo CryptoJones/AdmiralGrace --json title --jq .title)
BODY=$(gh issue view "$ISSUE" --repo CryptoJones/AdmiralGrace --json body --jq .body)
WT="$WT_ROOT/ag-$ISSUE"
BRANCH="feat/issue-$ISSUE"

cleanup() { rm -rf "$WT_ROOT/claims/$ISSUE"; }
trap cleanup EXIT

log "#$ISSUE $TITLE"
git worktree add "$WT" -b "$BRANCH" origin/main

# render the prompt and run the worker
PROMPT=$(sed "s/{{ISSUE}}/$ISSUE/g; s/{{TITLE}}/$TITLE/g" "$TEMPLATE")
log "worker: $WORKER_CMD"
printf '%s\n\n## Issue body\n\n%s\n' "$PROMPT" "$BODY" | (cd "$WT" && eval "$WORKER_CMD") || true

# gate — the driver's word is the only word
cd "$WT"
log "gate: test"
if ! cargo test --workspace --offline; then
  log "GATE FAILED (test) — leaving worktree $WT for inspection"; exit 1
fi
log "gate: clippy"
if ! cargo clippy --workspace --offline --all-targets; then
  log "GATE FAILED (clippy) — leaving worktree $WT for inspection"; exit 1
fi

if ! git diff --quiet origin/main; then
  # worker left changes uncommitted (or none at all) — commit them ourselves
  git add -A
  git commit -m "fix: issue #$ISSUE ($TITLE)

Co-Authored-By: Claude Code <noreply@anthropic.com>" || true
fi
[ "$(git rev-list --count origin/main..HEAD)" -ge 1 ] || { log "no commits produced — abort"; exit 1; }

git push -u origin "$BRANCH"
PR=$(gh pr create --repo CryptoJones/AdmiralGrace --title "$(git log -1 --format=%s)" --body "Closes #$ISSUE

Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/" \
  | grep -oE '[0-9]+$')
log "PR #$PR"
sleep 10
gh pr merge "$PR" --repo CryptoJones/AdmiralGrace --squash --delete-branch
log "merged"

cd "$REPO"
git checkout main -q && git pull --ff-only
git worktree remove "$WT" --force || true
rm -rf "$CARGO_TARGET_DIR/debug/incremental"
log "done: #$ISSUE"
