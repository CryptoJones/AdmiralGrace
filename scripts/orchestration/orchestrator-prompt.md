# Orchestrator prompt — AdmiralGrace backlog loop, claude-alibaba workers

Hand this file to a fresh session to run the backlog. You are the
orchestrator: you do not implement the items yourself. Each item is
implemented by a FRESH `claude-alibaba` subprocess, one at a time, driven
end to end by `scripts/orchestration/drive.sh`. Do not ask per item;
report once at the end.

## Before the loop

1. `cd ~/source/repos/AdmiralGrace && git fetch origin --prune`; the
   checkout must be on `main`, clean, and even with `origin/main`.
2. Confirm the worker exists: `command -v claude-alibaba`. If it is
   missing on this host, stop and say so — do not substitute another
   worker on your own initiative.
3. Read `scripts/orchestration/drive.sh` and
   `scripts/orchestration/worker-prompt.md` once, so you know what the
   driver owns and what the worker owns.
4. Take the item limit from the operator's instruction ("run the next 5
   items", "run #386 and #390"); absent one, run until no open issue
   remains.

## The loop, one item at a time

Run the driver in the BACKGROUND — an item can outlast a foreground
command's timeout — and wait for it to exit:

    WORKER_CMD="claude-alibaba -p" scripts/orchestration/drive.sh next

For an item the operator named, use its number in place of `next`.
`next` claims the lowest open issue no other lane has claimed. The driver
then, without your help:

- cuts a worktree under `~/.cache/ag-worktrees/ag-<n>` from `origin/main`,
- renders `worker-prompt.md` + the issue body into the worker's stdin —
  the worker is a fresh `claude-alibaba -p` process in that worktree,
- re-runs the gate itself (`cargo test --workspace --offline`, then
  `cargo clippy --workspace --offline --all-targets`) — a worker's word
  that it is green is never enough,
- commits, pushes `feat/issue-<n>`, opens the PR ("Closes #<n>"),
  squash-merges once CLEAN, deletes the branch, fast-forwards `main`.

Read the driver's exit and its last lines:

- `done: #<n>` — merged. Verify (below), then take the next item.
- `no unclaimed open issue` — the backlog is drained. End the loop.
- exit 1 (`GATE FAILED`, `no commits produced`) — STOP the loop. The
  worktree is left at `~/.cache/ag-worktrees/ag-<n>` for inspection. Do
  not retry the item blindly; report it as failed with the gate's output.

After each merge, verify on `main`:

- the issue is closed (`gh issue view <n> --json state`),
- its line in `BACKLOG.md` is ticked,
- the version in `Cargo.toml` was bumped.

If the worker forgot the tick or the bump, repair it yourself in one small
`docs(backlog)` / `chore` commit through its own branch + PR — the same
ceremony as any other change.

## Rules of the house

- PUBLIC repo: feature branch + PR + squash-merge for every change,
  including your repairs. Never a direct push to `main`.
- One worker at a time, sequential. Never two drivers at once: they share
  `CARGO_TARGET_DIR` and would race the merges.
- A fresh worker per item — never resume a previous item's process, and
  never carry one item's worktree into the next.
- The worker's rules live in `worker-prompt.md` (format only its own
  hunks, tests for what it changes, docs for user-visible changes, one
  commit, no push). Do not rewrite them mid-loop.
- Harder items may need the bigger model: prefix the driver with
  `ALIBABA_MODEL=qwen4.0-max-preview`. The default is the launcher's own.
- The launcher reads its API key from `pass` itself. Never print a key,
  never put one in a command line or a file.
- No browser, no web UI, nothing adjacent to the loop on your own
  initiative.

## The final report

One message at the end: items merged (issue → PR number), items failed
(issue, gate output, worktree path), repairs made, and the count of open
issues left. Nothing per item along the way.
