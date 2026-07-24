# PR review comments — ready to post

Five PRs reviewed, each blocked by a distinct, concrete issue. Comment bodies
below are used verbatim by `post-pr-review-comments.sh`. Edit here if you want
to change wording before running the script — the script re-reads this file.

=====================================================================
PR #189 - Add zero-address protection layer
=====================================================================
Thanks for this — the zero-address check logic itself looks good. There's one
build-breaking issue in this PR that needs a fix before it can merge, separate
from the branch being a bit behind `main`.

**The problem:** `scanner-engine/Cargo.toml` currently has the `crossbeam-epoch`
dependency declared twice (this predates your branch, so it's not something you
introduced originally) — but this PR's diff adds a **third** copy of the same
block on top of the existing two. TOML doesn't allow duplicate keys in the same
table, so `cargo` fails to parse the manifest before any code even compiles.

**What's needed:**
1. Pull the latest `main` (it already has the original duplicate removed — you
   should now see a single `crossbeam-epoch = ">=0.9.20"` line)
2. Check your diff for `scanner-engine/Cargo.toml` and remove the duplicate
   block your branch adds — there should be exactly one `crossbeam-epoch` entry
   in `[dependencies]`
3. Push the update — `cargo check` in `scanner-engine/` should then parse clean

This will also need a manual conflict resolution on `src/audit-guard/src/lib.rs`
once #185, #193, and #195 land first (a few other PRs touch that same file) —
happy to help walk through that when you get there.

=====================================================================
PR #184 - chore: add Rust build artifacts to version control
=====================================================================
Heads up — this branch is currently 179 commits behind `main`, which is far
enough back that a simple "Update branch" click likely won't resolve cleanly.

**What's needed:** rather than merging `main` into this branch as-is, it'll be
smoother to rebase from scratch:
```bash
git fetch origin main
git rebase origin/main
# resolve any conflicts as they come up, likely touching src/audit-guard/Cargo.lock,
# Cargo.toml, and src/lib.rs
git push --force-with-lease
```
Given how stale this is, it might also be worth double-checking whether the
build-artifacts changes here are still needed, or if `main`'s `.gitignore`
already handles this — happy to take a look once it's rebased.

=====================================================================
PR #187 - chore: ignore Rust target build artifacts
=====================================================================
Same situation as #184 — this branch is 179 commits behind `main`, so a
straightforward branch update likely won't apply cleanly.

**What's needed:**
```bash
git fetch origin main
git rebase origin/main
# resolve conflicts, likely in src/audit-guard/Cargo.lock, Cargo.toml, and src/lib.rs
git push --force-with-lease
```
Once rebased, this will also need to merge in after #185, #193, and #195 (a few
other open PRs touch the same `src/lib.rs` file), so expect one more round of
conflict resolution at that point.

=====================================================================
PR #190 - Build upgradeable proxy pattern entry point / policy hot-reload
=====================================================================
This one has a conflict against the current `main` on `src/audit-guard/Cargo.toml`
— nothing wrong with the approach here, it just needs a rebase to line up with
what's already on `main`.

**What's needed:**
```bash
git fetch origin main
git rebase origin/main
# resolve the Cargo.toml conflict
git push --force-with-lease
```
After that it should be clear to review — no other issues found in this one.

=====================================================================
PR #196 - feat(security): issue-160 optimize batch contract call performance
=====================================================================
Found something worth flagging before this goes further: `scanner-engine/Cargo.toml`
in this PR's diff isn't a Rust manifest anymore — it looks like it's been replaced
with what appears to be browser tab/session data (page titles, URLs, and tab IDs
from unrelated browser tabs) rather than the actual dependency list. This looks
like an accidental paste from a local tool or extension rather than an
intentional change.

**What's needed:**
1. Check your local working copy of `scanner-engine/Cargo.toml` — it should
   contain the Rust package manifest, not this tab-state content
2. Recover the correct file (e.g. `git checkout main -- scanner-engine/Cargo.toml`
   if you haven't intentionally changed anything in it) and re-commit
3. Worth double-checking your other changed files too in case the same tool
   affected anything else, and whether that leaked data includes anything you
   didn't mean to share publicly — you may want to check your browser
   extension/tooling setup

Once that's sorted, happy to take another look — didn't find other issues in
the rest of the diff.
