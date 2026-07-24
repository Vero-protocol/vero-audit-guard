#!/usr/bin/env node
/**
 * Posts the review comments in scripts/pr-review-comments.md to their
 * respective PRs via `gh pr comment`. Requires an authenticated `gh` CLI
 * session (run `gh auth status` first) with comment access to the repo.
 *
 * Usage:
 *   node scripts/post-pr-review-comments.js            # post all
 *   node scripts/post-pr-review-comments.js --dry-run  # print without posting
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const { execFileSync } = require("child_process");

const REPO = "Vero-protocol/vero-audit-guard";
const COMMENTS_FILE = path.join(__dirname, "pr-review-comments.md");
const DRY_RUN = process.argv.includes("--dry-run");

function parseComments(text) {
  const sections = text.split(/^={10,}$/m);
  const comments = [];
  // sections[0] is the file's leading description; PR blocks come in
  // (title, body) pairs starting at index 1.
  for (let i = 1; i + 1 < sections.length; i += 2) {
    const titleLine = sections[i].trim();
    const match = titleLine.match(/PR #(\d+)\s*-\s*(.+)/);
    if (!match) {
      throw new Error(`Could not parse PR number from section: "${titleLine}"`);
    }
    const [, number, title] = match;
    const body = sections[i + 1].trim();
    if (!body) {
      throw new Error(`Empty comment body for PR #${number}`);
    }
    comments.push({ number, title, body });
  }
  return comments;
}

function postComment(number, body) {
  const tmpFile = path.join(os.tmpdir(), `pr-comment-${number}-${Date.now()}.md`);
  fs.writeFileSync(tmpFile, body, "utf-8");
  try {
    execFileSync(
      "gh",
      ["pr", "comment", number, "--repo", REPO, "--body-file", tmpFile],
      { stdio: "inherit" }
    );
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

function main() {
  const text = fs.readFileSync(COMMENTS_FILE, "utf-8");
  const comments = parseComments(text);

  console.log(`Parsed ${comments.length} comment(s) from ${COMMENTS_FILE}\n`);

  for (const { number, title, body } of comments) {
    console.log(`--- PR #${number} - ${title} ---`);
    if (DRY_RUN) {
      console.log(body);
      console.log();
      continue;
    }
    try {
      postComment(number, body);
      console.log(`Posted comment on PR #${number}\n`);
    } catch (err) {
      console.error(`Failed to post comment on PR #${number}: ${err.message}\n`);
    }
  }
}

main();
