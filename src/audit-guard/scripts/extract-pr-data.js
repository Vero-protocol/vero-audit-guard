#!/usr/bin/env node
/**
 * GitHub Actions Helper
 * Extracts PR data from GitHub Actions context and prepares it for policy evaluation
 */

const fs = require("fs");

async function extractPRData() {
  const context = {
    prTitle: process.env.GITHUB_PR_TITLE || "",
    prBody: process.env.GITHUB_PR_BODY || "",
    prLabels: (process.env.GITHUB_PR_LABELS || "").split(",").filter(Boolean),
    baseBranch: process.env.GITHUB_BASE_BRANCH || "main",
    headBranch: process.env.GITHUB_HEAD_BRANCH || "",
    prNumber: parseInt(process.env.GITHUB_PR_NUMBER || "0"),
    prAuthor: process.env.GITHUB_PR_AUTHOR || "",
    additions: parseInt(process.env.GITHUB_ADDITIONS || "0"),
    deletions: parseInt(process.env.GITHUB_DELETIONS || "0"),
    changedFilesJson: process.env.GITHUB_CHANGED_FILES || "[]",
  };

  let changedFiles = [];
  try {
    changedFiles = JSON.parse(context.changedFilesJson);
  } catch (e) {
    console.warn("Warning: Could not parse changed files JSON");
  }

  const prData = {
    pull_request: {
      title: context.prTitle,
      body: context.prBody,
      labels: context.prLabels,
      base_branch: context.baseBranch,
      head_branch: context.headBranch,
      number: context.prNumber,
      author: context.prAuthor,
    },
    files_modified: changedFiles,
    additions: context.additions,
    deletions: context.deletions,
  };

  return prData;
}

async function main() {
  try {
    const prData = await extractPRData();
    const outputPath = process.argv[2] || "./pr-data.json";

    fs.writeFileSync(outputPath, JSON.stringify(prData, null, 2));
    console.log(`✅ PR data extracted to ${outputPath}`);
    console.log(JSON.stringify(prData, null, 2));
  } catch (error) {
    console.error("❌ Error extracting PR data:", error);
    process.exit(1);
  }
}

main();
