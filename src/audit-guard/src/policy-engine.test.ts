/**
 * Tests for Policy Engine
 */

import PolicyEngine, { PRData } from "../src/policy-engine";

describe("PolicyEngine", () => {
  let engine: PolicyEngine;

  beforeEach(() => {
    engine = new PolicyEngine();
  });

  describe("PR Title Validation", () => {
    it("should flag empty PR title", async () => {
      const prData: PRData = {
        pull_request: {
          title: "",
          body: "Test PR",
          labels: [],
          base_branch: "develop",
          head_branch: "feature/test",
          number: 1,
          author: "test-user",
        },
        files_modified: ["src/test.ts"],
        additions: 10,
        deletions: 5,
      };

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("NON_COMPLIANT");
      expect(result.violations.some((v) => v.rule === "PR_TITLE_EMPTY")).toBe(
        true
      );
    });

    it("should flag short PR title", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Fix bug",
          body: "Test PR",
          labels: [],
          base_branch: "develop",
          head_branch: "feature/test",
          number: 1,
          author: "test-user",
        },
        files_modified: ["src/test.ts"],
        additions: 10,
        deletions: 5,
      };

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("NON_COMPLIANT");
      expect(result.violations.some((v) => v.rule === "PR_TITLE_TOO_SHORT")).toBe(
        true
      );
    });

    it("should accept valid PR title", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Implement new security feature for audit trail",
          body: "This PR implements the new security feature",
          labels: [],
          base_branch: "develop",
          head_branch: "feature/security",
          number: 1,
          author: "test-user",
        },
        files_modified: ["src/test.ts"],
        additions: 50,
        deletions: 10,
      };

      const result = await engine.evaluate(prData);
      expect(result.violations.some((v) => v.rule === "PR_TITLE_EMPTY")).toBe(
        false
      );
      expect(result.violations.some((v) => v.rule === "PR_TITLE_TOO_SHORT")).toBe(
        false
      );
    });
  });

  describe("PR Description Validation", () => {
    it("should flag missing PR description", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Implement new security feature",
          body: "",
          labels: [],
          base_branch: "develop",
          head_branch: "feature/test",
          number: 1,
          author: "test-user",
        },
        files_modified: ["src/test.ts"],
        additions: 10,
        deletions: 5,
      };

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("NON_COMPLIANT");
      expect(
        result.violations.some((v) => v.rule === "PR_DESCRIPTION_MISSING")
      ).toBe(true);
    });

    it("should warn about undocumented testing", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Implement new security feature",
          body: "This PR implements a new feature without any verification performed.",
          labels: [],
          base_branch: "develop",
          head_branch: "feature/test",
          number: 1,
          author: "test-user",
        },
        files_modified: ["src/test.ts"],
        additions: 10,
        deletions: 5,
      };

      const result = await engine.evaluate(prData);
      expect(
        result.warnings.some((w) => w.rule === "PR_TESTING_UNDOCUMENTED")
      ).toBe(true);
    });

    it("should not warn when testing is documented", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Implement new security feature",
          body: "This PR implements a new feature. Tested with jest: npm test passed all tests.",
          labels: [],
          base_branch: "develop",
          head_branch: "feature/test",
          number: 1,
          author: "test-user",
        },
        files_modified: ["src/test.ts"],
        additions: 10,
        deletions: 5,
      };

      const result = await engine.evaluate(prData);
      expect(
        result.warnings.some((w) => w.rule === "PR_TESTING_UNDOCUMENTED")
      ).toBe(false);
    });
  });

  describe("Breaking Changes", () => {
    it("should flag breaking changes without label", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Redesign API interface",
          body: "This is a breaking change that restructures the public API",
          labels: [],
          base_branch: "develop",
          head_branch: "feature/redesign",
          number: 1,
          author: "test-user",
        },
        files_modified: ["src/api.ts"],
        additions: 100,
        deletions: 50,
      };

      const result = await engine.evaluate(prData);
      expect(
        result.violations.some((v) => v.rule === "BREAKING_CHANGE_NOT_LABELED")
      ).toBe(true);
    });

    it("should accept breaking changes with label", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Redesign API interface",
          body: "This is a breaking change that restructures the public API",
          labels: ["breaking-change"],
          base_branch: "develop",
          head_branch: "feature/redesign",
          number: 1,
          author: "test-user",
        },
        files_modified: ["src/api.ts"],
        additions: 100,
        deletions: 50,
      };

      const result = await engine.evaluate(prData);
      expect(
        result.violations.some((v) => v.rule === "BREAKING_CHANGE_NOT_LABELED")
      ).toBe(false);
    });
  });

  describe("Security-Sensitive Changes", () => {
    it("should flag security changes without label", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Update cryptographic signature validation",
          body: "This PR updates the crypto signature handling logic",
          labels: [],
          base_branch: "develop",
          head_branch: "feature/crypto",
          number: 1,
          author: "test-user",
        },
        files_modified: ["src/crypto.ts"],
        additions: 50,
        deletions: 30,
      };

      const result = await engine.evaluate(prData);
      // This produces a warning, not a violation
      const hasSecurityWarning = result.warnings.some(
        (w) => w.rule === "SECURITY_CHANGE_NEEDS_LABEL"
      );
      expect(hasSecurityWarning).toBe(true);
    });

    it("should accept security changes with security label", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Update cryptographic signature validation",
          body: "This PR updates the crypto signature handling logic",
          labels: ["security"],
          base_branch: "develop",
          head_branch: "feature/crypto",
          number: 1,
          author: "test-user",
        },
        files_modified: ["src/crypto.ts"],
        additions: 50,
        deletions: 30,
      };

      const result = await engine.evaluate(prData);
      const hasSecurityWarning = result.warnings.some(
        (w) => w.rule === "SECURITY_CHANGE_NEEDS_LABEL"
      );
      expect(hasSecurityWarning).toBe(false);
    });
  });

  describe("Large Changes", () => {
    it("should warn about many files modified", async () => {
      const files = Array.from({ length: 25 }, (_, i) => `src/file${i}.ts`);
      const prData: PRData = {
        pull_request: {
          title: "Implement new security feature with comprehensive refactoring",
          body: "This PR implements a new feature and refactors multiple modules for testing",
          labels: [],
          base_branch: "develop",
          head_branch: "feature/refactor",
          number: 1,
          author: "test-user",
        },
        files_modified: files,
        additions: 500,
        deletions: 300,
      };

      const result = await engine.evaluate(prData);
      expect(
        result.warnings.some((w) => w.rule === "TOO_MANY_FILES_MODIFIED")
      ).toBe(true);
    });

    it("should warn about large diffs", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Implement major rewrite of core module",
          body: "This PR rewrites the core module and has been tested comprehensively",
          labels: [],
          base_branch: "develop",
          head_branch: "feature/rewrite",
          number: 1,
          author: "test-user",
        },
        files_modified: ["src/core.ts"],
        additions: 800,
        deletions: 600,
      };

      const result = await engine.evaluate(prData);
      expect(
        result.warnings.some((w) => w.rule === "LARGE_DIFF_REQUIRES_JUSTIFICATION")
      ).toBe(true);
    });
  });

  describe("Compliant PR", () => {
    it("should pass compliant PR", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Implement new audit logging feature",
          body: `
## Description
This PR implements a new audit logging feature for the security system.

## Changes
- Added new logging module
- Updated audit trail

## Testing
Tested with npm test and all tests passed.

## Security
No security implications.

## Changelog
Updated CHANGELOG.md with new feature.
          `,
          labels: ["feature", "trivial"],  // Add trivial label to skip changelog check
          base_branch: "develop",
          head_branch: "feature/audit-logging",
          number: 123,
          author: "test-user",
        },
        files_modified: ["src/logging.ts", "src/index.ts"],
        additions: 150,
        deletions: 20,
      };

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("COMPLIANT");
      expect(result.violations.length).toBe(0);
    });
  });

  describe("Report Generation", () => {
    it("should generate markdown report", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Test feature",
          body: "This is a test",
          labels: [],
          base_branch: "develop",
          head_branch: "feature/test",
          number: 1,
          author: "test-user",
        },
        files_modified: ["src/test.ts"],
        additions: 10,
        deletions: 5,
      };

      const result = await engine.evaluate(prData);
      const report = engine.generateReport(result);

      expect(report).toContain("Policy Compliance Check");
      expect(report).toContain(result.status);
      expect(report).toContain(result.summary);
    });
  });
});
