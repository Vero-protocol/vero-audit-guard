/**
 * Tests for Policy Engine
 */

import PolicyEngine, { PRData } from "../src/policy-engine";
import * as fs from "fs";
import * as path from "path";

describe("PolicyEngine", () => {
  let engine: PolicyEngine;
  const authorizedRelayer = Keypair.random();

  beforeEach(() => {
    engine = new PolicyEngine();
    process.env.AUTHORIZED_ADDRESSES = authorizedRelayer.publicKey();
  });

  afterEach(() => {
    delete process.env.AUTHORIZED_ADDRESSES;
  });

  function signPRData(prData: PRData, keypair: Keypair, timestamp: number): PRData {
    const payloadData = {
      pull_request: prData.pull_request,
      files_modified: prData.files_modified,
      additions: prData.additions,
      deletions: prData.deletions,
      dependencies_added: prData.dependencies_added,
      dependencies_updated: prData.dependencies_updated,
      relayer: keypair.publicKey(),
      timestamp,
    };

    const payload = JSON.stringify(payloadData);
    const signature = keypair.sign(Buffer.from(payload)).toString("hex");

    return {
      ...prData,
      relayer: keypair.publicKey(),
      signature,
      timestamp,
    };
  }

  describe("PR Title Validation", () => {
    it("should flag empty PR title", async () => {
      const prData: PRData = signPRData({
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
      }, authorizedRelayer, Date.now());

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("NON_COMPLIANT");
      expect(result.violations.some((v) => v.rule === "PR_TITLE_EMPTY")).toBe(
        true
      );
    });

    it("should flag short PR title", async () => {
      const prData: PRData = signPRData({
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
      }, authorizedRelayer, Date.now());

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("NON_COMPLIANT");
      expect(result.violations.some((v) => v.rule === "PR_TITLE_TOO_SHORT")).toBe(
        true
      );
    });

    it("should accept valid PR title", async () => {
      const prData: PRData = signPRData({
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
      }, authorizedRelayer, Date.now());

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
      const prData: PRData = signPRData({
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
      }, authorizedRelayer, Date.now());

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("NON_COMPLIANT");
      expect(
        result.violations.some((v) => v.rule === "PR_DESCRIPTION_MISSING")
      ).toBe(true);
    });

    it("should warn about undocumented testing", async () => {
      const prData: PRData = signPRData({
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
      }, authorizedRelayer, Date.now());

      const result = await engine.evaluate(prData);
      expect(
        result.warnings.some((w) => w.rule === "PR_TESTING_UNDOCUMENTED")
      ).toBe(true);
    });

    it("should not warn when testing is documented", async () => {
      const prData: PRData = signPRData({
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
      }, authorizedRelayer, Date.now());

      const result = await engine.evaluate(prData);
      expect(
        result.warnings.some((w) => w.rule === "PR_TESTING_UNDOCUMENTED")
      ).toBe(false);
    });
  });

  describe("Breaking Changes", () => {
    it("should flag breaking changes without label", async () => {
      const prData: PRData = signPRData({
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
      }, authorizedRelayer, Date.now());

      const result = await engine.evaluate(prData);
      expect(
        result.violations.some((v) => v.rule === "BREAKING_CHANGE_NOT_LABELED")
      ).toBe(true);
    });

    it("should accept breaking changes with label", async () => {
      const prData: PRData = signPRData({
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
      }, authorizedRelayer, Date.now());

      const result = await engine.evaluate(prData);
      expect(
        result.violations.some((v) => v.rule === "BREAKING_CHANGE_NOT_LABELED")
      ).toBe(false);
    });
  });

  describe("Security-Sensitive Changes", () => {
    it("should flag security changes without label", async () => {
      const prData: PRData = signPRData({
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
      }, authorizedRelayer, Date.now());

      const result = await engine.evaluate(prData);
      // This produces a warning, not a violation
      const hasSecurityWarning = result.warnings.some(
        (w) => w.rule === "SECURITY_CHANGE_NEEDS_LABEL"
      );
      expect(hasSecurityWarning).toBe(true);
    });

    it("should accept security changes with security label", async () => {
      const prData: PRData = signPRData({
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
      }, authorizedRelayer, Date.now());

      const result = await engine.evaluate(prData);
      const hasSecurityWarning = result.warnings.some(
        (w) => w.rule === "SECURITY_CHANGE_NEEDS_LABEL"
      );
      expect(hasSecurityWarning).toBe(false);
    });
  });

  describe("Cryptographic Security", () => {
    it("should flag MD5 usage", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Update hash function",
          body: "This PR uses MD5 for hashing",
          labels: ["security"],
          base_branch: "main",
          head_branch: "feat/hash",
          number: 1,
          author: "user",
        },
        files_modified: ["src/hash.ts"],
        file_contents: {
          "src/hash.ts": "const hash = md5(data);",
        },
        additions: 10,
        deletions: 2,
      };

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("NON_COMPLIANT");
      expect(
        result.violations.some(
          (v) =>
            v.rule === "INSECURE_CRYPTO_ALGORITHM" && v.message.includes("MD5")
        )
      ).toBe(true);
    });

    it("should flag MD5 usage in string literals", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Update hash function",
          body: "This PR uses MD5 in createHash",
          labels: ["security"],
          base_branch: "main",
          head_branch: "feat/hash",
          number: 1,
          author: "user",
        },
        files_modified: ["src/hash.ts"],
        file_contents: {
          "src/hash.ts": "const hash = crypto.createHash('md5').update(data).digest('hex');",
        },
        additions: 10,
        deletions: 2,
      };

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("NON_COMPLIANT");
      expect(
        result.violations.some(
          (v) =>
            v.rule === "INSECURE_CRYPTO_ALGORITHM" && v.message.includes("MD5")
        )
      ).toBe(true);
    });

    it("should flag SHA1 usage", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Update hash function",
          body: "This PR uses SHA1 for hashing",
          labels: ["security"],
          base_branch: "main",
          head_branch: "feat/hash",
          number: 1,
          author: "user",
        },
        files_modified: ["src/hash.ts"],
        file_contents: {
          "src/hash.ts": "const hash = sha1(data);",
        },
        additions: 10,
        deletions: 2,
      };

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("NON_COMPLIANT");
      expect(
        result.violations.some(
          (v) =>
            v.rule === "INSECURE_CRYPTO_ALGORITHM" && v.message.includes("SHA1")
        )
      ).toBe(true);
    });

    it("should flag RC4 usage", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Update cipher",
          body: "This PR uses RC4",
          labels: ["security"],
          base_branch: "main",
          head_branch: "feat/cipher",
          number: 1,
          author: "user",
        },
        files_modified: ["src/cipher.ts"],
        file_contents: {
          "src/cipher.ts": "const cipher = rc4(key);",
        },
        additions: 10,
        deletions: 2,
      };

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("NON_COMPLIANT");
      expect(
        result.violations.some(
          (v) =>
            v.rule === "INSECURE_CRYPTO_ALGORITHM" && v.message.includes("RC4")
        )
      ).toBe(true);
    });

    it("should flag DES usage", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Update cipher",
          body: "This PR uses DES",
          labels: ["security"],
          base_branch: "main",
          head_branch: "feat/cipher",
          number: 1,
          author: "user",
        },
        files_modified: ["src/cipher.ts"],
        file_contents: {
          "src/cipher.ts": "const cipher = des(key);",
        },
        additions: 10,
        deletions: 2,
      };

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("NON_COMPLIANT");
      expect(
        result.violations.some(
          (v) =>
            v.rule === "INSECURE_CRYPTO_ALGORITHM" && v.message.includes("DES")
        )
      ).toBe(true);
    });

    it("should not flag modern crypto like SHA256", async () => {
      const prData: PRData = {
        pull_request: {
          title: "Update hash function",
          body: "This PR uses SHA256 for hashing",
          labels: ["security"],
          base_branch: "main",
          head_branch: "feat/hash",
          number: 1,
          author: "user",
        },
        files_modified: ["src/hash.ts"],
        file_contents: {
          "src/hash.ts": "const hash = sha256(data);",
        },
        additions: 10,
        deletions: 2,
      };

      const result = await engine.evaluate(prData);
      expect(
        result.violations.some((v) => v.rule === "INSECURE_CRYPTO_ALGORITHM")
      ).toBe(false);
    });
  });

  describe("Large Changes", () => {
    it("should warn about many files modified", async () => {
      const files = Array.from({ length: 25 }, (_, i) => `src/file${i}.ts`);
      const prData: PRData = signPRData({
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
      }, authorizedRelayer, Date.now());

      const result = await engine.evaluate(prData);
      expect(
        result.warnings.some((w) => w.rule === "TOO_MANY_FILES_MODIFIED")
      ).toBe(true);
    });

    it("should warn about large diffs", async () => {
      const prData: PRData = signPRData({
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
      }, authorizedRelayer, Date.now());

      const result = await engine.evaluate(prData);
      expect(
        result.warnings.some((w) => w.rule === "LARGE_DIFF_REQUIRES_JUSTIFICATION")
      ).toBe(true);
    });
  });

  describe("Compliant PR", () => {
    it("should pass compliant PR", async () => {
      const prData: PRData = signPRData({
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
      }, authorizedRelayer, Date.now());

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("COMPLIANT");
      expect(result.violations.length).toBe(0);
    });
  });

  describe("Report Generation", () => {
    it("should generate markdown report", async () => {
      const prData: PRData = signPRData({
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
      }, authorizedRelayer, Date.now());

      const result = await engine.evaluate(prData);
      const report = engine.generateReport(result);

      expect(report).toContain("Policy Compliance Check");
      expect(report).toContain(result.status);
      expect(report).toContain(result.summary);
    });
  });

  describe("Integer Overflow Detection", () => {
    const testFile = path.join(__dirname, "overflow-test.rs");

    afterEach(() => {
      if (fs.existsSync(testFile)) {
        fs.unlinkSync(testFile);
      }
    });

    it("should flag potential overflow in Rust file", async () => {
      const content = `
        fn test() {
          let a = 10000000000000000000;
          let b = a * 2;
        }
      `;
      fs.writeFileSync(testFile, content);

      const prData: PRData = {
        pull_request: {
          title: "Fix overflow bug in core contract",
          body: "This PR fixes a potential overflow. Testing included.",
          labels: ["security"],
          base_branch: "main",
          head_branch: "fix/overflow",
          number: 1,
          author: "security-expert",
        },
        files_modified: [testFile],
        additions: 10,
        deletions: 2,
      };

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("NON_COMPLIANT");
      expect(result.violations.some((v) => v.rule === "INTEGER_OVERFLOW")).toBe(
        true
      );
    });

    it("should flag potential underflow in Rust file", async () => {
      const content = `
        fn test() {
          let a = 5;
          let b = a - 10;
        }
      `;
      fs.writeFileSync(testFile, content);

      const prData: PRData = {
        pull_request: {
          title: "Fix underflow bug in core contract",
          body: "This PR fixes a potential underflow. Testing included.",
          labels: ["security"],
          base_branch: "main",
          head_branch: "fix/underflow",
          number: 2,
          author: "security-expert",
        },
        files_modified: [testFile],
        additions: 10,
        deletions: 2,
      };

      const result = await engine.evaluate(prData);
      expect(result.status).toBe("NON_COMPLIANT");
      expect(result.violations.some((v) => v.rule === "INTEGER_UNDERFLOW")).toBe(
        true
      );
    });

    it("should not flag safe arithmetic", async () => {
      const content = `
        fn test() {
          let a = 100;
          let b = a + 50;
        }
      `;
      fs.writeFileSync(testFile, content);

      const prData: PRData = {
        pull_request: {
          title: "Safe arithmetic changes",
          body: "This PR performs safe arithmetic. Tested thoroughly.",
          labels: ["trivial"],
          base_branch: "main",
          head_branch: "feat/safe",
          number: 3,
          author: "developer",
        },
        files_modified: [testFile],
        additions: 5,
        deletions: 1,
      };

      const result = await engine.evaluate(prData);
      expect(result.violations.some((v) => v.rule === "INTEGER_OVERFLOW")).toBe(
        false
      );
      expect(result.violations.some((v) => v.rule === "INTEGER_UNDERFLOW")).toBe(
        false
      );
    });
  });
});
