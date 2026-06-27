/**
 * Tests for WeakCryptoScanner
 *
 * Issue #103: [Audit-Guard #8] Scan for weak cryptographic primitives
 */

import WeakCryptoScanner from "./crypto-scanner";
import { CRYPTO_PATTERNS, CRYPTO_PATTERN_IDS } from "./crypto-patterns";

describe("WeakCryptoScanner", () => {
  let scanner: WeakCryptoScanner;

  beforeEach(() => {
    scanner = new WeakCryptoScanner();
  });

  describe("Pattern library", () => {
    it("should expose the documented pattern ids", () => {
      expect(CRYPTO_PATTERN_IDS).toEqual(
        expect.arrayContaining([
          "WEAK_HASH_MD5",
          "WEAK_HASH_SHA1",
          "WEAK_CIPHER_DES",
          "WEAK_CIPHER_RC4",
          "WEAK_RSA_KEY_SIZE",
          "ECB_MODE",
          "HARDCODED_IV_OR_NONCE",
          "WEAK_RANDOM_MATH",
        ])
      );
      // frozen
      expect(Object.isFrozen(CRYPTO_PATTERNS)).toBe(true);
    });

    it("should reject non-string input", () => {
      expect(() => scanner.scan(null as unknown as string)).toThrow(/must be a string/);
    });
  });

  describe("Pattern: WEAK_HASH_MD5", () => {
    it("should flag MD5.createHash('md5')", () => {
      const code = `
import crypto from "crypto";
const hash = crypto.createHash("md5").update(data).digest("hex");
`;
      const r = scanner.scan(code);
      expect(r.status).toBe("VULNERABLE");
      expect(r.findings.some((f) => f.ruleId === "WEAK_HASH_MD5")).toBe(true);
    });

    it("should NOT flag a variable named 'md5sum' (word boundary protects suffixes)", () => {
      // The regex uses a word boundary after "md5", so "md5sum" does not match.
      const code = `const md5sum = "filename.txt";`;
      const r = scanner.scan(code);
      expect(r.findings.some((f) => f.ruleId === "WEAK_HASH_MD5")).toBe(false);
    });
  });

  describe("Pattern: WEAK_HASH_SHA1", () => {
    it("should flag createHash('sha1')", () => {
      const code = `
const hash = crypto.createHash("sha1").update(data).digest("hex");
`;
      const r = scanner.scan(code);
      expect(r.findings.some((f) => f.ruleId === "WEAK_HASH_SHA1")).toBe(true);
    });

    it("should NOT flag SHA-256", () => {
      const code = `
const hash = crypto.createHash("sha256").update(data).digest("hex");
`;
      const r = scanner.scan(code);
      expect(r.findings.some((f) => f.ruleId === "WEAK_HASH_SHA1")).toBe(false);
    });
  });

  describe("Pattern: WEAK_CIPHER_DES", () => {
    it("should flag DES usage", () => {
      const code = `
const cipher = crypto.createCipheriv("des-ede3-cbc", key, iv);
`;
      const r = scanner.scan(code);
      expect(r.findings.some((f) => f.ruleId === "WEAK_CIPHER_DES")).toBe(true);
    });
  });

  describe("Pattern: WEAK_CIPHER_RC4", () => {
    it("should flag RC4 usage", () => {
      const code = `
const cipher = crypto.createCipheriv("rc4", key, "");
`;
      const r = scanner.scan(code);
      expect(r.findings.some((f) => f.ruleId === "WEAK_CIPHER_RC4")).toBe(true);
    });
  });

  describe("Pattern: WEAK_RSA_KEY_SIZE", () => {
    it("should flag RSA-1024", () => {
      const code = `
const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
`;
      const r = scanner.scan(code);
      expect(r.findings.some((f) => f.ruleId === "WEAK_RSA_KEY_SIZE")).toBe(true);
    });

    it("should NOT flag RSA-2048", () => {
      const code = `
const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
`;
      const r = scanner.scan(code);
      expect(r.findings.some((f) => f.ruleId === "WEAK_RSA_KEY_SIZE")).toBe(false);
    });
  });

  describe("Pattern: ECB_MODE", () => {
    it("should flag AES-ECB", () => {
      const code = `
const cipher = crypto.createCipheriv("aes-256-ecb", key, null);
`;
      const r = scanner.scan(code);
      expect(r.findings.some((f) => f.ruleId === "ECB_MODE")).toBe(true);
    });

    it("should NOT flag AES-GCM", () => {
      const code = `
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
`;
      const r = scanner.scan(code);
      expect(r.findings.some((f) => f.ruleId === "ECB_MODE")).toBe(false);
    });
  });

  describe("Pattern: HARDCODED_IV_OR_NONCE", () => {
    it("should flag a hardcoded IV in a crypto context", () => {
      // The hardcoded IV must be near a crypto keyword for the pattern to fire.
      const code = `
const iv = "00112233445566778899aabbccddeeff"; // crypto: AES initialization vector
const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
`;
      const r = scanner.scan(code);
      expect(r.findings.some((f) => f.ruleId === "HARDCODED_IV_OR_NONCE")).toBe(true);
    });

    it("should flag a hardcoded IV when crypto use is on a nearby line", () => {
      const code = `
const iv = "00112233445566778899aabbccddeeff";
const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
`;
      const r = scanner.scan(code);
      expect(r.findings.some((f) => f.ruleId === "HARDCODED_IV_OR_NONCE")).toBe(true);
    });

    it("should NOT flag a hardcoded value without crypto context", () => {
      const code = `
const nonce = "0011223344556677";
const value = parseInt(nonce, 16);
`;
      const r = scanner.scan(code);
      expect(r.findings.some((f) => f.ruleId === "HARDCODED_IV_OR_NONCE")).toBe(false);
    });
  });

  describe("Pattern: WEAK_RANDOM_MATH", () => {
    it("should flag Math.random() used to make a token", () => {
      const code = `
function makeToken() {
  const nonce = Math.random().toString(36).slice(2);
  return nonce;
}
`;
      const r = scanner.scan(code);
      expect(r.findings.some((f) => f.ruleId === "WEAK_RANDOM_MATH")).toBe(true);
    });

    it("should NOT flag Math.random() used for UI jitter", () => {
      const code = `
const jitter = Math.random() * 100;
`;
      const r = scanner.scan(code);
      expect(r.findings.some((f) => f.ruleId === "WEAK_RANDOM_MATH")).toBe(false);
    });
  });

  describe("Multi-pattern detection on a single sample", () => {
    it("should fire multiple rules against a deliberately-bad sample", () => {
      const code = `
function badCrypto(password: string) {
  const iv = "00000000000000000000000000000000";
  const md5Hash = crypto.createHash("md5").update(password).digest("hex");
  const cipher = crypto.createCipheriv("des-ede3-ecb", key, "");
  const weakKey = crypto.generateKeyPairSync("rsa", { modulusLength: 512 });
  const nonce = Math.random().toString(36);
  return { md5Hash, nonce };
}
`;
      const r = scanner.scan(code);
      const seen = new Set(r.findings.map((f) => f.ruleId));
      expect(seen.size).toBeGreaterThanOrEqual(4);
      expect(r.status).toBe("VULNERABLE");
      expect(r.count).toBe(seen.size);
    });
  });

  describe("Safe code (no findings)", () => {
    it("should report SAFE for clean code", () => {
      const code = `
import crypto from "crypto";
function encrypt(data: Buffer, key: Buffer) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return { iv, ciphertext: cipher.update(data) };
}
`;
      const r = scanner.scan(code);
      expect(r.status).toBe("SAFE");
      expect(r.count).toBe(0);
    });
  });

  describe("Severity sort & line numbers", () => {
    it("should sort findings by severity (CRITICAL first) then by line", () => {
      const code = `
const a = crypto.createHash("md5");
const b = crypto.createHash("sha1");
`;
      const r = scanner.scan(code, { file: "crypto.ts" });
      const ranks = r.findings.map(
        (f) =>
          ({
            LOW: 1,
            MEDIUM: 2,
            HIGH: 3,
            CRITICAL: 4,
          }[f.severity])
      );
      const sorted = [...ranks].sort((a, b) => b - a);
      expect(ranks).toEqual(sorted);
      for (const f of r.findings) {
        expect(f.file).toBe("crypto.ts");
        expect(typeof f.line).toBe("number");
      }
    });
  });

  describe("Pattern subsetting", () => {
    it("should respect options.patterns restriction", () => {
      const code = `
const md5 = crypto.createHash("md5");
const sha1 = crypto.createHash("sha1");
`;
      const r = scanner.scan(code, { patterns: ["WEAK_HASH_SHA1"] });
      expect(r.findings.length).toBe(1);
      expect(r.findings[0].ruleId).toBe("WEAK_HASH_SHA1");
    });
  });

  describe("Report generation", () => {
    it("should produce a markdown report", () => {
      const code = `const hash = crypto.createHash("md5");`;
      const r = scanner.scan(code, { file: "crypto.ts" });
      const report = scanner.generateReport(r);
      expect(report).toContain("Weak Cryptographic Primitive Scan");
      expect(report).toContain("VULNERABLE");
      expect(report).toContain("crypto.ts");
      expect(report).toContain("WEAK_HASH_MD5");
    });
  });

  describe("A buggy pattern should not break the scan", () => {
    it("should swallow exceptions from a throwing pattern", () => {
      const throwingPattern = {
        id: "BROKEN",
        title: "broken",
        description: "broken",
        severity: "LOW" as const,
        detect: () => {
          throw new Error("intentional");
        },
      };
      const customScanner = new WeakCryptoScanner([throwingPattern]);
      const r = customScanner.scan("hello");
      expect(r.status).toBe("SAFE");
    });
  });
});
