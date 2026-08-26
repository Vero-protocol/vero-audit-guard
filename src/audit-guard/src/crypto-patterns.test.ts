import {
  CRYPTO_PATTERNS,
  CRYPTO_PATTERN_IDS,
} from "./crypto-patterns";

describe("crypto-patterns", () => {
  const getPattern = (id: string) => {
    const pattern = CRYPTO_PATTERNS.find((p) => p.id === id);
    if (!pattern) {
      throw new Error(`Pattern not found: ${id}`);
    }
    return pattern;
  };

  describe("pattern library", () => {
    it("exports all documented crypto pattern ids", () => {
      expect(CRYPTO_PATTERN_IDS).toEqual([
        "WEAK_HASH_MD5",
        "WEAK_HASH_SHA1",
        "WEAK_CIPHER_DES",
        "WEAK_CIPHER_RC4",
        "WEAK_RSA_KEY_SIZE",
        "ECB_MODE",
        "HARDCODED_IV_OR_NONCE",
        "WEAK_RANDOM_MATH",
      ]);
    });

    it("contains one detector for every exported id", () => {
      expect(CRYPTO_PATTERNS).toHaveLength(CRYPTO_PATTERN_IDS.length);

      for (const pattern of CRYPTO_PATTERNS) {
        expect(pattern.id).toBeTruthy();
        expect(pattern.title).toBeTruthy();
        expect(pattern.description).toBeTruthy();
        expect(typeof pattern.detect).toBe("function");
      }
    });

    it("returns no findings for clean cryptographic code", () => {
      const patternInputs: Record<string, string> = {
        WEAK_HASH_MD5: 'const hash = crypto.createHash("sha256");',
        WEAK_HASH_SHA1: 'const hash = crypto.createHash("sha256");',
        WEAK_CIPHER_DES: 'const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);',
        WEAK_CIPHER_RC4: 'const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);',
        WEAK_RSA_KEY_SIZE:
          'crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });',
        ECB_MODE:
          'const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);',
        HARDCODED_IV_OR_NONCE:
          'const iv = crypto.randomBytes(16);',
        WEAK_RANDOM_MATH:
          'const jitter = Math.random() * 100;',
      };

      for (const [id, code] of Object.entries(patternInputs)) {
        expect(getPattern(id).detect(code)).toHaveLength(0);
      }
    });
  });

  describe("WEAK_HASH_MD5", () => {
    it("detects MD5", () => {
      const findings = getPattern("WEAK_HASH_MD5").detect(
        'const hash = crypto.createHash("md5");',
      );

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe("WEAK_HASH_MD5");
      expect(findings[0].severity).toBe("CRITICAL");
    });

    it("does not flag words containing md5 as a suffix", () => {
      expect(
        getPattern("WEAK_HASH_MD5").detect('const md5sum = "file";'),
      ).toHaveLength(0);
    });
  });

  describe("WEAK_HASH_SHA1", () => {
    it("detects SHA-1", () => {
      const findings = getPattern("WEAK_HASH_SHA1").detect(
        'const hash = crypto.createHash("sha1");',
      );

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe("WEAK_HASH_SHA1");
    });

    it("does not flag SHA-256", () => {
      expect(
        getPattern("WEAK_HASH_SHA1").detect(
          'const hash = crypto.createHash("sha256");',
        ),
      ).toHaveLength(0);
    });
  });

  describe("WEAK_CIPHER_DES", () => {
    it("detects DES and 3DES", () => {
      const findings = getPattern("WEAK_CIPHER_DES").detect(
        'const cipher = crypto.createCipheriv("des-ede3-cbc", key, iv);',
      );

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe("WEAK_CIPHER_DES");
    });

    it("does not flag AES-GCM", () => {
      expect(
        getPattern("WEAK_CIPHER_DES").detect(
          'const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);',
        ),
      ).toHaveLength(0);
    });
  });

  describe("WEAK_CIPHER_RC4", () => {
    it("detects RC4", () => {
      const findings = getPattern("WEAK_CIPHER_RC4").detect(
        'const cipher = crypto.createCipheriv("rc4", key, iv);',
      );

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe("WEAK_CIPHER_RC4");
    });

    it("does not flag unrelated cipher names", () => {
      expect(
        getPattern("WEAK_CIPHER_RC4").detect(
          'const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);',
        ),
      ).toHaveLength(0);
    });
  });

  describe("WEAK_RSA_KEY_SIZE", () => {
    it("detects RSA-1024", () => {
      const findings = getPattern("WEAK_RSA_KEY_SIZE").detect(
        'crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });',
      );

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe("WEAK_RSA_KEY_SIZE");
    });

    it("does not flag RSA-2048", () => {
      expect(
        getPattern("WEAK_RSA_KEY_SIZE").detect(
          'crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });',
        ),
      ).toHaveLength(0);
    });
  });

  describe("ECB_MODE", () => {
    it("detects AES-ECB", () => {
      const findings = getPattern("ECB_MODE").detect(
        'const cipher = crypto.createCipheriv("aes-256-ecb", key, null);',
      );

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe("ECB_MODE");
    });

    it("does not flag AES-GCM", () => {
      expect(
        getPattern("ECB_MODE").detect(
          'const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);',
        ),
      ).toHaveLength(0);
    });
  });

  describe("HARDCODED_IV_OR_NONCE", () => {
    it("detects a hardcoded IV in crypto context", () => {
      const findings = getPattern("HARDCODED_IV_OR_NONCE").detect(
        [
          'const iv = "00112233445566778899aabbccddeeff";',
          'const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);',
        ].join("\n"),
      );

      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].ruleId).toBe("HARDCODED_IV_OR_NONCE");
    });

    it("does not flag an unrelated hardcoded value", () => {
      expect(
        getPattern("HARDCODED_IV_OR_NONCE").detect(
          'const value = "0011223344556677";',
        ),
      ).toHaveLength(0);
    });
  });

  describe("WEAK_RANDOM_MATH", () => {
    it("detects Math.random used for token material", () => {
      const findings = getPattern("WEAK_RANDOM_MATH").detect(
        [
          "function makeToken() {",
          '  const nonce = Math.random().toString(36);',
          "  return nonce;",
          "}",
        ].join("\n"),
      );

      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].ruleId).toBe("WEAK_RANDOM_MATH");
    });

    it("does not flag Math.random used for UI jitter", () => {
      expect(
        getPattern("WEAK_RANDOM_MATH").detect(
          "const jitter = Math.random() * 100;",
        ),
      ).toHaveLength(0);
    });
  });

  describe("finding metadata", () => {
    it("includes file and line information when context is supplied", () => {
      const findings = getPattern("WEAK_HASH_MD5").detect(
        'const hash = crypto.createHash("md5");',
        {
          file: "example.ts",
          lines: ['const hash = crypto.createHash("md5");'],
        },
      );

      expect(findings[0].file).toBe("example.ts");
      expect(findings[0].line).toBe(1);
      expect(findings[0].snippet).toContain("md5");
    });
  });
});
