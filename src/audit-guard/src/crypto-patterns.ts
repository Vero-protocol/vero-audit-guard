/**
 * Weak Cryptographic Primitive Detection - Pattern Library
 *
 * Issue #103: [Audit-Guard #8] Scan for weak cryptographic primitives
 *
 * Each pattern is a small, focused detector that takes a code snippet
 * and emits zero or more CryptoFinding objects. Patterns are pure
 * (no I/O, no global state) so they can be unit-tested or composed.
 *
 * Heuristics are intentionally conservative: a finding is something a
 * human reviewer should at least glance at. False positives are
 * expected; false negatives are not - when in doubt, flag.
 */

import type { CryptoFinding, CryptoSeverity } from "./crypto-scanner";

// Re-export for callers that may import the type from either module.
export type { CryptoSeverity };

/** Context passed to a pattern detector (file path, line breakdown). */
export interface CryptoDetectionContext {
  file?: string;
  /** Pre-split lines of the source. */
  lines?: string[];
}

export interface CryptoPattern {
  id: string;
  title: string;
  description: string;
  severity: CryptoSeverity;
  /** Reference URL for remediation. */
  references?: string[];
  detect: (code: string, context?: CryptoDetectionContext) => CryptoFinding[];
}

/** Helper: get lines lazily. */
function lookupLines(
  code: string,
  context?: CryptoDetectionContext
): { lines: string[] } {
  if (context?.lines) return { lines: context.lines };
  return { lines: code.split(/\r?\n/) };
}

/** Build a CryptoFinding with sensible defaults. */
function makeFinding(
  partial: Omit<CryptoFinding, "snippet" | "message" | "remediation"> & {
    message: string;
    remediation: string;
    snippet?: string;
  },
  lines: string[]
): CryptoFinding {
  const snippet =
    partial.snippet !== undefined
      ? partial.snippet
      : (lines[partial.line! - 1] ?? "").trim();
  return {
    file: partial.file,
    line: partial.line,
    snippet,
    ruleId: partial.ruleId,
    severity: partial.severity,
    message: partial.message,
    remediation: partial.remediation,
  };
}

// ----------------------------------------------------------------------------
// Pattern #1: WEAK_HASH_MD5
// Detects MD5 digests/hashes in code, including common library calls.
// ----------------------------------------------------------------------------
const WEAK_HASH_MD5: CryptoPattern = {
  id: "WEAK_HASH_MD5",
  title: "Use of MD5 hash function",
  description:
    "MD5 is cryptographically broken and vulnerable to collision attacks. It must not be used for signatures, integrity, or any security-sensitive purpose.",
  severity: "CRITICAL",
  references: ["https://owasp.org/www-community/vulnerabilities/Insecure_Hash_Algorithm"],
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: CryptoFinding[] = [];
    const md5Re = /\b(md5|MD5)\b/;
    for (let i = 0; i < lines.length; i++) {
      if (!md5Re.test(lines[i])) continue;
      findings.push(
        makeFinding(
          {
            file: context?.file,
            line: i + 1,
            ruleId: WEAK_HASH_MD5.id,
            severity: WEAK_HASH_MD5.severity,
            message: `MD5 detected on line ${i + 1}. MD5 is broken and unsuitable for security use.`,
            remediation:
              "Replace MD5 with SHA-256 or SHA-3 for hashing, or a modern authenticated scheme (e.g. HMAC-SHA256) for integrity.",
          },
          lines
        )
      );
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #2: WEAK_HASH_SHA1
// Detects SHA1 digests/hashes in code, including common library calls.
// ----------------------------------------------------------------------------
const WEAK_HASH_SHA1: CryptoPattern = {
  id: "WEAK_HASH_SHA1",
  title: "Use of SHA-1 hash function",
  description:
    "SHA-1 is deprecated and considered broken for collision resistance. Avoid for signatures, certificates, and integrity checks.",
  severity: "HIGH",
  references: ["https://owasp.org/www-community/vulnerabilities/Insecure_Hash_Algorithm"],
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: CryptoFinding[] = [];
    const sha1Re = /\b(sha1|SHA1|sha-1|SHA-1)\b/;
    for (let i = 0; i < lines.length; i++) {
      if (!sha1Re.test(lines[i])) continue;
      findings.push(
        makeFinding(
          {
            file: context?.file,
            line: i + 1,
            ruleId: WEAK_HASH_SHA1.id,
            severity: WEAK_HASH_SHA1.severity,
            message: `SHA-1 detected on line ${i + 1}. SHA-1 is deprecated and should not be used for security-sensitive operations.`,
            remediation:
              "Replace SHA-1 with SHA-256 or SHA-3. For code signing or certificates, migrate to stronger algorithms.",
          },
          lines
        )
      );
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #3: WEAK_CIPHER_DES
// Detects DES / 3DES / TDEA usage.
// ----------------------------------------------------------------------------
const WEAK_CIPHER_DES: CryptoPattern = {
  id: "WEAK_CIPHER_DES",
  title: "Use of DES / 3DES block cipher",
  description:
    "DES has an effective 56-bit key and is brute-forceable. 3DES/TDEA is deprecated (Sweet32 attack) and should not be used.",
  severity: "CRITICAL",
  references: ["https://sweet32.info/"],
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: CryptoFinding[] = [];
    const desRe = /\b(des|3des|tripledes|tdea|TDES|TDEA|DES|3DES|TripleDES)\b/;
    for (let i = 0; i < lines.length; i++) {
      if (!desRe.test(lines[i])) continue;
      findings.push(
        makeFinding(
          {
            file: context?.file,
            line: i + 1,
            ruleId: WEAK_CIPHER_DES.id,
            severity: WEAK_CIPHER_DES.severity,
            message: `DES/3DES detected on line ${i + 1}. These ciphers are deprecated and vulnerable to practical attacks.`,
            remediation:
              "Replace with AES-256-GCM or ChaCha20-Poly1305. Use authenticated encryption with a random IV/nonce.",
          },
          lines
        )
      );
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #4: WEAK_CIPHER_RC4
// Detects RC4 / ARC4 usage.
// ----------------------------------------------------------------------------
const WEAK_CIPHER_RC4: CryptoPattern = {
  id: "WEAK_CIPHER_RC4",
  title: "Use of RC4 stream cipher",
  description:
    "RC4 has statistical biases and is prohibited in TLS. It must not be used for encryption.",
  severity: "CRITICAL",
  references: ["https://tools.ietf.org/html/rfc7465"],
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: CryptoFinding[] = [];
    const rc4Re = /\b(rc4|RC4|arc4|ARC4)\b/;
    for (let i = 0; i < lines.length; i++) {
      if (!rc4Re.test(lines[i])) continue;
      findings.push(
        makeFinding(
          {
            file: context?.file,
            line: i + 1,
            ruleId: WEAK_CIPHER_RC4.id,
            severity: WEAK_CIPHER_RC4.severity,
            message: `RC4 detected on line ${i + 1}. RC4 is broken and banned in modern protocols.`,
            remediation: "Replace RC4 with AES-256-GCM or ChaCha20-Poly1305.",
          },
          lines
        )
      );
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #5: WEAK_RSA_KEY_SIZE
// Detects RSA key sizes of 512 or 1024 bits.
// ----------------------------------------------------------------------------
const WEAK_RSA_KEY_SIZE: CryptoPattern = {
  id: "WEAK_RSA_KEY_SIZE",
  title: "Weak RSA key size",
  description:
    "RSA keys smaller than 2048 bits are considered weak. 512-bit and 1024-bit RSA keys have been factored or are within reach of motivated attackers.",
  severity: "HIGH",
  references: ["https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf"],
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: CryptoFinding[] = [];
    const weakRsaRe = /\b(rsa|RSA)\b[^\n]*?\b(512|1024)\b|\b(512|1024)\b[^\n]*?\b(rsa|RSA)\b/;
    for (let i = 0; i < lines.length; i++) {
      if (!weakRsaRe.test(lines[i])) continue;
      findings.push(
        makeFinding(
          {
            file: context?.file,
            line: i + 1,
            ruleId: WEAK_RSA_KEY_SIZE.id,
            severity: WEAK_RSA_KEY_SIZE.severity,
            message: `Weak RSA key size (512 or 1024 bits) detected on line ${i + 1}.`,
            remediation:
              "Use RSA-2048 as a minimum; prefer RSA-3072 or ECDSA P-256/P-384 for new designs.",
          },
          lines
        )
      );
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #6: ECB_MODE
// Detects ECB block cipher mode.
// ----------------------------------------------------------------------------
const ECB_MODE: CryptoPattern = {
  id: "ECB_MODE",
  title: "Use of ECB block cipher mode",
  description:
    "ECB mode leaks plaintext structure and is not semantically secure. Never use ECB for confidential data.",
  severity: "HIGH",
  references: ["https://cryptopals.com/sets/2/challenges/12"],
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: CryptoFinding[] = [];
    const ecbRe = /\bECB\b|_ECB\b|\becb\b/;
    for (let i = 0; i < lines.length; i++) {
      if (!ecbRe.test(lines[i])) continue;
      findings.push(
        makeFinding(
          {
            file: context?.file,
            line: i + 1,
            ruleId: ECB_MODE.id,
            severity: ECB_MODE.severity,
            message: `ECB mode detected on line ${i + 1}. ECB leaks plaintext structure and is insecure.`,
            remediation:
              "Use CBC with a random IV and authentication (e.g. HMAC) or, better, an authenticated mode such as GCM or ChaCha20-Poly1305.",
          },
          lines
        )
      );
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #7: HARDCODED_IV_OR_NONCE
// Detects hardcoded initialization vectors or nonces in crypto contexts.
// ----------------------------------------------------------------------------
const HARDCODED_IV_OR_NONCE: CryptoPattern = {
  id: "HARDCODED_IV_OR_NONCE",
  title: "Hardcoded IV or nonce",
  description:
    "A static/hardcoded IV or nonce defeats the security guarantees of symmetric encryption. IVs and nonces must be unique and unpredictable per message.",
  severity: "HIGH",
  references: ["https://owasp.org/www-community/vulnerabilities/Insecure_Randomness"],
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: CryptoFinding[] = [];
    // Look for assignments to iv/nonce/salt variables with hex literals,
    // but only when the surrounding lines also hint at a crypto context.
    const cryptoContextRe = /\b(aes|cipher|encrypt|decrypt|crypto|Crypto|AES|CIPHER)\b/;
    const hardcodedIvRe =
      /\b(iv|nonce|salt|initializationVector)\b\s*[:=]\s*["'`](0x[0-9a-fA-F]+|[0-9a-fA-F]{8,})["'`]/i;
    for (let i = 0; i < lines.length; i++) {
      if (!hardcodedIvRe.test(lines[i])) continue;
      // Require nearby crypto context to avoid flagging unrelated variables
      // named iv/nonce/salt while still catching split assignment/use pairs.
      const windowStart = Math.max(0, i - 2);
      const windowEnd = Math.min(lines.length, i + 3);
      const nearby = lines.slice(windowStart, windowEnd).join("\n");
      if (!cryptoContextRe.test(nearby)) continue;
      findings.push(
        makeFinding(
          {
            file: context?.file,
            line: i + 1,
            ruleId: HARDCODED_IV_OR_NONCE.id,
            severity: HARDCODED_IV_OR_NONCE.severity,
            message: `Hardcoded IV/nonce/salt detected on line ${i + 1}. Static values break confidentiality guarantees.`,
            remediation:
              "Generate a random IV/nonce for each encryption operation using a cryptographically secure random number generator.",
          },
          lines
        )
      );
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #8: WEAK_RANDOM_MATH
// Detects Math.random() used in a cryptographic or secret context.
// ----------------------------------------------------------------------------
const WEAK_RANDOM_MATH: CryptoPattern = {
  id: "WEAK_RANDOM_MATH",
  title: "Math.random() used for security-sensitive randomness",
  description:
    "Math.random() is not cryptographically secure. Using it for keys, nonces, tokens, or secrets is a vulnerability.",
  severity: "HIGH",
  references: ["https://owasp.org/www-community/vulnerabilities/Insecure_Randomness"],
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: CryptoFinding[] = [];
    const mathRandomRe = /\bMath\.random\s*\(\s*\)/;
    const cryptoContextRe =
      /\b(key|secret|token|password|nonce|iv|salt|crypto|encrypt|sign|auth|randomBytes|rng)\b/i;
    for (let i = 0; i < lines.length; i++) {
      if (!mathRandomRe.test(lines[i])) continue;
      // Look for a crypto context in the same line or the surrounding 2 lines.
      const windowStart = Math.max(0, i - 2);
      const windowEnd = Math.min(lines.length, i + 3);
      const nearby = lines.slice(windowStart, windowEnd).join("\n");
      if (!cryptoContextRe.test(nearby)) continue;
      findings.push(
        makeFinding(
          {
            file: context?.file,
            line: i + 1,
            ruleId: WEAK_RANDOM_MATH.id,
            severity: WEAK_RANDOM_MATH.severity,
            message: `Math.random() used in a security-sensitive context around line ${i + 1}.`,
            remediation:
              "Use a cryptographically secure random number generator (e.g. crypto.randomBytes in Node.js, crypto.getRandomValues in browsers, or os.urandom in Python).",
          },
          lines
        )
      );
    }
    return findings;
  },
};

/** Complete pattern library, exposed for callers that want to iterate. */
export const CRYPTO_PATTERNS: readonly CryptoPattern[] = Object.freeze([
  WEAK_HASH_MD5,
  WEAK_HASH_SHA1,
  WEAK_CIPHER_DES,
  WEAK_CIPHER_RC4,
  WEAK_RSA_KEY_SIZE,
  ECB_MODE,
  HARDCODED_IV_OR_NONCE,
  WEAK_RANDOM_MATH,
]);

export const CRYPTO_PATTERN_IDS = CRYPTO_PATTERNS.map((p) => p.id);
