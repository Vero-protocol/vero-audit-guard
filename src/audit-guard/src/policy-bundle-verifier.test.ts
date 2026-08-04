/**
 * Tests for Policy Bundle Signature Verification (Issue #171 / VAG-003)
 *
 * Covers the happy path plus non-happy-path and adversarial-input scenarios:
 * tampered bundles (add/remove/modify), forged/untrusted signatures, malformed
 * manifests and signatures, and missing configuration.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { Keypair } from "@stellar/stellar-sdk";
import PolicyBundleVerifier, {
  PolicyBundleError,
  PolicyBundleErrorCode,
  canonicalizeManifest,
  computeBundleManifest,
  signBundleManifest,
  TelemetrySink,
  PolicyBundleVerificationResult,
} from "./policy-bundle-verifier";

const MANIFEST_FILENAME = "bundle.manifest.json";

describe("Policy Bundle Signature Verification", () => {
  let tmpDir: string;
  let policiesDir: string;
  let signer: Keypair;
  let telemetry: jest.Mock<void, Parameters<TelemetrySink>>;

  const writePolicy = (name: string, body: string): void => {
    fs.writeFileSync(path.join(policiesDir, name), body);
  };

  const writeSignedManifest = (): void => {
    const manifest = computeBundleManifest(policiesDir);
    fs.writeFileSync(
      path.join(policiesDir, MANIFEST_FILENAME),
      JSON.stringify(manifest, null, 2)
    );
  };

  const currentSignature = (): string =>
    signBundleManifest(computeBundleManifest(policiesDir), signer);

  const makeVerifier = (
    overrides: Partial<ConstructorParameters<typeof PolicyBundleVerifier>[0]> = {}
  ): PolicyBundleVerifier =>
    new PolicyBundleVerifier({
      policiesDir,
      signature: currentSignature(),
      trustedSigners: [signer.publicKey()],
      telemetry,
      ...overrides,
    });

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vag-bundle-"));
    policiesDir = path.join(tmpDir, "policies");
    fs.mkdirSync(policiesDir);
    writePolicy("a.rego", "package a\ndeny := false\n");
    writePolicy("b.rego", "package b\ndeny := false\n");
    signer = Keypair.random();
    telemetry = jest.fn();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // ---- computeBundleManifest -------------------------------------------

  describe("computeBundleManifest", () => {
    it("produces a deterministic, sorted manifest", () => {
      const manifest = computeBundleManifest(policiesDir);
      expect(manifest.version).toBe(1);
      expect(manifest.algorithm).toBe("sha256");
      expect(manifest.files.map((f) => f.path)).toEqual(["a.rego", "b.rego"]);
      expect(manifest.bundle_digest).toMatch(/^[0-9a-f]{64}$/);
      // Recomputing yields identical output.
      expect(computeBundleManifest(policiesDir)).toEqual(manifest);
    });

    it("recurses into subdirectories with POSIX-relative paths", () => {
      fs.mkdirSync(path.join(policiesDir, "nested"));
      writePolicy(path.join("nested", "c.rego"), "package c\n");
      const manifest = computeBundleManifest(policiesDir);
      expect(manifest.files.map((f) => f.path)).toContain("nested/c.rego");
    });

    it("ignores non-policy files", () => {
      writePolicy("notes.txt", "not a policy");
      const manifest = computeBundleManifest(policiesDir);
      expect(manifest.files.map((f) => f.path)).toEqual(["a.rego", "b.rego"]);
    });

    it("throws BundleDirNotFound for a missing directory", () => {
      expect(() => computeBundleManifest(path.join(tmpDir, "nope"))).toThrow(
        PolicyBundleError
      );
      try {
        computeBundleManifest(path.join(tmpDir, "nope"));
      } catch (e) {
        expect((e as PolicyBundleError).code).toBe(
          PolicyBundleErrorCode.BundleDirNotFound
        );
      }
    });

    it("throws BundleDirNotFound when the path is a file", () => {
      const filePath = path.join(tmpDir, "afile");
      fs.writeFileSync(filePath, "x");
      try {
        computeBundleManifest(filePath);
        fail("expected throw");
      } catch (e) {
        expect((e as PolicyBundleError).code).toBe(
          PolicyBundleErrorCode.BundleDirNotFound
        );
      }
    });

    it("throws EmptyBundle when there are no policy files", () => {
      const empty = path.join(tmpDir, "empty");
      fs.mkdirSync(empty);
      try {
        computeBundleManifest(empty);
        fail("expected throw");
      } catch (e) {
        expect((e as PolicyBundleError).code).toBe(
          PolicyBundleErrorCode.EmptyBundle
        );
      }
    });
  });

  // ---- canonicalizeManifest --------------------------------------------

  describe("canonicalizeManifest", () => {
    it("is stable regardless of file ordering", () => {
      const manifest = computeBundleManifest(policiesDir);
      const shuffled = {
        ...manifest,
        files: [...manifest.files].reverse(),
      };
      expect(canonicalizeManifest(shuffled)).toBe(
        canonicalizeManifest(manifest)
      );
    });
  });

  // ---- happy path -------------------------------------------------------

  it("verifies a bundle signed by a trusted signer", () => {
    writeSignedManifest();
    const result = makeVerifier().verify();

    expect(result.verified).toBe(true);
    expect(result.signer).toBe(signer.publicKey());
    expect(result.errors).toHaveLength(0);
    expect(result.drift).toBeUndefined();
    expect(result.bundleDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(telemetry).toHaveBeenCalledWith(
      expect.objectContaining({ level: "info", code: "POLICY_BUNDLE_VERIFIED" })
    );
  });

  it("reads signature and signers from the environment", () => {
    writeSignedManifest();
    process.env.POLICY_BUNDLE_SIGNATURE = currentSignature();
    process.env.POLICY_BUNDLE_SIGNERS = `  ,${signer.publicKey()}, `;
    try {
      const verifier = new PolicyBundleVerifier({ policiesDir, telemetry });
      expect(verifier.isConfigured()).toBe(true);
      expect(verifier.verify().verified).toBe(true);
    } finally {
      delete process.env.POLICY_BUNDLE_SIGNATURE;
      delete process.env.POLICY_BUNDLE_SIGNERS;
    }
  });

  it("reports not-configured when signature or signers are absent", () => {
    writeSignedManifest();
    const verifier = new PolicyBundleVerifier({
      policiesDir,
      signature: undefined,
      trustedSigners: [],
      telemetry,
    });
    expect(verifier.isConfigured()).toBe(false);
  });

  // ---- adversarial: bundle tampering -----------------------------------

  describe("bundle tampering", () => {
    it("detects a modified policy file", () => {
      writeSignedManifest();
      const signature = currentSignature(); // signature over the ORIGINAL bundle
      writePolicy("a.rego", "package a\ndeny := true # sneaky change\n");

      const result = makeVerifier({ signature }).verify();

      expect(result.verified).toBe(false);
      expect(result.drift?.modified).toContain("a.rego");
      expectError(result, PolicyBundleErrorCode.BundleTampered);
      expect(telemetry).toHaveBeenCalledWith(
        expect.objectContaining({
          level: "critical",
          code: PolicyBundleErrorCode.BundleTampered,
        })
      );
    });

    it("detects an added policy file", () => {
      writeSignedManifest();
      const signature = currentSignature();
      writePolicy("evil.rego", "package evil\n");

      const result = makeVerifier({ signature }).verify();

      expect(result.verified).toBe(false);
      expect(result.drift?.added).toContain("evil.rego");
      expectError(result, PolicyBundleErrorCode.BundleTampered);
    });

    it("detects a removed policy file", () => {
      writeSignedManifest();
      const signature = currentSignature();
      fs.rmSync(path.join(policiesDir, "b.rego"));

      const result = makeVerifier({ signature }).verify();

      expect(result.verified).toBe(false);
      expect(result.drift?.removed).toContain("b.rego");
      expectError(result, PolicyBundleErrorCode.BundleTampered);
    });
  });

  // ---- adversarial: signature forgery ----------------------------------

  describe("signature forgery", () => {
    it("rejects a signature from an untrusted key", () => {
      writeSignedManifest();
      const attacker = Keypair.random();
      const forged = signBundleManifest(
        computeBundleManifest(policiesDir),
        attacker
      );

      const result = makeVerifier({ signature: forged }).verify();

      expect(result.verified).toBe(false);
      expect(result.signer).toBeUndefined();
      expectError(result, PolicyBundleErrorCode.SignatureInvalid);
    });

    it("rejects a valid signature over a DIFFERENT manifest", () => {
      writeSignedManifest();
      // Attacker edits the committed manifest to match their tampered bundle
      // and re-hashes it, but cannot sign it with the trusted key.
      writePolicy("a.rego", "package a\ndeny := true\n");
      writeSignedManifest();
      const attacker = Keypair.random();
      const forged = signBundleManifest(
        computeBundleManifest(policiesDir),
        attacker
      );

      const result = makeVerifier({ signature: forged }).verify();

      expect(result.verified).toBe(false);
      expectError(result, PolicyBundleErrorCode.SignatureInvalid);
    });

    it("rejects a malformed (non-hex) signature", () => {
      writeSignedManifest();
      const result = makeVerifier({ signature: "zzzz-not-hex" }).verify();
      expect(result.verified).toBe(false);
      expectError(result, PolicyBundleErrorCode.SignatureMalformed);
    });

    it("rejects an odd-length signature", () => {
      writeSignedManifest();
      const result = makeVerifier({ signature: "abc" }).verify();
      expect(result.verified).toBe(false);
      expectError(result, PolicyBundleErrorCode.SignatureMalformed);
    });

    it("skips malformed trusted-signer keys and still rejects", () => {
      writeSignedManifest();
      const result = makeVerifier({
        trustedSigners: ["not-a-key", "GALSO_BAD"],
      }).verify();
      expect(result.verified).toBe(false);
      expectError(result, PolicyBundleErrorCode.SignatureInvalid);
    });
  });

  // ---- configuration failures ------------------------------------------

  describe("configuration failures", () => {
    it("reports ManifestMissing when no signed manifest exists", () => {
      const result = makeVerifier().verify();
      expect(result.verified).toBe(false);
      expectError(result, PolicyBundleErrorCode.ManifestMissing);
    });

    it("reports SignatureMissing when no signature is configured", () => {
      writeSignedManifest();
      const result = makeVerifier({ signature: undefined }).verify();
      expect(result.verified).toBe(false);
      expectError(result, PolicyBundleErrorCode.SignatureMissing);
    });

    it("reports NoTrustedSigners when the signer set is empty", () => {
      writeSignedManifest();
      const result = makeVerifier({ trustedSigners: [] }).verify();
      expect(result.verified).toBe(false);
      expectError(result, PolicyBundleErrorCode.NoTrustedSigners);
    });

    it("reports EmptyBundle and short-circuits when the bundle has no policies", () => {
      // Capture a valid signature BEFORE emptying the bundle.
      writeSignedManifest();
      const signature = currentSignature();
      fs.rmSync(path.join(policiesDir, "a.rego"));
      fs.rmSync(path.join(policiesDir, "b.rego"));
      const result = new PolicyBundleVerifier({
        policiesDir,
        signature,
        trustedSigners: [signer.publicKey()],
        telemetry,
      }).verify();
      expect(result.verified).toBe(false);
      expect(result.bundleDigest).toBe("");
      expectError(result, PolicyBundleErrorCode.EmptyBundle);
    });
  });

  // ---- adversarial: malformed manifests --------------------------------

  describe("malformed signed manifest", () => {
    const writeRawManifest = (raw: string): void => {
      fs.writeFileSync(path.join(policiesDir, MANIFEST_FILENAME), raw);
    };

    it("reports ManifestMalformed on invalid JSON", () => {
      writeRawManifest("{ not json");
      const result = makeVerifier().verify();
      expect(result.verified).toBe(false);
      expectError(result, PolicyBundleErrorCode.ManifestMalformed);
    });

    it("reports ManifestMalformed on a structurally invalid manifest", () => {
      writeRawManifest(JSON.stringify({ version: 2, files: [] }));
      const result = makeVerifier().verify();
      expect(result.verified).toBe(false);
      expectError(result, PolicyBundleErrorCode.ManifestMalformed);
    });

    it("reports ManifestMalformed on a bad file entry", () => {
      writeRawManifest(
        JSON.stringify({
          version: 1,
          algorithm: "sha256",
          files: [{ path: "a.rego" }],
          bundle_digest: "deadbeef",
        })
      );
      const result = makeVerifier().verify();
      expect(result.verified).toBe(false);
      expectError(result, PolicyBundleErrorCode.ManifestMalformed);
    });
  });

  // ---- telemetry --------------------------------------------------------

  describe("telemetry", () => {
    it("emits a critical event for tampering and does not throw", () => {
      writeSignedManifest();
      const signature = currentSignature();
      writePolicy("a.rego", "tampered");
      const events: Array<Parameters<TelemetrySink>[0]> = [];
      const verifier = makeVerifier({
        signature,
        telemetry: (e) => events.push(e),
      });
      expect(() => verifier.verify()).not.toThrow();
      expect(events.some((e) => e.level === "critical")).toBe(true);
    });

    it("falls back to the console sink by default", () => {
      writeSignedManifest();
      const errSpy = jest.spyOn(console, "error").mockImplementation(() => {});
      const logSpy = jest.spyOn(console, "log").mockImplementation(() => {});
      try {
        // Trigger a critical (tampered) path with the default console sink.
        const signature = currentSignature();
        writePolicy("a.rego", "tampered");
        new PolicyBundleVerifier({
          policiesDir,
          signature,
          trustedSigners: [signer.publicKey()],
        }).verify();
        expect(errSpy).toHaveBeenCalled();
      } finally {
        errSpy.mockRestore();
        logSpy.mockRestore();
      }
    });

    it("logs an info line on the default sink for a verified bundle", () => {
      writeSignedManifest();
      const logSpy = jest.spyOn(console, "log").mockImplementation(() => {});
      try {
        new PolicyBundleVerifier({
          policiesDir,
          signature: currentSignature(),
          trustedSigners: [signer.publicKey()],
        }).verify();
        expect(logSpy).toHaveBeenCalled();
      } finally {
        logSpy.mockRestore();
      }
    });
  });

  // ---- error type -------------------------------------------------------

  it("PolicyBundleError carries a stable code and is instanceof Error", () => {
    const err = new PolicyBundleError(
      PolicyBundleErrorCode.BundleTampered,
      "msg",
      "detail"
    );
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(PolicyBundleError);
    expect(err.code).toBe(PolicyBundleErrorCode.BundleTampered);
    expect(err.detail).toBe("detail");
    expect(err.name).toBe("PolicyBundleError");
  });
});

/** Assert that a verification result contains an error with the given code. */
function expectError(
  result: PolicyBundleVerificationResult,
  code: PolicyBundleErrorCode
): void {
  expect(result.errors.map((e) => e.code)).toContain(code);
}
