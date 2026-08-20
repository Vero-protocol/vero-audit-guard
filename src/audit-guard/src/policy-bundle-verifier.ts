/**
 * Policy Bundle Signature Verification (Issue #171 / VAG-003)
 *
 * A second, independent control against a compromised CI runner silently
 * pushing an unauthorized policy change.
 *
 * PR review reduces — but does not eliminate — the risk that a compromised
 * runner alters the Rego policy bundle that `PolicyEngine` evaluates against.
 * This module recomputes a deterministic manifest of the on-disk policy
 * bundle and verifies it against a manifest that was signed **offline** by a
 * trusted maintainer key (Stellar Ed25519). A runner that has write access to
 * the checkout can edit a `.rego` file *and* the committed manifest, but it
 * cannot forge a signature without the maintainer's secret key — so tampering
 * becomes detectable.
 *
 * Authority context: observational / telemetry-only. `verify()` never throws
 * to halt a pipeline and has no on-chain halt authority; it returns a typed
 * result and surfaces failures as alerts (see {@link emitTelemetry}). Callers
 * decide what to do with the verdict.
 *
 * Error propagation follows the repo's `thiserror`-style discipline: every
 * failure mode is a typed {@link PolicyBundleError} with a stable
 * {@link PolicyBundleErrorCode}, never a bare panic/throw for control flow.
 */

import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { Keypair } from "@stellar/stellar-sdk";

/** Stable, machine-readable identifiers for every policy-bundle failure mode. */
export enum PolicyBundleErrorCode {
  /** The configured policies directory does not exist or is not a directory. */
  BundleDirNotFound = "POLICY_BUNDLE_DIR_NOT_FOUND",
  /** The policies directory contains no policy files to protect. */
  EmptyBundle = "POLICY_BUNDLE_EMPTY",
  /** No signed manifest was found to verify the live bundle against. */
  ManifestMissing = "POLICY_BUNDLE_MANIFEST_MISSING",
  /** The signed manifest exists but could not be parsed / is structurally invalid. */
  ManifestMalformed = "POLICY_BUNDLE_MANIFEST_MALFORMED",
  /** No detached signature was supplied for the signed manifest. */
  SignatureMissing = "POLICY_BUNDLE_SIGNATURE_MISSING",
  /** The signature is not valid hex / not a well-formed Ed25519 signature. */
  SignatureMalformed = "POLICY_BUNDLE_SIGNATURE_MALFORMED",
  /** No trusted signer public keys were configured. */
  NoTrustedSigners = "POLICY_BUNDLE_NO_TRUSTED_SIGNERS",
  /** The signature is cryptographically valid but not from a trusted signer. */
  UntrustedSigner = "POLICY_BUNDLE_UNTRUSTED_SIGNER",
  /** The signature did not verify against any trusted signer. */
  SignatureInvalid = "POLICY_BUNDLE_SIGNATURE_INVALID",
  /** The on-disk bundle drifted from the signed manifest (add/remove/modify). */
  BundleTampered = "POLICY_BUNDLE_TAMPERED",
}

/**
 * Typed error for a single policy-bundle failure mode. Analogous to a
 * `thiserror` enum variant on the Rust side of the codebase: it carries a
 * stable {@link code} for programmatic handling plus human-readable context.
 */
export class PolicyBundleError extends Error {
  public readonly code: PolicyBundleErrorCode;
  public readonly detail?: string;

  constructor(code: PolicyBundleErrorCode, message: string, detail?: string) {
    super(message);
    this.name = "PolicyBundleError";
    this.code = code;
    this.detail = detail;
    // Restore prototype chain for `instanceof` under transpiled targets.
    Object.setPrototypeOf(this, PolicyBundleError.prototype);
  }
}

/** One file's contribution to the bundle manifest. */
export interface PolicyBundleFileEntry {
  /** POSIX-style path relative to the policies directory. */
  path: string;
  /** Lowercase hex SHA-256 of the file's raw bytes. */
  sha256: string;
  /** File size in bytes. */
  bytes: number;
}

/** A deterministic, signable description of a policy bundle's contents. */
export interface PolicyBundleManifest {
  /** Manifest schema version. */
  version: 1;
  /** Hash algorithm used for per-file and aggregate digests. */
  algorithm: "sha256";
  /** File entries, always sorted by `path`. */
  files: PolicyBundleFileEntry[];
  /** SHA-256 over the canonical serialization of `files`. */
  bundle_digest: string;
}

/** Files that differ between the live bundle and the signed manifest. */
export interface PolicyBundleDrift {
  added: string[];
  removed: string[];
  modified: string[];
}

/** Outcome of a (non-throwing) bundle verification. */
export interface PolicyBundleVerificationResult {
  /** True only when the live bundle matches a manifest signed by a trusted key. */
  verified: boolean;
  /** Digest of the live, on-disk bundle. */
  bundleDigest: string;
  /** Public key of the trusted signer whose signature verified, if any. */
  signer?: string;
  /** Typed, non-throwing errors describing why verification failed. */
  errors: PolicyBundleError[];
  /** Populated when the live bundle drifted from the signed manifest. */
  drift?: PolicyBundleDrift;
  /** ISO-8601 timestamp of when verification ran. */
  checkedAt: string;
}

/** Sink for verification telemetry. Injectable so failures are testable. */
export type TelemetrySink = (event: {
  level: "info" | "warn" | "critical";
  code: string;
  message: string;
  detail?: string;
}) => void;

export interface PolicyBundleVerifierOptions {
  /** Directory holding the `.rego` policy bundle. */
  policiesDir?: string;
  /** Path to the committed, signed manifest JSON. */
  manifestPath?: string;
  /** Detached hex Ed25519 signature over the canonical signed manifest. */
  signature?: string;
  /** Trusted signer public keys (Stellar `G...` addresses). */
  trustedSigners?: string[];
  /** File extensions that constitute the bundle (default: `.rego`). */
  extensions?: string[];
  /** Telemetry sink; defaults to `console`. */
  telemetry?: TelemetrySink;
}

const DEFAULT_EXTENSIONS = [".rego"];
const DEFAULT_MANIFEST_FILENAME = "bundle.manifest.json";

/**
 * Recursively collect bundle files under `dir`, returning paths relative to
 * `dir` using POSIX separators, sorted deterministically.
 */
function collectBundleFiles(dir: string, extensions: string[]): string[] {
  const out: string[] = [];
  const walk = (current: string): void => {
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const abs = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(abs);
      } else if (
        entry.isFile() &&
        extensions.some((ext) => entry.name.toLowerCase().endsWith(ext))
      ) {
        const rel = path.relative(dir, abs).split(path.sep).join("/");
        out.push(rel);
      }
    }
  };
  walk(dir);
  return out.sort();
}

function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Canonical serialization of a manifest for signing/verification. Object keys
 * are emitted in a fixed order and file entries are sorted by path, so the
 * bytes are stable regardless of filesystem ordering or JSON key ordering.
 */
export function canonicalizeManifest(manifest: PolicyBundleManifest): string {
  const files = [...manifest.files]
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
    .map((f) => ({ path: f.path, sha256: f.sha256, bytes: f.bytes }));
  return JSON.stringify({
    version: manifest.version,
    algorithm: manifest.algorithm,
    files,
    bundle_digest: manifest.bundle_digest,
  });
}

/**
 * Compute a deterministic manifest for the policy bundle at `policiesDir`.
 *
 * @throws {PolicyBundleError} `BundleDirNotFound` if the directory is missing,
 *   `EmptyBundle` if no policy files are present.
 */
export function computeBundleManifest(
  policiesDir: string,
  extensions: string[] = DEFAULT_EXTENSIONS
): PolicyBundleManifest {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(policiesDir);
  } catch {
    throw new PolicyBundleError(
      PolicyBundleErrorCode.BundleDirNotFound,
      "Policy bundle directory not found",
      policiesDir
    );
  }
  if (!stat.isDirectory()) {
    throw new PolicyBundleError(
      PolicyBundleErrorCode.BundleDirNotFound,
      "Policy bundle path is not a directory",
      policiesDir
    );
  }

  const relPaths = collectBundleFiles(policiesDir, extensions);
  if (relPaths.length === 0) {
    throw new PolicyBundleError(
      PolicyBundleErrorCode.EmptyBundle,
      "Policy bundle contains no policy files",
      `No ${extensions.join("/")} files under ${policiesDir}`
    );
  }

  const files: PolicyBundleFileEntry[] = relPaths.map((rel) => {
    const contents = fs.readFileSync(path.join(policiesDir, rel));
    return { path: rel, sha256: sha256Hex(contents), bytes: contents.length };
  });

  // Aggregate digest over the canonical file list (excluding bundle_digest).
  const digestBasis = JSON.stringify(
    files.map((f) => ({ path: f.path, sha256: f.sha256, bytes: f.bytes }))
  );
  const bundle_digest = sha256Hex(digestBasis);

  return { version: 1, algorithm: "sha256", files, bundle_digest };
}

/**
 * Sign a manifest with a maintainer keypair, returning the detached hex
 * signature over the canonical manifest bytes. Intended for offline tooling
 * and tests — production signing happens on an air-gapped/maintainer machine.
 */
export function signBundleManifest(
  manifest: PolicyBundleManifest,
  keypair: Keypair
): string {
  const payload = Buffer.from(canonicalizeManifest(manifest), "utf-8");
  return keypair.sign(payload).toString("hex");
}

/** Compare a live manifest against a signed manifest, returning any drift. */
function diffManifests(
  live: PolicyBundleManifest,
  signed: PolicyBundleManifest
): PolicyBundleDrift {
  const liveMap = new Map(live.files.map((f) => [f.path, f.sha256]));
  const signedMap = new Map(signed.files.map((f) => [f.path, f.sha256]));

  const added: string[] = [];
  const modified: string[] = [];
  for (const [p, hash] of liveMap) {
    if (!signedMap.has(p)) {
      added.push(p);
    } else if (signedMap.get(p) !== hash) {
      modified.push(p);
    }
  }
  const removed: string[] = [];
  for (const p of signedMap.keys()) {
    if (!liveMap.has(p)) {
      removed.push(p);
    }
  }
  return {
    added: added.sort(),
    removed: removed.sort(),
    modified: modified.sort(),
  };
}

function parseSignedManifest(raw: string): PolicyBundleManifest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new PolicyBundleError(
      PolicyBundleErrorCode.ManifestMalformed,
      "Signed manifest is not valid JSON",
      (e as Error).message
    );
  }
  const m = parsed as Partial<PolicyBundleManifest>;
  if (
    !m ||
    m.version !== 1 ||
    m.algorithm !== "sha256" ||
    !Array.isArray(m.files) ||
    typeof m.bundle_digest !== "string"
  ) {
    throw new PolicyBundleError(
      PolicyBundleErrorCode.ManifestMalformed,
      "Signed manifest is structurally invalid",
      "Expected {version:1, algorithm:'sha256', files:[], bundle_digest}"
    );
  }
  for (const f of m.files) {
    if (
      !f ||
      typeof f.path !== "string" ||
      typeof f.sha256 !== "string" ||
      typeof f.bytes !== "number"
    ) {
      throw new PolicyBundleError(
        PolicyBundleErrorCode.ManifestMalformed,
        "Signed manifest has a malformed file entry",
        JSON.stringify(f)
      );
    }
  }
  return m as PolicyBundleManifest;
}

/**
 * Verifies that a policy bundle on disk matches a manifest signed by a trusted
 * maintainer key. All failures are collected as typed errors — the verifier is
 * observational and never throws for an expected verification failure.
 */
export class PolicyBundleVerifier {
  private readonly policiesDir: string;
  private readonly manifestPath: string;
  private readonly signature?: string;
  private readonly trustedSigners: string[];
  private readonly extensions: string[];
  private readonly telemetry: TelemetrySink;

  constructor(options: PolicyBundleVerifierOptions = {}) {
    this.policiesDir =
      options.policiesDir || path.join(__dirname, "..", "policies");
    this.manifestPath =
      options.manifestPath ||
      path.join(this.policiesDir, DEFAULT_MANIFEST_FILENAME);
    this.signature =
      options.signature ?? process.env.POLICY_BUNDLE_SIGNATURE ?? undefined;
    this.trustedSigners =
      options.trustedSigners ??
      (process.env.POLICY_BUNDLE_SIGNERS || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    this.extensions = options.extensions ?? DEFAULT_EXTENSIONS;
    this.telemetry = options.telemetry ?? defaultTelemetrySink;
  }

  /**
   * True when a signature and at least one trusted signer are configured, i.e.
   * the operator has opted this repo into bundle-signature enforcement. When
   * false, callers should treat verification as "not configured" rather than a
   * hard failure, preserving the observational-only invariant.
   */
  isConfigured(): boolean {
    return Boolean(this.signature) && this.trustedSigners.length > 0;
  }

  /**
   * Verify the live bundle against the signed manifest. Never throws for an
   * expected verification failure; unexpected I/O errors from manifest reading
   * are captured as typed errors too.
   */
  verify(): PolicyBundleVerificationResult {
    const errors: PolicyBundleError[] = [];
    const checkedAt = new Date().toISOString();

    // 1. Compute the live manifest. A missing/empty bundle is itself a failure.
    let live: PolicyBundleManifest;
    try {
      live = computeBundleManifest(this.policiesDir, this.extensions);
    } catch (e) {
      const err = asPolicyBundleError(e);
      return {
        verified: false,
        bundleDigest: "",
        errors: [err],
        checkedAt,
      };
    }
    const bundleDigest = live.bundle_digest;

    // 2. Load and parse the signed manifest.
    let signed: PolicyBundleManifest | undefined;
    if (!fs.existsSync(this.manifestPath)) {
      errors.push(
        new PolicyBundleError(
          PolicyBundleErrorCode.ManifestMissing,
          "No signed policy-bundle manifest found",
          this.manifestPath
        )
      );
    } else {
      try {
        signed = parseSignedManifest(
          fs.readFileSync(this.manifestPath, "utf-8")
        );
      } catch (e) {
        errors.push(asPolicyBundleError(e));
      }
    }

    // 3. Detect drift between live bundle and signed manifest.
    let drift: PolicyBundleDrift | undefined;
    if (signed) {
      drift = diffManifests(live, signed);
      if (drift.added.length || drift.removed.length || drift.modified.length) {
        errors.push(
          new PolicyBundleError(
            PolicyBundleErrorCode.BundleTampered,
            "Live policy bundle does not match the signed manifest",
            `added=[${drift.added.join(", ")}] removed=[${drift.removed.join(
              ", "
            )}] modified=[${drift.modified.join(", ")}]`
          )
        );
      } else {
        drift = undefined;
      }
    }

    // 4. Verify the detached signature over the signed manifest.
    const signer = signed
      ? this.verifySignature(signed, errors)
      : undefined;

    const verified =
      errors.length === 0 && Boolean(signer) && Boolean(signed);

    const result: PolicyBundleVerificationResult = {
      verified,
      bundleDigest,
      signer,
      errors,
      drift,
      checkedAt,
    };
    this.emitTelemetry(result);
    return result;
  }

  /**
   * Verify the detached signature against the trusted signer set. Pushes typed
   * errors and returns the matching signer's public key, or undefined.
   */
  private verifySignature(
    signed: PolicyBundleManifest,
    errors: PolicyBundleError[]
  ): string | undefined {
    if (!this.signature) {
      errors.push(
        new PolicyBundleError(
          PolicyBundleErrorCode.SignatureMissing,
          "No detached signature configured for the policy bundle",
          "Set POLICY_BUNDLE_SIGNATURE or pass options.signature"
        )
      );
      return undefined;
    }
    if (this.trustedSigners.length === 0) {
      errors.push(
        new PolicyBundleError(
          PolicyBundleErrorCode.NoTrustedSigners,
          "No trusted signers configured for the policy bundle",
          "Set POLICY_BUNDLE_SIGNERS or pass options.trustedSigners"
        )
      );
      return undefined;
    }

    let sigBytes: Buffer;
    try {
      sigBytes = hexToBuffer(this.signature);
    } catch (e) {
      errors.push(
        new PolicyBundleError(
          PolicyBundleErrorCode.SignatureMalformed,
          "Policy-bundle signature is not valid hex",
          (e as Error).message
        )
      );
      return undefined;
    }

    const payload = Buffer.from(canonicalizeManifest(signed), "utf-8");
    for (const pub of this.trustedSigners) {
      try {
        const keypair = Keypair.fromPublicKey(pub);
        if (keypair.verify(payload, sigBytes)) {
          return pub;
        }
      } catch {
        // Malformed trusted-signer key: skip it, try the rest.
        continue;
      }
    }

    errors.push(
      new PolicyBundleError(
        PolicyBundleErrorCode.SignatureInvalid,
        "Policy-bundle signature did not verify against any trusted signer",
        `signers=${this.trustedSigners.length}`
      )
    );
    return undefined;
  }

  /** Surface the verdict as telemetry so failures alert rather than drop silently. */
  emitTelemetry(result: PolicyBundleVerificationResult): void {
    if (result.verified) {
      this.telemetry({
        level: "info",
        code: "POLICY_BUNDLE_VERIFIED",
        message: `Policy bundle verified (signer ${result.signer})`,
        detail: `digest=${result.bundleDigest}`,
      });
      return;
    }
    for (const err of result.errors) {
      const level =
        err.code === PolicyBundleErrorCode.BundleTampered ||
        err.code === PolicyBundleErrorCode.SignatureInvalid ||
        err.code === PolicyBundleErrorCode.UntrustedSigner
          ? "critical"
          : "warn";
      this.telemetry({
        level,
        code: err.code,
        message: err.message,
        detail: err.detail,
      });
    }
  }
}

/** Convert a hex string to a Buffer, rejecting non-hex / odd-length input. */
function hexToBuffer(hex: string): Buffer {
  const normalized = hex.trim().toLowerCase();
  if (normalized.length === 0 || normalized.length % 2 !== 0) {
    throw new Error("signature hex has invalid length");
  }
  if (!/^[0-9a-f]+$/.test(normalized)) {
    throw new Error("signature contains non-hex characters");
  }
  return Buffer.from(normalized, "hex");
}

/** Narrow an unknown thrown value to a PolicyBundleError. */
function asPolicyBundleError(e: unknown): PolicyBundleError {
  if (e instanceof PolicyBundleError) {
    return e;
  }
  return new PolicyBundleError(
    PolicyBundleErrorCode.ManifestMalformed,
    "Unexpected error during policy-bundle verification",
    (e as Error)?.message
  );
}

/** Default telemetry sink: structured console output at the right level. */
const defaultTelemetrySink: TelemetrySink = (event) => {
  const line = `[PolicyBundleVerifier] ${event.code}: ${event.message}${
    event.detail ? ` (${event.detail})` : ""
  }`;
  if (event.level === "critical") {
    console.error(line);
  } else if (event.level === "warn") {
    console.warn(line);
  } else {
    console.log(line);
  }
};

export default PolicyBundleVerifier;
