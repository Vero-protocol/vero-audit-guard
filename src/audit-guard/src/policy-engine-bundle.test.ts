/**
 * Integration tests for PolicyEngine's opt-in policy-bundle signature check
 * (Issue #171 / VAG-003). Verifies the observational wiring: a tampered bundle
 * surfaces as a CRITICAL warning (not a hard violation), and the check is a
 * no-op when signing is not configured.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { Keypair } from "@stellar/stellar-sdk";
import PolicyEngine, { PRData } from "./policy-engine";
import {
  computeBundleManifest,
  signBundleManifest,
} from "./policy-bundle-verifier";

describe("PolicyEngine — policy bundle verification integration", () => {
  let tmpDir: string;
  let policiesDir: string;
  const relayer = Keypair.random();
  const signer = Keypair.random();

  const signPRData = (prData: PRData, timestamp: number): PRData => {
    const payload = JSON.stringify({
      pull_request: prData.pull_request,
      files_modified: prData.files_modified,
      additions: prData.additions,
      deletions: prData.deletions,
      dependencies_added: prData.dependencies_added,
      dependencies_updated: prData.dependencies_updated,
      relayer: relayer.publicKey(),
      timestamp,
    });
    return {
      ...prData,
      relayer: relayer.publicKey(),
      signature: relayer.sign(Buffer.from(payload)).toString("hex"),
      timestamp,
    };
  };

  const basePR = (): PRData =>
    signPRData(
      {
        pull_request: {
          title: "Valid compliant PR title that is long enough",
          body: "Detailed description with test and changelog mentioned.",
          labels: ["security", "trivial"],
          base_branch: "develop",
          head_branch: "feature/test",
          number: 1,
          author: "test-user",
        },
        files_modified: ["src/test.ts"],
        additions: 10,
        deletions: 5,
      },
      Date.now()
    );

  const writeSignedManifestAndSignature = (): void => {
    const manifest = computeBundleManifest(policiesDir);
    fs.writeFileSync(
      path.join(policiesDir, "bundle.manifest.json"),
      JSON.stringify(manifest, null, 2)
    );
    process.env.POLICY_BUNDLE_SIGNATURE = signBundleManifest(manifest, signer);
    process.env.POLICY_BUNDLE_SIGNERS = signer.publicKey();
  };

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vag-pe-bundle-"));
    policiesDir = path.join(tmpDir, "policies");
    fs.mkdirSync(policiesDir);
    fs.writeFileSync(
      path.join(policiesDir, "pr_compliance.rego"),
      "package pr.compliance\ndeny := false\n"
    );
    process.env.AUTHORIZED_ADDRESSES = relayer.publicKey();
  });

  afterEach(() => {
    delete process.env.AUTHORIZED_ADDRESSES;
    delete process.env.POLICY_BUNDLE_SIGNATURE;
    delete process.env.POLICY_BUNDLE_SIGNERS;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("is a no-op when bundle signing is not configured", async () => {
    const engine = new PolicyEngine(policiesDir);
    const result = await engine.evaluate(basePR());
    expect(
      result.warnings.some((w) => w.rule.startsWith("POLICY_BUNDLE_"))
    ).toBe(false);
  });

  it("adds no bundle warning when the signed bundle is intact", async () => {
    writeSignedManifestAndSignature();
    const engine = new PolicyEngine(policiesDir);
    const result = await engine.evaluate(basePR());
    expect(
      result.warnings.some((w) => w.rule.startsWith("POLICY_BUNDLE_"))
    ).toBe(false);
  });

  it("surfaces a CRITICAL warning when the bundle is tampered", async () => {
    writeSignedManifestAndSignature();
    // Tamper AFTER signing — as a compromised runner would.
    fs.writeFileSync(
      path.join(policiesDir, "pr_compliance.rego"),
      "package pr.compliance\ndeny := true # backdoor\n"
    );

    const engine = new PolicyEngine(policiesDir);
    const result = await engine.evaluate(basePR());

    const bundleWarning = result.warnings.find(
      (w) => w.rule === "POLICY_BUNDLE_TAMPERED"
    );
    expect(bundleWarning).toBeDefined();
    expect(bundleWarning?.severity).toBe("CRITICAL");
    // Observational-only: it is a warning, not a hard violation.
    expect(
      result.violations.some((v) => v.rule.startsWith("POLICY_BUNDLE_"))
    ).toBe(false);
  });
});
