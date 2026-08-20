/**
 * Tests for Relayer Signature Verification
 */

import PolicyEngine, { PRData } from "./policy-engine";
import { Keypair } from "@stellar/stellar-sdk";

describe("Relayer Signature Verification", () => {
  let engine: PolicyEngine;
  const authorizedRelayer = Keypair.random();
  const unauthorizedRelayer = Keypair.random();

  beforeEach(() => {
    engine = new PolicyEngine();
    process.env.AUTHORIZED_ADDRESSES = authorizedRelayer.publicKey();
  });

  afterEach(() => {
    delete process.env.AUTHORIZED_ADDRESSES;
  });

  function getBasePRData(): PRData {
    return {
      pull_request: {
        title: "Valid security feature PR title long enough",
        body: "This is a valid body with test mentioned.",
        labels: ["security"],
        base_branch: "develop",
        head_branch: "feature/test",
        number: 1,
        author: "test-user",
      },
      files_modified: ["src/test.ts"],
      additions: 10,
      deletions: 5,
    };
  }

  function signPRData(prData: PRData, keypair: Keypair, timestamp: number): PRData {
    // Exact same payload logic as in policy-engine.ts
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

  it("should fail if signature fields are missing", async () => {
    const prData = getBasePRData();
    const result = await engine.evaluate(prData);

    expect(result.status).toBe("NON_COMPLIANT");
    expect(result.violations.some(v => v.rule === "RELAYER_SIGNATURE_MISSING")).toBe(true);
  });

  it("should fail if relayer is not authorized", async () => {
    const timestamp = Date.now();
    const prData = signPRData(getBasePRData(), unauthorizedRelayer, timestamp);

    const result = await engine.evaluate(prData);

    expect(result.status).toBe("NON_COMPLIANT");
    expect(result.violations.some(v => v.rule === "RELAYER_UNAUTHORIZED")).toBe(true);
  });

  it("should fail if AUTHORIZED_ADDRESSES is not set", async () => {
    delete process.env.AUTHORIZED_ADDRESSES;
    const timestamp = Date.now();
    const prData = signPRData(getBasePRData(), authorizedRelayer, timestamp);

    const result = await engine.evaluate(prData);

    expect(result.status).toBe("NON_COMPLIANT");
    expect(result.violations.some(v => v.rule === "RELAYER_UNAUTHORIZED")).toBe(true);
    expect(result.violations.some(v => v.detail.includes("No authorized relayers configured"))).toBe(true);
  });

  it("should fail if signature is expired", async () => {
    const tenMinutesAgo = Date.now() - (10 * 60 * 1000);
    const prData = signPRData(getBasePRData(), authorizedRelayer, tenMinutesAgo);

    const result = await engine.evaluate(prData);

    expect(result.status).toBe("NON_COMPLIANT");
    expect(result.violations.some(v => v.rule === "RELAYER_SIGNATURE_EXPIRED")).toBe(true);
  });

  it("should fail if cryptographic signature is invalid", async () => {
    const timestamp = Date.now();
    const prData = signPRData(getBasePRData(), authorizedRelayer, timestamp);
    prData.signature = "abcd".repeat(16); // Invalid hex signature

    const result = await engine.evaluate(prData);

    expect(result.status).toBe("NON_COMPLIANT");
    expect(result.violations.some(v => v.rule === "RELAYER_SIGNATURE_INVALID")).toBe(true);
  });

  it("should pass with valid signature from authorized relayer", async () => {
    const timestamp = Date.now();
    const prData = signPRData(getBasePRData(), authorizedRelayer, timestamp);

    const result = await engine.evaluate(prData);

    // Check specifically for signature violations
    const sigViolations = result.violations.filter(v => v.rule.startsWith("RELAYER_SIGNATURE"));
    expect(sigViolations.length).toBe(0);

    // It might still be NON_COMPLIANT due to other rules (e.g. changelog),
    // but the signature check should pass.
  });
});
