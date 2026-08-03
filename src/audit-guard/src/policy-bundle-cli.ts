#!/usr/bin/env ts-node
/**
 * Policy Bundle signing CLI (Issue #171 / VAG-003).
 *
 * Maintainer-facing, offline tooling for the second, independent control that
 * protects the Rego policy bundle from a compromised CI runner.
 *
 *   Regenerate the committed manifest after an intentional policy change:
 *     npm run policy-bundle -- regenerate
 *
 *   Produce a detached signature for the current manifest (run on a trusted
 *   machine; the secret is read from the environment, never the argv/history):
 *     POLICY_BUNDLE_SIGNING_SECRET=S... npm run policy-bundle -- sign
 *
 *   Verify the on-disk bundle against the committed manifest + signature:
 *     POLICY_BUNDLE_SIGNATURE=... POLICY_BUNDLE_SIGNERS=G... \
 *       npm run policy-bundle -- verify
 *
 * The resulting `POLICY_BUNDLE_SIGNATURE` (signature) and `POLICY_BUNDLE_SIGNERS`
 * (trusted public keys) are configured as CI variables/secrets so the pipeline
 * can independently verify that policies were not tampered with.
 */

import * as fs from "fs";
import * as path from "path";
import { Keypair } from "@stellar/stellar-sdk";
import {
  PolicyBundleVerifier,
  computeBundleManifest,
  signBundleManifest,
} from "./policy-bundle-verifier";

const POLICIES_DIR = path.join(__dirname, "..", "policies");
const MANIFEST_PATH = path.join(POLICIES_DIR, "bundle.manifest.json");

function regenerate(): void {
  const manifest = computeBundleManifest(POLICIES_DIR);
  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + "\n");
  console.log(
    `✅ Wrote manifest for ${manifest.files.length} file(s): ${MANIFEST_PATH}`
  );
  console.log(`   bundle_digest=${manifest.bundle_digest}`);
  console.log(
    "   Next: sign it on a trusted machine and set POLICY_BUNDLE_SIGNATURE."
  );
}

function sign(): void {
  const secret = process.env.POLICY_BUNDLE_SIGNING_SECRET;
  if (!secret) {
    console.error(
      "❌ POLICY_BUNDLE_SIGNING_SECRET is not set. Provide a Stellar secret (S...)."
    );
    process.exit(1);
    return;
  }
  const keypair = Keypair.fromSecret(secret.trim());
  const manifest = computeBundleManifest(POLICIES_DIR);
  const signature = signBundleManifest(manifest, keypair);
  console.log(`bundle_digest=${manifest.bundle_digest}`);
  console.log(`signer_public_key=${keypair.publicKey()}`);
  console.log(`POLICY_BUNDLE_SIGNATURE=${signature}`);
}

function verify(): void {
  const result = new PolicyBundleVerifier({
    policiesDir: POLICIES_DIR,
  }).verify();
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.verified ? 0 : 1);
}

function main(): void {
  const command = process.argv[2];
  switch (command) {
    case "regenerate":
      regenerate();
      break;
    case "sign":
      sign();
      break;
    case "verify":
      verify();
      break;
    default:
      console.error(
        "Usage: policy-bundle-cli <regenerate|sign|verify>\n" +
          "  regenerate  Recompute and write policies/bundle.manifest.json\n" +
          "  sign        Print a detached signature (needs POLICY_BUNDLE_SIGNING_SECRET)\n" +
          "  verify      Verify the on-disk bundle against the signed manifest"
      );
      process.exit(1);
  }
}

if (require.main === module) {
  main();
}
