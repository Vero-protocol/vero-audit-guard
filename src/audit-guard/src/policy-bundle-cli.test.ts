import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { Keypair } from "@stellar/stellar-sdk";

jest.setTimeout(60_000);

const PACKAGE_ROOT = path.resolve(__dirname, "..");
const SOURCE_POLICIES_DIR = path.join(PACKAGE_ROOT, "policies");
const TS_NODE_REGISTER = require.resolve("ts-node/register/transpile-only");

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

interface SignatureFixture {
  publicKey: string;
  signature: string;
}

function isolatedEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    NODE_ENV: "test",
    NODE_PATH: path.join(PACKAGE_ROOT, "node_modules"),
    TS_NODE_PROJECT: path.join(PACKAGE_ROOT, "tsconfig.json"),
    PATH: process.env.PATH,
    Path: process.env.Path,
    PATHEXT: process.env.PATHEXT,
    SystemRoot: process.env.SystemRoot,
    WINDIR: process.env.WINDIR,
    TEMP: process.env.TEMP,
    TMP: process.env.TMP,
    TMPDIR: process.env.TMPDIR,
    ...overrides,
  };

  return Object.fromEntries(
    Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined)
  );
}

describe("policy-bundle CLI entrypoint", () => {
  let tempDir: string;
  let tempCliPath: string;
  let tempPoliciesDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-guard-policy-bundle-cli-"));
    const tempSourceDir = path.join(tempDir, "src");
    tempPoliciesDir = path.join(tempDir, "policies");
    fs.mkdirSync(tempSourceDir, { recursive: true });
    fs.cpSync(SOURCE_POLICIES_DIR, tempPoliciesDir, { recursive: true });
    fs.copyFileSync(
      path.join(__dirname, "policy-bundle-cli.ts"),
      path.join(tempSourceDir, "policy-bundle-cli.ts")
    );
    fs.copyFileSync(
      path.join(__dirname, "policy-bundle-verifier.ts"),
      path.join(tempSourceDir, "policy-bundle-verifier.ts")
    );
    tempCliPath = path.join(tempSourceDir, "policy-bundle-cli.ts");
  });

  afterEach(() => {
    fs.rmSync(tempDir, { force: true, recursive: true });
  });

  function runCli(command: string, env: NodeJS.ProcessEnv = {}): CliResult {
    const result = spawnSync(
      process.execPath,
      ["-r", TS_NODE_REGISTER, tempCliPath, command],
      {
        cwd: tempDir,
        env: isolatedEnv(env),
        encoding: "utf8",
        maxBuffer: 1024 * 1024,
        shell: false,
        timeout: 20_000,
        windowsHide: true,
      }
    );

    if (result.error) {
      throw result.error;
    }

    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  }

  function regenerateAndSign(): SignatureFixture {
    const regenerateResult = runCli("regenerate");
    expect(regenerateResult.status).toBe(0);

    const keypair = Keypair.random();
    const signResult = runCli("sign", {
      POLICY_BUNDLE_SIGNING_SECRET: keypair.secret(),
    });
    expect(signResult.status).toBe(0);
    expect(signResult.stdout).not.toContain(keypair.secret());

    const signature = signResult.stdout.match(
      /^POLICY_BUNDLE_SIGNATURE=([0-9a-f]+)$/m
    )?.[1];
    const publicKey = signResult.stdout.match(/^signer_public_key=(G[A-Z0-9]+)$/m)?.[1];
    if (!signature || !publicKey) {
      throw new Error("Policy bundle sign output did not contain the expected credentials");
    }

    return { publicKey, signature };
  }

  it("regenerates a deterministic manifest in an isolated policy bundle", () => {
    const result = runCli("regenerate");
    const manifest = JSON.parse(
      fs.readFileSync(path.join(tempPoliciesDir, "bundle.manifest.json"), "utf8")
    ) as {
      algorithm: string;
      bundle_digest: string;
      files: unknown[];
      version: number;
    };

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Wrote manifest");
    expect(manifest).toMatchObject({ algorithm: "sha256", version: 1 });
    expect(manifest.bundle_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(manifest.files.length).toBeGreaterThan(0);
  });

  it("signs and verifies the isolated on-disk bundle", () => {
    const { publicKey, signature } = regenerateAndSign();

    const verifyResult = runCli("verify", {
      POLICY_BUNDLE_SIGNATURE: signature,
      POLICY_BUNDLE_SIGNERS: publicKey,
    });

    expect(verifyResult.status).toBe(0);
    expect(verifyResult.stdout).toContain('"verified": true');
    expect(verifyResult.stdout).toContain(`"signer": "${publicKey}"`);
  });

  it("fails verification after a signed policy bundle is modified", () => {
    const { publicKey, signature } = regenerateAndSign();
    fs.appendFileSync(
      path.join(tempPoliciesDir, "pr_compliance.rego"),
      "\n# CLI tamper-detection test\n",
      "utf8"
    );

    const verifyResult = runCli("verify", {
      POLICY_BUNDLE_SIGNATURE: signature,
      POLICY_BUNDLE_SIGNERS: publicKey,
    });

    expect(verifyResult.status).toBe(1);
    expect(verifyResult.stdout).toContain('"verified": false');
    expect(verifyResult.stdout).toContain("POLICY_BUNDLE_TAMPERED");
    expect(verifyResult.stdout).toContain('"modified": [');
    expect(verifyResult.stdout).toContain('"pr_compliance.rego"');
  });

  it("fails verification after a policy file is added", () => {
    const { publicKey, signature } = regenerateAndSign();
    fs.writeFileSync(
      path.join(tempPoliciesDir, "unexpected.rego"),
      "package unexpected\nallow := false\n",
      "utf8"
    );

    const verifyResult = runCli("verify", {
      POLICY_BUNDLE_SIGNATURE: signature,
      POLICY_BUNDLE_SIGNERS: publicKey,
    });

    expect(verifyResult.status).toBe(1);
    expect(verifyResult.stdout).toContain("POLICY_BUNDLE_TAMPERED");
    expect(verifyResult.stdout).toContain('"added": [');
    expect(verifyResult.stdout).toContain('"unexpected.rego"');
  });

  it("rejects verification when the detached signature is absent", () => {
    const regenerateResult = runCli("regenerate");
    expect(regenerateResult.status).toBe(0);

    const verifyResult = runCli("verify", {
      POLICY_BUNDLE_SIGNERS: Keypair.random().publicKey(),
    });

    expect(verifyResult.status).toBe(1);
    expect(verifyResult.stdout).toContain('"verified": false');
    expect(verifyResult.stdout).toContain("POLICY_BUNDLE_SIGNATURE_MISSING");
  });

  it("rejects a malformed detached signature", () => {
    const regenerateResult = runCli("regenerate");
    expect(regenerateResult.status).toBe(0);

    const verifyResult = runCli("verify", {
      POLICY_BUNDLE_SIGNATURE: "not-hex",
      POLICY_BUNDLE_SIGNERS: Keypair.random().publicKey(),
    });

    expect(verifyResult.status).toBe(1);
    expect(verifyResult.stdout).toContain("POLICY_BUNDLE_SIGNATURE_MALFORMED");
  });

  it("rejects signing when the offline signing secret is absent", () => {
    const regenerateResult = runCli("regenerate");
    expect(regenerateResult.status).toBe(0);

    const signResult = runCli("sign");

    expect(signResult.status).toBe(1);
    expect(signResult.stderr).toContain("POLICY_BUNDLE_SIGNING_SECRET is not set");
  });

  it("rejects an unknown command and prints usage", () => {
    const result = runCli("unknown-command");

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Usage: policy-bundle-cli <regenerate|sign|verify>");
  });
});
