/**
 * Tests for RelayerTxScanner
 *
 * Issue #25: feat: relayer unauthorized tx scan
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import RelayerTxScanner, {
  RELAYER_RULES,
  TxData,
} from "./relayer-scanner";

const ALICE = "alice-relayer-signer-1";
const BOB = "bob-relayer-signer-2";
const CAROL = "carol-relayer-signer-3";
const EVE = "eve-foreign-signer";
const TRUSTED = "trusted-relayer-signer";

function makeTx(overrides: Partial<TxData> = {}): TxData {
  return {
    sourceAccount: `${ALICE}.source`,
    sequence: "1",
    signers: [],
    operations: [{ type: "payment" }],
    txHash: "deadbeef",
    ...overrides,
  };
}

describe("RelayerTxScanner", () => {
  describe("constructor / configuration loading", () => {
    it("should normalise signer addresses to lowercase", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE.toUpperCase()],
        denylist: [],
      });
      const result = scanner.scan(makeTx({ sourceAccount: ALICE, signers: [ALICE.toUpperCase()] }));
      expect(result.status).toBe("AUTHORIZED");
    });

    it("should throw when config path does not exist", () => {
      expect(() =>
        RelayerTxScanner.fromConfigFile("/does/not/exist/relayer.config.json")
      ).toThrow(/Relayer config file not found/);
    });

    it("should reject multisigThreshold less than 1", () => {
      expect(
        () =>
          new RelayerTxScanner({
            authorizedSigners: [ALICE],
            denylist: [],
            multisigThreshold: 0,
          })
      ).toThrow(/multisigThreshold must be a positive integer/);
    });

    it("should load config from a JSON file", () => {
      const tmp = path.join(os.tmpdir(), `relayer-config-${Date.now()}.json`);
      fs.writeFileSync(
        tmp,
        JSON.stringify({
          authorizedSigners: [ALICE, BOB],
          denylist: [EVE],
          multisigThreshold: 2,
        })
      );
      try {
        const scanner = RelayerTxScanner.fromConfigFile(tmp, false);
        expect(scanner.authorizedSigners).toContain(ALICE);
        expect(scanner.denylistSigners).toContain(EVE);
      } finally {
        fs.unlinkSync(tmp);
      }
    });

    it("should throw on malformed JSON config", () => {
      const tmp = path.join(os.tmpdir(), `relayer-bad-${Date.now()}.json`);
      fs.writeFileSync(tmp, "{this is not json}");
      try {
        expect(() => RelayerTxScanner.fromConfigFile(tmp, false)).toThrow(/Failed to parse/);
      } finally {
        fs.unlinkSync(tmp);
      }
    });
  });

  describe("AUTHORIZED transactions", () => {
    it("should authorize when all signers are whitelisted", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE, BOB],
        denylist: [],
      });
      const result = scanner.scan(makeTx({ signers: [ALICE, BOB] }));
      expect(result.status).toBe("AUTHORIZED");
      expect(result.violations).toHaveLength(0);
      expect(result.warnings).toHaveLength(0);
      expect(result.unauthorizedSigners).toEqual([]);
      expect(result.denylistedSigners).toEqual([]);
      expect(result.authorizedSignerCount).toBe(2);
    });
  });

  describe("UNAUTHORIZED — foreign signer detection", () => {
    it("should flag a single unauthorized foreign signer", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE],
        denylist: [],
      });
      const result = scanner.scan(makeTx({ signers: [ALICE, EVE] }));
      expect(result.status).toBe("UNAUTHORIZED");
      const viol = result.violations.find(
        (v) => v.rule === RELAYER_RULES.UNAUTHORIZED_SIGNER
      );
      expect(viol).toBeDefined();
      expect(viol!.severity).toBe("HIGH");
      expect(result.unauthorizedSigners).toContain(EVE);
    });

    it("should flag multiple unauthorized signers", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE],
        denylist: [],
      });
      const result = scanner.scan(makeTx({ signers: [BOB, CAROL, EVE] }));
      expect(result.status).toBe("UNAUTHORIZED");
      expect(result.unauthorizedSigners).toHaveLength(3);
      expect(result.unauthorizedSigners).toEqual(
        expect.arrayContaining([BOB, CAROL, EVE])
      );
    });
  });

  describe("UNAUTHORIZED — denylist", () => {
    it("should emit a CRITICAL violation for any denylisted signer", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE, BOB],
        denylist: [EVE],
      });
      const result = scanner.scan(makeTx({ signers: [ALICE, EVE] }));
      expect(result.status).toBe("UNAUTHORIZED");
      const viol = result.violations.find(
        (v) => v.rule === RELAYER_RULES.DENYLISTED_SIGNER
      );
      expect(viol).toBeDefined();
      expect(viol!.severity).toBe("CRITICAL");
      expect(result.denylistedSigners).toContain(EVE);
    });

    it("should still flag foreign signers in addition to denylisted signers", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE],
        denylist: [EVE],
      });
      const result = scanner.scan(
        makeTx({ signers: [ALICE, EVE, CAROL] })
      );
      expect(result.denylistedSigners).toContain(EVE);
      expect(result.unauthorizedSigners).toContain(CAROL);
    });
  });

  describe("Multi-sig threshold", () => {
    it("should emit WARNING when threshold not met but TX is otherwise clean", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE, BOB, CAROL],
        denylist: [],
        multisigThreshold: 2,
      });
      const result = scanner.scan(makeTx({ signers: [ALICE] }));
      expect(result.status).toBe("REQUIRES_REVIEW");
      const warn = result.warnings.find(
        (w) => w.rule === RELAYER_RULES.MULTISIG_THRESHOLD_NOT_MET
      );
      expect(warn).toBeDefined();
      expect(warn!.severity).toBe("MEDIUM");
    });

    it("should AUTHORIZE when threshold is met exactly", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE, BOB, CAROL],
        denylist: [],
        multisigThreshold: 2,
      });
      const result = scanner.scan(makeTx({ signers: [ALICE, BOB] }));
      expect(result.status).toBe("AUTHORIZED");
    });

    it("should escalate threshold miss to VIOLATION when combined with a foreign signer", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE, BOB],
        denylist: [],
        multisigThreshold: 3,
      });
      const result = scanner.scan(makeTx({ signers: [ALICE, EVE] }));
      expect(result.status).toBe("UNAUTHORIZED");
      const viol = result.violations.find(
        (v) => v.rule === RELAYER_RULES.MULTISIG_THRESHOLD_NOT_MET
      );
      expect(viol).toBeDefined();
      expect(viol!.severity).toBe("HIGH");
    });
  });

  describe("Source account trusted-list", () => {
    it("should WARN when sourceAccount is not in the trusted-list", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE],
        denylist: [],
        sourceAccounts: [TRUSTED],
      });
      const result = scanner.scan(
        makeTx({ sourceAccount: "G-unknown-source", signers: [ALICE] })
      );
      const warn = result.warnings.find(
        (w) => w.rule === RELAYER_RULES.UNVERIFIED_SOURCE_ACCOUNT
      );
      expect(warn).toBeDefined();
      expect(result.status).toBe("REQUIRES_REVIEW");
    });

    it("should not warn when sourceAccount is in the trusted-list", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE],
        denylist: [],
        sourceAccounts: [TRUSTED],
      });
      const result = scanner.scan(
        makeTx({ sourceAccount: TRUSTED, signers: [ALICE] })
      );
      expect(
        result.warnings.some(
          (w) => w.rule === RELAYER_RULES.UNVERIFIED_SOURCE_ACCOUNT
        )
      ).toBe(false);
      expect(result.status).toBe("AUTHORIZED");
    });
  });

  describe("Edge cases", () => {
    it("should reject TX with empty signer array", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE],
        denylist: [],
      });
      const result = scanner.scan(makeTx({ signers: [] }));
      expect(result.status).toBe("UNAUTHORIZED");
      const viol = result.violations.find(
        (v) => v.rule === RELAYER_RULES.EMPTY_SIGNERS
      );
      expect(viol).toBeDefined();
      expect(viol!.severity).toBe("CRITICAL");
    });

    it("should silently skip malformed (empty-string) signer entries", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE],
        denylist: [],
      });
      const result = scanner.scan(
        makeTx({ signers: ["", " ", null as unknown as string, ALICE] })
      );
      // null/undefined/blank are normalized to empty and filtered out.
      // Only ALICE remains — TX should be AUTHORIZED.
      expect(result.status).toBe("AUTHORIZED");
      expect(result.authorizedSignerCount).toBe(1);
    });

    it("should throw when given a non-object TX", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE],
        denylist: [],
      });
      expect(() => scanner.scan(null as unknown as TxData)).toThrow(/must be an object/);
    });

    it("should throw when signers is not an array", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE],
        denylist: [],
      });
      expect(() =>
        scanner.scan({ ...makeTx(), signers: "not-an-array" as unknown as string[] })
      ).toThrow(/must be an array/);
    });
  });

  describe("Report generation", () => {
    it("should produce a markdown report (denylist + foreign signer + untrusted source)", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE],
        denylist: [EVE],
        sourceAccounts: [TRUSTED],
      });
      const result = scanner.scan(
        makeTx({ signers: [ALICE, EVE, CAROL], sourceAccount: "G-other-source" })
      );
      const report = scanner.generateReport(result);
      expect(report).toContain("Relayer TX Scan");
      expect(report).toContain("UNAUTHORIZED");
      expect(report).toContain(RELAYER_RULES.UNAUTHORIZED_SIGNER);
      expect(report).toContain(RELAYER_RULES.DENYLISTED_SIGNER);
      expect(report).toContain(RELAYER_RULES.UNVERIFIED_SOURCE_ACCOUNT);
      expect(result.txHash).toBeDefined();
      expect(report).toContain(result.txHash as string);
    });
  });

  describe("Access control (fail-closed by default)", () => {
    it("should mark all TXs unauthorized when empty allowlist is used", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [],
        denylist: [],
      });
      const result = scanner.scan(makeTx({ signers: [ALICE] }));
      expect(result.status).toBe("UNAUTHORIZED");
      expect(
        result.violations.some(
          (v) => v.rule === RELAYER_RULES.UNAUTHORIZED_SIGNER
        )
      ).toBe(true);
    });
  });

  describe("Boundary: denylist vs. unauthorizedSigners", () => {
    it("should report a denylisted signer ONLY in denylistedSigners, not in unauthorizedSigners", () => {
      const scanner = new RelayerTxScanner({
        authorizedSigners: [ALICE],
        denylist: [EVE],
      });
      const result = scanner.scan(makeTx({ signers: [ALICE, EVE] }));
      expect(result.denylistedSigners).toContain(EVE);
      expect(result.unauthorizedSigners).not.toContain(EVE);
    });
  });

  describe("Env-var overrides (RELAYER_AUTHORIZED_SIGNERS, RELAYER_DENYLIST, RELAYER_MULTISIG_THRESHOLD)", () => {
    it("should override authorizedSigners from env", () => {
      const tmp = path.join(os.tmpdir(), `relayer-env-${Date.now()}.json`);
      fs.writeFileSync(
        tmp,
        JSON.stringify({ authorizedSigners: [BOB], denylist: [] })
      );
      try {
        process.env.RELAYER_AUTHORIZED_SIGNERS = ALICE;
        const scanner = RelayerTxScanner.fromConfigFile(tmp, true);
        expect(scanner.authorizedSigners).toEqual([ALICE]);
      } finally {
        delete process.env.RELAYER_AUTHORIZED_SIGNERS;
        fs.unlinkSync(tmp);
      }
    });

    it("should override denylist from env", () => {
      const tmp = path.join(os.tmpdir(), `relayer-env-${Date.now()}.json`);
      fs.writeFileSync(
        tmp,
        JSON.stringify({ authorizedSigners: [ALICE], denylist: [] })
      );
      try {
        process.env.RELAYER_DENYLIST = EVE;
        const scanner = RelayerTxScanner.fromConfigFile(tmp, true);
        expect(scanner.denylistSigners).toEqual([EVE]);
      } finally {
        delete process.env.RELAYER_DENYLIST;
        fs.unlinkSync(tmp);
      }
    });

    it("should override multisigThreshold from env", () => {
      const tmp = path.join(os.tmpdir(), `relayer-env-${Date.now()}.json`);
      fs.writeFileSync(
        tmp,
        JSON.stringify({
          authorizedSigners: [ALICE, BOB, CAROL],
          denylist: [],
          multisigThreshold: 1,
        })
      );
      try {
        process.env.RELAYER_MULTISIG_THRESHOLD = "3";
        const scanner = RelayerTxScanner.fromConfigFile(tmp, true);
        const result = scanner.scan(makeTx({ signers: [ALICE, BOB] }));
        expect(result.status).toBe("REQUIRES_REVIEW");
      } finally {
        delete process.env.RELAYER_MULTISIG_THRESHOLD;
        fs.unlinkSync(tmp);
      }
    });

    it("should ignore invalid RELAYER_MULTISIG_THRESHOLD env value", () => {
      const tmp = path.join(os.tmpdir(), `relayer-env-${Date.now()}.json`);
      fs.writeFileSync(
        tmp,
        JSON.stringify({
          authorizedSigners: [ALICE, BOB],
          denylist: [],
          multisigThreshold: 1,
        })
      );
      try {
        process.env.RELAYER_MULTISIG_THRESHOLD = "not-a-number";
        const scanner = RelayerTxScanner.fromConfigFile(tmp, true);
        // Falls back to file value (1); so [ALICE, BOB] authorizes.
        const result = scanner.scan(makeTx({ signers: [ALICE] }));
        expect(result.status).toBe("AUTHORIZED");
      } finally {
        delete process.env.RELAYER_MULTISIG_THRESHOLD;
        fs.unlinkSync(tmp);
      }
    });
  });

  describe("discover() with RELAYER_CONFIG env var", () => {
    it("should load config from RELAYER_CONFIG env path", () => {
      const tmp = path.join(os.tmpdir(), `relayer-discover-${Date.now()}.json`);
      fs.writeFileSync(
        tmp,
        JSON.stringify({ authorizedSigners: [ALICE], denylist: [] })
      );
      try {
        process.env.RELAYER_CONFIG = tmp;
        const scanner = RelayerTxScanner.discover();
        expect(scanner.authorizedSigners).toContain(ALICE);
      } finally {
        delete process.env.RELAYER_CONFIG;
        fs.unlinkSync(tmp);
      }
    });
  });
});
