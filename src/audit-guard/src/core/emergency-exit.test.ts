/**
 * Tests — Emergency Recovery & Exit (Issue #166)
 *
 * Coverage:
 *  1. Normal exit flow (happy path)
 *  2. Unauthorized attempt (missing / wrong address, expired timestamp, bad sig)
 *  3. Double-trigger prevention
 *  4. Edge-case state (reentrancy guard, recovery from HALTED, withdrawal guards,
 *     checked arithmetic helpers, setState validation)
 */

import { Keypair } from "@stellar/stellar-sdk";
import EmergencyExitEngine, {
  buildSignedAuth,
  canonicalPayload,
  computeReceiptId,
  safeAdd,
  safeSub,
  U64_MAX,
  EmergencyReceipt,
} from "./emergency-exit";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEngine(authorizedKey: string, opts: Record<string, unknown> = {}) {
  return new EmergencyExitEngine({
    authorizedAddresses: authorizedKey,
    ...opts,
  });
}

const FIXED_NOW = 1_700_000_000_000; // deterministic epoch ms

// ---------------------------------------------------------------------------
// 1. Normal exit flow
// ---------------------------------------------------------------------------

describe("Normal exit flow", () => {
  const caller = Keypair.random();

  beforeEach(() => {
    delete process.env.EMERGENCY_AUTHORIZED_ADDRESSES;
  });

  it("starts in ACTIVE state with stateVersion 0", () => {
    const engine = makeEngine(caller.publicKey());
    const state = engine.getState();
    expect(state.status).toBe("ACTIVE");
    expect(state.triggeredAt).toBeNull();
    expect(state.reason).toBeNull();
    expect(state.stateVersion).toBe(0);
  });

  it("transitions to HALTED and returns a valid receipt", async () => {
    const engine = makeEngine(caller.publicKey());
    const auth = buildSignedAuth(caller, "CRITICAL_EXPLOIT", "Funds at risk", FIXED_NOW);

    const receipt = await engine.triggerEmergencyExit(auth, FIXED_NOW);

    expect(receipt.action).toBe("HALT");
    expect(receipt.status).toBe("HALTED");
    expect(receipt.condition).toBe("CRITICAL_EXPLOIT");
    expect(receipt.callerPublicKey).toBe(caller.publicKey());
    expect(receipt.reason).toBe("Funds at risk");
    expect(receipt.priorStateVersion).toBe(0);
    expect(receipt.newStateVersion).toBe(1);
    expect(receipt.triggeredAt).toBe(new Date(FIXED_NOW).toISOString());
  });

  it("persists HALTED state after halt", async () => {
    const engine = makeEngine(caller.publicKey());
    const auth = buildSignedAuth(caller, "UNAUTHORIZED_STATE", "State change detected", FIXED_NOW);

    await engine.triggerEmergencyExit(auth, FIXED_NOW);

    const state = engine.getState();
    expect(state.status).toBe("HALTED");
    expect(state.stateVersion).toBe(1);
    expect(state.reason).toBe("State change detected");
    expect(state.triggeredAt).toBe(new Date(FIXED_NOW).toISOString());
  });

  it("isHalted() reflects engine state", async () => {
    const engine = makeEngine(caller.publicKey());
    expect(engine.isHalted()).toBe(false);

    const auth = buildSignedAuth(caller, "CONSENSUS_FAILURE", "Consensus broken", FIXED_NOW);
    await engine.triggerEmergencyExit(auth, FIXED_NOW);

    expect(engine.isHalted()).toBe(true);
  });

  it("receiptId is a deterministic SHA-256 hex string", async () => {
    const engine = makeEngine(caller.publicKey());
    const auth = buildSignedAuth(caller, "GOVERNANCE_OVERRIDE", "Governance vote", FIXED_NOW);
    const receipt = await engine.triggerEmergencyExit(auth, FIXED_NOW);

    // receiptId must equal the standalone helper
    const expected = computeReceiptId(auth.payload);
    expect(receipt.receiptId).toBe(expected);
    // Must be a 64-char hex string
    expect(receipt.receiptId).toMatch(/^[0-9a-f]{64}$/);
  });

  it("notifyOnCall hook is invoked with the receipt after halt", async () => {
    const notifyMock = jest.fn().mockResolvedValue(undefined);
    const engine = makeEngine(caller.publicKey(), { notifyOnCall: notifyMock });
    const auth = buildSignedAuth(caller, "MANUAL_ADMIN_HALT", "Routine halt", FIXED_NOW);

    const receipt = await engine.triggerEmergencyExit(auth, FIXED_NOW);

    expect(notifyMock).toHaveBeenCalledTimes(1);
    expect(notifyMock).toHaveBeenCalledWith(receipt);
  });

  it("notifyOnCall failure does NOT prevent halt from succeeding", async () => {
    const notifyMock = jest.fn().mockRejectedValue(new Error("network failure"));
    const engine = makeEngine(caller.publicKey(), { notifyOnCall: notifyMock });
    const auth = buildSignedAuth(caller, "CRITICAL_EXPLOIT", "Silent halt", FIXED_NOW);

    // Should not throw despite notification error
    await expect(engine.triggerEmergencyExit(auth, FIXED_NOW)).resolves.toMatchObject({
      status: "HALTED",
    });
    expect(engine.isHalted()).toBe(true);
  });

  it("withdrawFunds succeeds when HALTED with valid auth and sufficient balance", async () => {
    const engine = makeEngine(caller.publicKey());
    const haltAuth = buildSignedAuth(caller, "CRITICAL_EXPLOIT", "Halt for withdrawal", FIXED_NOW);
    await engine.triggerEmergencyExit(haltAuth, FIXED_NOW);

    const withdrawAuth = buildSignedAuth(caller, "MANUAL_ADMIN_HALT", "Fund recovery", FIXED_NOW + 1000);
    const result = engine.withdrawFunds(
      withdrawAuth,
      BigInt(500),
      BigInt(1000),
      FIXED_NOW + 1000
    );

    expect(result.amount).toBe(BigInt(500));
    expect(result.remainingBalance).toBe(BigInt(500));
    expect(result.callerPublicKey).toBe(caller.publicKey());
  });

  it("recoverEngine transitions HALTED → RECOVERED", async () => {
    const engine = makeEngine(caller.publicKey());
    const haltAuth = buildSignedAuth(caller, "CRITICAL_EXPLOIT", "Emergency halt", FIXED_NOW);
    await engine.triggerEmergencyExit(haltAuth, FIXED_NOW);

    const recoverAuth = buildSignedAuth(
      caller,
      "GOVERNANCE_OVERRIDE",
      "Post-incident recovery approved",
      FIXED_NOW + 60_000
    );
    const receipt = await engine.recoverEngine(recoverAuth, FIXED_NOW + 60_000);

    expect(receipt.action).toBe("RECOVERY");
    expect(receipt.status).toBe("RECOVERED");
    expect(receipt.priorStateVersion).toBe(1);
    expect(receipt.newStateVersion).toBe(2);

    const state = engine.getState();
    expect(state.status).toBe("RECOVERED");
    expect(state.stateVersion).toBe(2);
  });

  it("falls back to EMERGENCY_AUTHORIZED_ADDRESSES env var when no option supplied", async () => {
    process.env.EMERGENCY_AUTHORIZED_ADDRESSES = caller.publicKey();
    // No authorizedAddresses option — engine reads from env
    const engine = new EmergencyExitEngine();
    const auth = buildSignedAuth(caller, "MANUAL_ADMIN_HALT", "Env-var auth", FIXED_NOW);

    await expect(engine.triggerEmergencyExit(auth, FIXED_NOW)).resolves.toMatchObject({
      status: "HALTED",
    });

    delete process.env.EMERGENCY_AUTHORIZED_ADDRESSES;
  });
});

// ---------------------------------------------------------------------------
// 2. Unauthorized attempts
// ---------------------------------------------------------------------------

describe("Unauthorized attempt", () => {
  const authorizedCaller = Keypair.random();
  const unauthorizedCaller = Keypair.random();

  beforeEach(() => {
    delete process.env.EMERGENCY_AUTHORIZED_ADDRESSES;
  });

  it("rejects when no authorized addresses are configured", async () => {
    const engine = new EmergencyExitEngine({ authorizedAddresses: "" });
    const auth = buildSignedAuth(authorizedCaller, "CRITICAL_EXPLOIT", "Exploit", FIXED_NOW);

    await expect(engine.triggerEmergencyExit(auth, FIXED_NOW)).rejects.toThrow(
      "UNAUTHORIZED: no addresses configured"
    );
    expect(engine.isHalted()).toBe(false);
  });

  it("rejects a caller not in the authorized set", async () => {
    const engine = makeEngine(authorizedCaller.publicKey());
    const auth = buildSignedAuth(unauthorizedCaller, "CRITICAL_EXPLOIT", "Impersonation", FIXED_NOW);

    await expect(engine.triggerEmergencyExit(auth, FIXED_NOW)).rejects.toThrow(
      "UNAUTHORIZED: caller"
    );
    expect(engine.isHalted()).toBe(false);
  });

  it("rejects an expired auth payload (older than authWindowMs)", async () => {
    const engine = makeEngine(authorizedCaller.publicKey(), { authWindowMs: 60_000 });
    const staleNow = FIXED_NOW - 120_000; // 2 minutes ago
    const auth = buildSignedAuth(authorizedCaller, "CRITICAL_EXPLOIT", "Stale", staleNow);

    await expect(engine.triggerEmergencyExit(auth, FIXED_NOW)).rejects.toThrow(
      "UNAUTHORIZED: auth payload expired"
    );
    expect(engine.isHalted()).toBe(false);
  });

  it("rejects a future-dated auth payload (replay with future timestamp)", async () => {
    const engine = makeEngine(authorizedCaller.publicKey(), { authWindowMs: 60_000 });
    const futureNow = FIXED_NOW + 120_000; // 2 minutes in the future
    const auth = buildSignedAuth(authorizedCaller, "CRITICAL_EXPLOIT", "Future", futureNow);

    await expect(engine.triggerEmergencyExit(auth, FIXED_NOW)).rejects.toThrow(
      "UNAUTHORIZED: auth payload expired"
    );
  });

  it("rejects a tampered signature (bytes changed)", async () => {
    const engine = makeEngine(authorizedCaller.publicKey());
    const auth = buildSignedAuth(authorizedCaller, "CRITICAL_EXPLOIT", "Valid", FIXED_NOW);

    // Flip the last two hex chars to corrupt the signature
    const tampered = {
      ...auth,
      signature: auth.signature.slice(0, -2) + "00",
    };

    await expect(engine.triggerEmergencyExit(tampered, FIXED_NOW)).rejects.toThrow(
      "UNAUTHORIZED: invalid signature"
    );
    expect(engine.isHalted()).toBe(false);
  });

  it("rejects when payload fields are tampered after signing", async () => {
    const engine = makeEngine(authorizedCaller.publicKey());
    const auth = buildSignedAuth(authorizedCaller, "CRITICAL_EXPLOIT", "Original reason", FIXED_NOW);

    // Mutate the reason after signing — signature no longer matches
    const tampered = {
      payload: { ...auth.payload, reason: "Injected reason" },
      signature: auth.signature,
    };

    await expect(engine.triggerEmergencyExit(tampered, FIXED_NOW)).rejects.toThrow(
      "UNAUTHORIZED: invalid signature"
    );
  });

  it("does not mutate state on authorization failure", async () => {
    const engine = makeEngine(authorizedCaller.publicKey());
    const stateBefore = engine.getState();

    const auth = buildSignedAuth(unauthorizedCaller, "CRITICAL_EXPLOIT", "Rejected", FIXED_NOW);
    await expect(engine.triggerEmergencyExit(auth, FIXED_NOW)).rejects.toThrow();

    expect(engine.getState()).toEqual(stateBefore);
  });
});

// ---------------------------------------------------------------------------
// 3. Double-trigger prevention
// ---------------------------------------------------------------------------

describe("Double-trigger prevention", () => {
  const caller = Keypair.random();

  it("rejects a second halt attempt when already HALTED", async () => {
    const engine = makeEngine(caller.publicKey());
    const auth1 = buildSignedAuth(caller, "CRITICAL_EXPLOIT", "First halt", FIXED_NOW);
    await engine.triggerEmergencyExit(auth1, FIXED_NOW);

    const auth2 = buildSignedAuth(caller, "CRITICAL_EXPLOIT", "Second halt", FIXED_NOW + 1000);
    await expect(engine.triggerEmergencyExit(auth2, FIXED_NOW + 1000)).rejects.toThrow(
      "ALREADY_HALTED"
    );

    // stateVersion must not increment
    expect(engine.getState().stateVersion).toBe(1);
  });

  it("stateVersion is only incremented once after a successful halt", async () => {
    const engine = makeEngine(caller.publicKey());
    expect(engine.getState().stateVersion).toBe(0);

    const auth = buildSignedAuth(caller, "MANUAL_ADMIN_HALT", "Once", FIXED_NOW);
    await engine.triggerEmergencyExit(auth, FIXED_NOW);

    expect(engine.getState().stateVersion).toBe(1);
  });

  it("recoverEngine rejects when engine is ACTIVE (not halted first)", async () => {
    const engine = makeEngine(caller.publicKey());
    const auth = buildSignedAuth(caller, "GOVERNANCE_OVERRIDE", "Bad recovery", FIXED_NOW);

    await expect(engine.recoverEngine(auth, FIXED_NOW)).rejects.toThrow(
      "INVALID_STATE: recoverEngine requires HALTED"
    );
  });

  it("recoverEngine rejects a second recovery attempt on RECOVERED engine", async () => {
    const engine = makeEngine(caller.publicKey());
    const haltAuth = buildSignedAuth(caller, "CRITICAL_EXPLOIT", "Halt", FIXED_NOW);
    await engine.triggerEmergencyExit(haltAuth, FIXED_NOW);

    const recoverAuth1 = buildSignedAuth(caller, "GOVERNANCE_OVERRIDE", "First recovery", FIXED_NOW + 1000);
    await engine.recoverEngine(recoverAuth1, FIXED_NOW + 1000);

    const recoverAuth2 = buildSignedAuth(caller, "GOVERNANCE_OVERRIDE", "Second recovery", FIXED_NOW + 2000);
    await expect(engine.recoverEngine(recoverAuth2, FIXED_NOW + 2000)).rejects.toThrow(
      "INVALID_STATE: recoverEngine requires HALTED"
    );
  });
});

// ---------------------------------------------------------------------------
// 4. Edge-case state
// ---------------------------------------------------------------------------

describe("Edge-case state", () => {
  const caller = Keypair.random();

  // -- Checked arithmetic --

  describe("safeAdd", () => {
    it("returns correct sum for normal values", () => {
      expect(safeAdd(BigInt(10), BigInt(20))).toBe(BigInt(30));
    });

    it("returns U64_MAX exactly when summing to the boundary", () => {
      expect(safeAdd(U64_MAX - BigInt(1), BigInt(1))).toBe(U64_MAX);
    });

    it("throws on overflow beyond U64_MAX", () => {
      expect(() => safeAdd(U64_MAX, BigInt(1))).toThrow("overflow");
    });

    it("throws on negative operand", () => {
      expect(() => safeAdd(BigInt(-1), BigInt(5))).toThrow("non-negative");
    });
  });

  describe("safeSub", () => {
    it("returns correct difference for normal values", () => {
      expect(safeSub(BigInt(100), BigInt(40))).toBe(BigInt(60));
    });

    it("returns zero when a === b", () => {
      expect(safeSub(BigInt(7), BigInt(7))).toBe(BigInt(0));
    });

    it("throws on underflow (b > a)", () => {
      expect(() => safeSub(BigInt(5), BigInt(10))).toThrow("underflow");
    });

    it("throws on negative operand", () => {
      expect(() => safeSub(BigInt(-1), BigInt(5))).toThrow("non-negative");
    });
  });

  // -- withdrawFunds edge cases --

  describe("withdrawFunds", () => {
    it("rejects withdrawal when engine is ACTIVE", () => {
      const engine = makeEngine(caller.publicKey());
      const auth = buildSignedAuth(caller, "MANUAL_ADMIN_HALT", "Withdraw", FIXED_NOW);

      expect(() => engine.withdrawFunds(auth, BigInt(100), BigInt(1000), FIXED_NOW)).toThrow(
        "INVALID_STATE: withdrawFunds requires HALTED"
      );
    });

    it("rejects zero-amount withdrawal", async () => {
      const engine = makeEngine(caller.publicKey());
      const haltAuth = buildSignedAuth(caller, "CRITICAL_EXPLOIT", "Halt", FIXED_NOW);
      await engine.triggerEmergencyExit(haltAuth, FIXED_NOW);

      const withdrawAuth = buildSignedAuth(caller, "MANUAL_ADMIN_HALT", "Zero", FIXED_NOW + 100);
      expect(() => engine.withdrawFunds(withdrawAuth, BigInt(0), BigInt(1000), FIXED_NOW + 100)).toThrow(
        "amount must be > 0"
      );
    });

    it("rejects withdrawal exceeding available balance (underflow guard)", async () => {
      const engine = makeEngine(caller.publicKey());
      const haltAuth = buildSignedAuth(caller, "CRITICAL_EXPLOIT", "Halt", FIXED_NOW);
      await engine.triggerEmergencyExit(haltAuth, FIXED_NOW);

      const withdrawAuth = buildSignedAuth(caller, "MANUAL_ADMIN_HALT", "Over-withdraw", FIXED_NOW + 100);
      expect(() => engine.withdrawFunds(withdrawAuth, BigInt(2000), BigInt(1000), FIXED_NOW + 100)).toThrow(
        "underflow"
      );
    });

    it("allows draining entire balance (amount === balance)", async () => {
      const engine = makeEngine(caller.publicKey());
      const haltAuth = buildSignedAuth(caller, "CRITICAL_EXPLOIT", "Halt", FIXED_NOW);
      await engine.triggerEmergencyExit(haltAuth, FIXED_NOW);

      const withdrawAuth = buildSignedAuth(caller, "MANUAL_ADMIN_HALT", "Full drain", FIXED_NOW + 100);
      const result = engine.withdrawFunds(withdrawAuth, BigInt(1000), BigInt(1000), FIXED_NOW + 100);
      expect(result.remainingBalance).toBe(BigInt(0));
    });
  });

  // -- setState validation --

  describe("setState", () => {
    it("accepts valid state objects", () => {
      const engine = makeEngine(caller.publicKey());
      const validState = {
        status: "HALTED" as const,
        triggeredAt: new Date(FIXED_NOW).toISOString(),
        reason: "Rehydrated",
        stateVersion: 5,
      };
      expect(() => engine.setState(validState)).not.toThrow();
      expect(engine.getState().stateVersion).toBe(5);
    });

    it("rejects unknown status values", () => {
      const engine = makeEngine(caller.publicKey());
      expect(() =>
        engine.setState({
          status: "ZOMBIE" as unknown as "ACTIVE",
          triggeredAt: null,
          reason: null,
          stateVersion: 1,
        })
      ).toThrow("unknown status");
    });

    it("rejects negative stateVersion", () => {
      const engine = makeEngine(caller.publicKey());
      expect(() =>
        engine.setState({
          status: "ACTIVE",
          triggeredAt: null,
          reason: null,
          stateVersion: -1,
        })
      ).toThrow("non-negative");
    });
  });

  // -- Reentrancy guard --

  it("reentrancy guard is released even if requireAuth throws", async () => {
    const engine = makeEngine(caller.publicKey());
    const badAuth = buildSignedAuth(
      Keypair.random(), // unauthorized
      "CRITICAL_EXPLOIT",
      "Reentrancy test",
      FIXED_NOW
    );

    await expect(engine.triggerEmergencyExit(badAuth, FIXED_NOW)).rejects.toThrow("UNAUTHORIZED");

    // A legitimate call should succeed — _locked must have been released
    const goodAuth = buildSignedAuth(caller, "CRITICAL_EXPLOIT", "After rejection", FIXED_NOW);
    await expect(engine.triggerEmergencyExit(goodAuth, FIXED_NOW)).resolves.toMatchObject({
      status: "HALTED",
    });
  });

  // -- canonicalPayload determinism --

  it("canonicalPayload produces identical output for identical inputs", () => {
    const payload = {
      callerPublicKey: caller.publicKey(),
      condition: "CRITICAL_EXPLOIT" as const,
      reason: "Determinism check",
      timestamp: FIXED_NOW,
    };
    expect(canonicalPayload(payload)).toBe(canonicalPayload({ ...payload }));
  });

  it("canonicalPayload differs when any field changes", () => {
    const base = {
      callerPublicKey: caller.publicKey(),
      condition: "CRITICAL_EXPLOIT" as const,
      reason: "Base",
      timestamp: FIXED_NOW,
    };
    const mutated = { ...base, reason: "Mutated" };
    expect(canonicalPayload(base)).not.toBe(canonicalPayload(mutated));
  });

  // -- getState returns an immutable snapshot --

  it("getState returns a copy — mutations do not affect internal state", () => {
    const engine = makeEngine(caller.publicKey());
    const snapshot = engine.getState() as Record<string, unknown>;
    snapshot["status"] = "HALTED"; // mutate the snapshot

    // Internal state must still be ACTIVE
    expect(engine.getState().status).toBe("ACTIVE");
  });
});
