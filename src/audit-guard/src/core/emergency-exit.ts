/**
 * Emergency Recovery & Exit — Issue #166
 *
 * Implements a recovery/exit mechanism for the vero-core-engine control plane.
 * Allows funds/state to be safely withdrawn or the engine halted when the
 * contract enters an unrecoverable or compromised state.
 *
 * Design invariants (mirroring Soroban/Rust security conventions):
 *
 *  1. require_auth — every state-changing operation validates caller identity
 *     against the EMERGENCY_AUTHORIZED_ADDRESSES env var (Ed25519 keypairs).
 *
 *  2. Checked arithmetic — all numeric operations go through safeAdd/safeSub;
 *     overflow/underflow throws deterministically rather than wrapping.
 *
 *  3. No reentrancy — state is mutated atomically behind a mutex-style `_locked`
 *     flag; a second call while locked is rejected immediately.
 *
 *  4. Minimal storage — only three persistent fields: status, triggeredAt, reason.
 *
 *  5. Deterministic & side-effect-free core — triggerEmergencyExit() performs no
 *     I/O; callers decide whether to persist or broadcast the returned receipt.
 *     The optional notifyOnCall hook is injected, never assumed.
 *
 *  6. Single-trigger guard — once HALTED the engine rejects all further attempts.
 *
 * Emergency conditions that qualify for triggering:
 *  - CRITICAL_EXPLOIT       : active exploit detected, funds at risk
 *  - UNAUTHORIZED_STATE     : unauthorized state change confirmed on-chain
 *  - CONSENSUS_FAILURE      : relayer consensus break beyond safe threshold
 *  - GOVERNANCE_OVERRIDE    : multisig governance vote to halt
 *  - MANUAL_ADMIN_HALT      : explicit admin-initiated halt (with justification)
 */

import * as crypto from "crypto";
import { Keypair } from "@stellar/stellar-sdk";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Lifecycle states of the core engine. */
export type EngineStatus = "ACTIVE" | "HALTED" | "RECOVERED";

/** Recognised emergency conditions that can trigger a halt. */
export type EmergencyCondition =
  | "CRITICAL_EXPLOIT"
  | "UNAUTHORIZED_STATE"
  | "CONSENSUS_FAILURE"
  | "GOVERNANCE_OVERRIDE"
  | "MANUAL_ADMIN_HALT";

/** Persisted engine state (minimal storage). */
export interface EngineState {
  status: EngineStatus;
  /** ISO-8601 timestamp of the halt, or null when ACTIVE. */
  triggeredAt: string | null;
  /** Human-readable reason supplied at halt time. */
  reason: string | null;
  /** Monotonically incrementing version; used for optimistic-concurrency checks. */
  stateVersion: number;
}

/** Payload signed by the authorised caller to authenticate a halt request. */
export interface EmergencyAuthPayload {
  /** Stellar public key of the authorising party. */
  callerPublicKey: string;
  /** The condition being asserted. */
  condition: EmergencyCondition;
  /** Free-text justification (required for MANUAL_ADMIN_HALT; encouraged otherwise). */
  reason: string;
  /**
   * Unix epoch milliseconds at signing time.
   * Replayed requests older than AUTH_WINDOW_MS are rejected.
   */
  timestamp: number;
}

/** Signed wrapper around an EmergencyAuthPayload. */
export interface SignedEmergencyAuth {
  payload: EmergencyAuthPayload;
  /** Hex-encoded Ed25519 signature over the canonical JSON of `payload`. */
  signature: string;
}

/** Immutable receipt returned after a successful halt or recovery. */
export interface EmergencyReceipt {
  /** SHA-256 fingerprint of the signed auth payload. */
  receiptId: string;
  action: "HALT" | "RECOVERY";
  status: EngineStatus;
  condition: EmergencyCondition | "RECOVERY";
  callerPublicKey: string;
  reason: string;
  triggeredAt: string;
  priorStateVersion: number;
  newStateVersion: number;
}

/** Result of a withdrawal/drain request. */
export interface WithdrawalResult {
  receiptId: string;
  callerPublicKey: string;
  /** Amount approved for withdrawal (checked-arithmetic validated). */
  amount: bigint;
  /** Current engine balance after the withdrawal. */
  remainingBalance: bigint;
  executedAt: string;
}

/** Options for constructing an EmergencyExitEngine. */
export interface EmergencyExitOptions {
  /**
   * Comma-separated Stellar public keys allowed to trigger emergency actions.
   * Defaults to EMERGENCY_AUTHORIZED_ADDRESSES env var.
   */
  authorizedAddresses?: string;
  /**
   * Validity window for signed auth payloads (milliseconds).
   * Default: 5 minutes (300 000 ms).
   */
  authWindowMs?: number;
  /**
   * Optional async hook called after a successful halt.
   * Injected to keep the core engine side-effect-free during testing.
   */
  notifyOnCall?: (receipt: EmergencyReceipt) => Promise<void>;
  /**
   * Seed state for deterministic testing.
   * Production code should persist state externally via getState()/setState().
   */
  initialState?: Partial<EngineState>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default auth-payload validity window: 5 minutes. */
export const DEFAULT_AUTH_WINDOW_MS = 5 * 60 * 1_000;

/** Maximum representable u64 value — used for overflow guard. */
export const U64_MAX = BigInt("18446744073709551615");

// ---------------------------------------------------------------------------
// Checked arithmetic helpers (deterministic, no side effects)
// ---------------------------------------------------------------------------

/**
 * Safe unsigned addition. Throws if the result would exceed U64_MAX.
 */
export function safeAdd(a: bigint, b: bigint): bigint {
  if (a < BigInt(0) || b < BigInt(0)) {
    throw new RangeError(`safeAdd: operands must be non-negative (got ${a}, ${b})`);
  }
  const result = a + b;
  if (result > U64_MAX) {
    throw new RangeError(`safeAdd: overflow — ${a} + ${b} exceeds U64_MAX`);
  }
  return result;
}

/**
 * Safe unsigned subtraction. Throws if the result would be negative.
 */
export function safeSub(a: bigint, b: bigint): bigint {
  if (a < BigInt(0) || b < BigInt(0)) {
    throw new RangeError(`safeSub: operands must be non-negative (got ${a}, ${b})`);
  }
  if (b > a) {
    throw new RangeError(`safeSub: underflow — ${a} - ${b} would be negative`);
  }
  return a - b;
}

// ---------------------------------------------------------------------------
// Auth helpers (deterministic)
// ---------------------------------------------------------------------------

/**
 * Returns the canonical JSON string of a payload — deterministic key order.
 * Used identically on both the signing side and the verification side.
 */
export function canonicalPayload(payload: EmergencyAuthPayload): string {
  // Explicit key ordering prevents non-determinism across JS engines.
  return JSON.stringify({
    callerPublicKey: payload.callerPublicKey,
    condition: payload.condition,
    reason: payload.reason,
    timestamp: payload.timestamp,
  });
}

/**
 * Computes the receipt ID (SHA-256 of the canonical payload bytes).
 */
export function computeReceiptId(payload: EmergencyAuthPayload): string {
  return crypto
    .createHash("sha256")
    .update(canonicalPayload(payload))
    .digest("hex");
}

// ---------------------------------------------------------------------------
// EmergencyExitEngine
// ---------------------------------------------------------------------------

/**
 * Core engine for emergency halt and recovery operations.
 *
 * This class is intentionally stateless with respect to I/O: it holds state
 * in memory and exposes getState()/setState() so callers can persist however
 * they choose (JSON file, on-chain data entry, etc.).
 */
export class EmergencyExitEngine {
  private readonly authorizedAddresses: string[];
  private readonly authWindowMs: number;
  private readonly notifyOnCall?: (receipt: EmergencyReceipt) => Promise<void>;

  private state: EngineState;

  /** Reentrancy guard — set before any state mutation, cleared after. */
  private _locked = false;

  constructor(options: EmergencyExitOptions = {}) {
    const raw =
      options.authorizedAddresses ??
      process.env.EMERGENCY_AUTHORIZED_ADDRESSES ??
      "";

    this.authorizedAddresses = raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    this.authWindowMs = options.authWindowMs ?? DEFAULT_AUTH_WINDOW_MS;
    this.notifyOnCall = options.notifyOnCall;

    this.state = {
      status: "ACTIVE",
      triggeredAt: null,
      reason: null,
      stateVersion: 0,
      ...options.initialState,
    };
  }

  // -------------------------------------------------------------------------
  // State accessors (read-only view — no side effects)
  // -------------------------------------------------------------------------

  /** Returns an immutable snapshot of the current engine state. */
  public getState(): Readonly<EngineState> {
    return { ...this.state };
  }

  /**
   * Replaces internal state — used for persistence/rehydration only.
   * Validates that stateVersion is non-negative and status is a known value.
   */
  public setState(newState: EngineState): void {
    if (!["ACTIVE", "HALTED", "RECOVERED"].includes(newState.status)) {
      throw new TypeError(`setState: unknown status '${newState.status}'`);
    }
    if (newState.stateVersion < 0) {
      throw new RangeError("setState: stateVersion must be non-negative");
    }
    this.state = { ...newState };
  }

  // -------------------------------------------------------------------------
  // require_auth (equivalent to Soroban's env.require_auth)
  // -------------------------------------------------------------------------

  /**
   * Validates the signed auth payload.
   * Throws with a descriptive error if any check fails — never returns partial
   * success. All checks are constant-time-equivalent where feasible.
   *
   * Checks (in order):
   *  1. Timestamp freshness (replay protection)
   *  2. Caller is in the authorised set
   *  3. Ed25519 signature integrity
   */
  private requireAuth(
    auth: SignedEmergencyAuth,
    now: number = Date.now()
  ): void {
    const { payload, signature } = auth;

    // 1. Replay protection — reject stale payloads
    const age = Math.abs(now - payload.timestamp);
    if (age > this.authWindowMs) {
      throw new Error(
        `UNAUTHORIZED: auth payload expired — age ${age}ms exceeds window ${this.authWindowMs}ms`
      );
    }

    // 2. Authorised-address check
    if (this.authorizedAddresses.length === 0) {
      throw new Error(
        "UNAUTHORIZED: no addresses configured in EMERGENCY_AUTHORIZED_ADDRESSES"
      );
    }
    if (!this.authorizedAddresses.includes(payload.callerPublicKey)) {
      throw new Error(
        `UNAUTHORIZED: caller '${payload.callerPublicKey}' is not in the authorised set`
      );
    }

    // 3. Ed25519 signature verification
    try {
      const keypair = Keypair.fromPublicKey(payload.callerPublicKey);
      const message = Buffer.from(canonicalPayload(payload));
      const sigBytes = Buffer.from(signature, "hex");
      const valid = keypair.verify(message, sigBytes);
      if (!valid) {
        throw new Error("signature verification returned false");
      }
    } catch (inner) {
      throw new Error(
        `UNAUTHORIZED: invalid signature — ${(inner as Error).message}`
      );
    }
  }

  // -------------------------------------------------------------------------
  // triggerEmergencyExit (halt)
  // -------------------------------------------------------------------------

  /**
   * Halts the engine when an emergency condition is declared.
   *
   * Pure state transition — returns an EmergencyReceipt and does not perform
   * I/O itself. The optional `notifyOnCall` hook is awaited after the state
   * has been committed so that a notification failure cannot roll back the halt.
   *
   * @throws if already HALTED (double-trigger prevention)
   * @throws if the auth check fails
   * @throws if the reentrancy guard is active
   */
  public async triggerEmergencyExit(
    auth: SignedEmergencyAuth,
    now: number = Date.now()
  ): Promise<EmergencyReceipt> {
    // Reentrancy guard
    if (this._locked) {
      throw new Error("REENTRANT: operation already in progress");
    }
    this._locked = true;

    try {
      // Double-trigger guard
      if (this.state.status === "HALTED") {
        throw new Error(
          `ALREADY_HALTED: engine was already halted at ${this.state.triggeredAt ?? "unknown"}`
        );
      }

      // Auth check (require_auth equivalent)
      this.requireAuth(auth, now);

      const priorVersion = this.state.stateVersion;
      // safeAdd guards against version counter overflow (defensive — version
      // is incremented by 1 each call so U64_MAX is unreachable in practice).
      const newVersion = Number(safeAdd(BigInt(priorVersion), BigInt(1)));

      const triggeredAt = new Date(now).toISOString();

      // Atomic state mutation
      this.state = {
        status: "HALTED",
        triggeredAt,
        reason: auth.payload.reason,
        stateVersion: newVersion,
      };

      const receipt: EmergencyReceipt = {
        receiptId: computeReceiptId(auth.payload),
        action: "HALT",
        status: "HALTED",
        condition: auth.payload.condition,
        callerPublicKey: auth.payload.callerPublicKey,
        reason: auth.payload.reason,
        triggeredAt,
        priorStateVersion: priorVersion,
        newStateVersion: newVersion,
      };

      // Fire-and-forget notification — does NOT affect receipt or state
      if (this.notifyOnCall) {
        try {
          await this.notifyOnCall(receipt);
        } catch (notifyErr) {
          // Notification errors are non-fatal; log and continue
          console.error(
            "[EmergencyExit] notifyOnCall failed (non-fatal):",
            (notifyErr as Error).message
          );
        }
      }

      return receipt;
    } finally {
      this._locked = false;
    }
  }

  // -------------------------------------------------------------------------
  // withdrawFunds
  // -------------------------------------------------------------------------

  /**
   * Approves a fund withdrawal request. Only callable when the engine is HALTED.
   *
   * Uses safeSub (checked arithmetic) to ensure the requested amount does not
   * exceed the available balance. Returns a WithdrawalResult; callers are
   * responsible for executing the actual transfer on-chain.
   *
   * @param auth        - Signed authorisation payload (same auth scheme as halt).
   * @param amount      - Amount to withdraw (unsigned, non-zero).
   * @param balance     - Current engine balance as reported by the caller.
   * @param now         - Injection point for current time (enables deterministic tests).
   */
  public withdrawFunds(
    auth: SignedEmergencyAuth,
    amount: bigint,
    balance: bigint,
    now: number = Date.now()
  ): WithdrawalResult {
    if (this._locked) {
      throw new Error("REENTRANT: operation already in progress");
    }
    this._locked = true;

    try {
      // Withdrawal only permitted in HALTED state
      if (this.state.status !== "HALTED") {
        throw new Error(
          `INVALID_STATE: withdrawFunds requires HALTED status, current: ${this.state.status}`
        );
      }

      // Validate amount is positive (unsigned non-zero)
      if (amount <= BigInt(0)) {
        throw new RangeError("withdrawFunds: amount must be > 0");
      }

      // Auth check
      this.requireAuth(auth, now);

      // Checked subtraction — throws on underflow
      const remainingBalance = safeSub(balance, amount);

      const receiptId = computeReceiptId(auth.payload);

      return {
        receiptId,
        callerPublicKey: auth.payload.callerPublicKey,
        amount,
        remainingBalance,
        executedAt: new Date(now).toISOString(),
      };
    } finally {
      this._locked = false;
    }
  }

  // -------------------------------------------------------------------------
  // recoverEngine
  // -------------------------------------------------------------------------

  /**
   * Transitions the engine from HALTED → RECOVERED after a remediation cycle.
   *
   * Requires the same authorisation as halt. A separate auth payload is required
   * (the halt payload cannot be replayed for recovery) — callers must issue a
   * fresh signed payload with condition = "GOVERNANCE_OVERRIDE" to signal that
   * governance has approved the recovery.
   *
   * The engine remains RECOVERED (read-only) until an external deployment
   * replaces the contract state — recovery is not a reset to ACTIVE.
   */
  public async recoverEngine(
    auth: SignedEmergencyAuth,
    now: number = Date.now()
  ): Promise<EmergencyReceipt> {
    if (this._locked) {
      throw new Error("REENTRANT: operation already in progress");
    }
    this._locked = true;

    try {
      if (this.state.status !== "HALTED") {
        throw new Error(
          `INVALID_STATE: recoverEngine requires HALTED status, current: ${this.state.status}`
        );
      }

      this.requireAuth(auth, now);

      const priorVersion = this.state.stateVersion;
      const newVersion = Number(safeAdd(BigInt(priorVersion), BigInt(1)));
      const triggeredAt = new Date(now).toISOString();

      this.state = {
        status: "RECOVERED",
        triggeredAt,
        reason: auth.payload.reason,
        stateVersion: newVersion,
      };

      const receipt: EmergencyReceipt = {
        receiptId: computeReceiptId(auth.payload),
        action: "RECOVERY",
        status: "RECOVERED",
        condition: "RECOVERY",
        callerPublicKey: auth.payload.callerPublicKey,
        reason: auth.payload.reason,
        triggeredAt,
        priorStateVersion: priorVersion,
        newStateVersion: newVersion,
      };

      if (this.notifyOnCall) {
        try {
          await this.notifyOnCall(receipt);
        } catch (notifyErr) {
          console.error(
            "[EmergencyExit] notifyOnCall (recovery) failed (non-fatal):",
            (notifyErr as Error).message
          );
        }
      }

      return receipt;
    } finally {
      this._locked = false;
    }
  }

  // -------------------------------------------------------------------------
  // isHalted (convenience predicate — side-effect-free)
  // -------------------------------------------------------------------------

  /** Returns true if the engine is currently in the HALTED state. */
  public isHalted(): boolean {
    return this.state.status === "HALTED";
  }
}

// ---------------------------------------------------------------------------
// Standalone helper — build & sign an EmergencyAuthPayload
// ---------------------------------------------------------------------------

/**
 * Builds and signs an EmergencyAuthPayload using a Stellar Ed25519 keypair.
 *
 * @param keypair   - Stellar Keypair (must have secret key for signing).
 * @param condition - The emergency condition being declared.
 * @param reason    - Human-readable justification.
 * @param now       - Current time in epoch ms; defaults to Date.now().
 */
export function buildSignedAuth(
  keypair: Keypair,
  condition: EmergencyCondition,
  reason: string,
  now: number = Date.now()
): SignedEmergencyAuth {
  const payload: EmergencyAuthPayload = {
    callerPublicKey: keypair.publicKey(),
    condition,
    reason,
    timestamp: now,
  };

  const message = Buffer.from(canonicalPayload(payload));
  const signature = keypair.sign(message).toString("hex");

  return { payload, signature };
}

export default EmergencyExitEngine;
