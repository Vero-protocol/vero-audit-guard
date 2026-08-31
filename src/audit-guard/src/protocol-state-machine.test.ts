/**
 * Protocol State Machine — Regression Test Suite
 *
 * Issue #172 / VAG-004
 *
 * Covers:
 *  • All valid (happy-path) transitions
 *  • Invalid transitions from every state
 *  • Adversarial inputs (replayed scanIds, clock-skew, null/empty values)
 *  • Error hierarchy / typed error propagation
 *  • tryApply non-throwing API
 *  • Observer / telemetry callback wiring
 *  • RESET from every state
 *  • Machine shutdown
 *  • History depth cap
 *  • Snapshot hash chaining (ZK-readiness)
 *  • buildStateMachineAlert payloads
 *  • createConsoleAlertObserver wiring
 */

import ProtocolStateMachine, {
  InvalidTransitionError,
  ScanIdMismatchError,
  TimestampViolationError,
  StateMachineShutdownError,
  InvariantViolationError,
  buildStateMachineAlert,
  createConsoleAlertObserver,
  type ProtocolEvent,
  type ProtocolState,
  type TransitionObserver,
  type StateMachineAlertPayload,
  type TransitionRecord,
  type StateMachineErrorUnion,
} from "./protocol-state-machine";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const NOW = 1_700_000_000_000; // fixed epoch for deterministic tests

function makeSm(opts?: ConstructorParameters<typeof ProtocolStateMachine>[0]) {
  return new ProtocolStateMachine({
    nowFn: () => NOW,
    maxClockSkewMs: 60_000,
    ...opts,
  });
}

function scanStarted(scanId = "s1", target = "/target", timestamp = NOW): ProtocolEvent {
  return { type: "SCAN_STARTED", scanId, target, timestamp };
}
function scanCompleted(scanId = "s1", findingCount = 0, timestamp = NOW): ProtocolEvent {
  return { type: "SCAN_COMPLETED", scanId, findingCount, timestamp };
}
function scanFailed(scanId = "s1", reason = "oom", timestamp = NOW): ProtocolEvent {
  return { type: "SCAN_FAILED", scanId, reason, timestamp };
}
function reportStarted(scanId = "s1", timestamp = NOW): ProtocolEvent {
  return { type: "REPORT_STARTED", scanId, timestamp };
}
function reportDelivered(scanId = "s1", reportHash = "abc123", timestamp = NOW): ProtocolEvent {
  return { type: "REPORT_DELIVERED", scanId, reportHash, timestamp };
}
function reportFailed(scanId = "s1", reason = "write error", timestamp = NOW): ProtocolEvent {
  return { type: "REPORT_FAILED", scanId, reason, timestamp };
}
function reset(requestedBy = "test", timestamp = NOW): ProtocolEvent {
  return { type: "RESET", requestedBy, timestamp };
}

// ---------------------------------------------------------------------------
// Happy-path transitions
// ---------------------------------------------------------------------------

describe("happy-path transitions", () => {
  test("IDLE → SCANNING on SCAN_STARTED", () => {
    const sm = makeSm();
    expect(sm.state).toBe("IDLE");
    sm.apply(scanStarted("s1"));
    expect(sm.state).toBe("SCANNING");
    expect(sm.activeScanId).toBe("s1");
  });

  test("SCANNING → REPORTING on SCAN_COMPLETED", () => {
    const sm = makeSm();
    sm.apply(scanStarted());
    sm.apply(scanCompleted());
    expect(sm.state).toBe("REPORTING");
  });

  test("REPORTING → DONE on REPORT_DELIVERED", () => {
    const sm = makeSm();
    sm.apply(scanStarted());
    sm.apply(scanCompleted());
    sm.apply(reportDelivered());
    expect(sm.state).toBe("DONE");
  });

  test("SCANNING → FAILED on SCAN_FAILED", () => {
    const sm = makeSm();
    sm.apply(scanStarted());
    sm.apply(scanFailed());
    expect(sm.state).toBe("FAILED");
  });

  test("REPORTING → FAILED on REPORT_FAILED", () => {
    const sm = makeSm();
    sm.apply(scanStarted());
    sm.apply(scanCompleted());
    sm.apply(reportFailed());
    expect(sm.state).toBe("FAILED");
  });

  test("REPORTING is idempotent on REPORT_STARTED", () => {
    const sm = makeSm();
    sm.apply(scanStarted());
    sm.apply(scanCompleted());
    sm.apply(reportStarted()); // already in REPORTING
    expect(sm.state).toBe("REPORTING");
  });

  test("transition count increments correctly", () => {
    const sm = makeSm();
    expect(sm.transitionCount).toBe(0);
    sm.apply(scanStarted());
    sm.apply(scanCompleted());
    sm.apply(reportDelivered());
    expect(sm.transitionCount).toBe(3);
  });

  test("activeScanId cleared after DONE via RESET", () => {
    const sm = makeSm();
    sm.apply(scanStarted("scan-99"));
    sm.apply(scanCompleted("scan-99"));
    sm.apply(reportDelivered("scan-99"));
    sm.apply(reset());
    expect(sm.state).toBe("IDLE");
    expect(sm.activeScanId).toBeNull();
  });

  test("full happy path produces correct history sequence", () => {
    const sm = makeSm();
    sm.apply(scanStarted("s1"));
    sm.apply(scanCompleted("s1"));
    sm.apply(reportDelivered("s1"));

    const history = sm.history;
    expect(history).toHaveLength(3);
    expect(history[0].fromState).toBe("IDLE");
    expect(history[0].toState).toBe("SCANNING");
    expect(history[1].fromState).toBe("SCANNING");
    expect(history[1].toState).toBe("REPORTING");
    expect(history[2].fromState).toBe("REPORTING");
    expect(history[2].toState).toBe("DONE");
  });
});

// ---------------------------------------------------------------------------
// RESET from all states
// ---------------------------------------------------------------------------

describe("RESET transitions", () => {
  const states: ProtocolState[] = ["IDLE", "SCANNING", "REPORTING", "DONE", "FAILED"];

  test.each([
    ["IDLE",      () => { const sm = makeSm(); return sm; }],
    ["SCANNING",  () => { const sm = makeSm(); sm.apply(scanStarted()); return sm; }],
    ["REPORTING", () => { const sm = makeSm(); sm.apply(scanStarted()); sm.apply(scanCompleted()); return sm; }],
    ["DONE",      () => { const sm = makeSm(); sm.apply(scanStarted()); sm.apply(scanCompleted()); sm.apply(reportDelivered()); return sm; }],
    ["FAILED",    () => { const sm = makeSm(); sm.apply(scanStarted()); sm.apply(scanFailed()); return sm; }],
  ])("RESET from %s → IDLE", (stateName, factory) => {
    const sm = factory();
    expect(sm.state).toBe(stateName);
    sm.apply(reset("operator"));
    expect(sm.state).toBe("IDLE");
    expect(sm.activeScanId).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Invalid transitions — non-happy-path
// ---------------------------------------------------------------------------

describe("invalid transitions throw InvalidTransitionError", () => {
  test("SCAN_COMPLETED from IDLE is invalid", () => {
    const sm = makeSm();
    expect(() => sm.apply(scanCompleted())).toThrow(InvalidTransitionError);
  });

  test("REPORT_DELIVERED from IDLE is invalid", () => {
    const sm = makeSm();
    expect(() => sm.apply(reportDelivered())).toThrow(InvalidTransitionError);
  });

  test("SCAN_STARTED from SCANNING is invalid", () => {
    const sm = makeSm();
    sm.apply(scanStarted("s1"));
    expect(() => sm.apply(scanStarted("s2"))).toThrow(InvalidTransitionError);
  });

  test("SCAN_STARTED from REPORTING is invalid", () => {
    const sm = makeSm();
    sm.apply(scanStarted());
    sm.apply(scanCompleted());
    expect(() => sm.apply(scanStarted("s2"))).toThrow(InvalidTransitionError);
  });

  test("SCAN_STARTED from DONE is invalid", () => {
    const sm = makeSm();
    sm.apply(scanStarted());
    sm.apply(scanCompleted());
    sm.apply(reportDelivered());
    expect(() => sm.apply(scanStarted("s2"))).toThrow(InvalidTransitionError);
  });

  test("SCAN_COMPLETED from REPORTING is invalid", () => {
    const sm = makeSm();
    sm.apply(scanStarted());
    sm.apply(scanCompleted());
    expect(() => sm.apply(scanCompleted())).toThrow(InvalidTransitionError);
  });

  test("SCAN_FAILED from DONE is invalid", () => {
    const sm = makeSm();
    sm.apply(scanStarted());
    sm.apply(scanCompleted());
    sm.apply(reportDelivered());
    expect(() => sm.apply(scanFailed())).toThrow(InvalidTransitionError);
  });

  test("REPORT_DELIVERED from FAILED is invalid", () => {
    const sm = makeSm();
    sm.apply(scanStarted());
    sm.apply(scanFailed());
    expect(() => sm.apply(reportDelivered())).toThrow(InvalidTransitionError);
  });

  test("REPORT_DELIVERED from SCANNING is invalid", () => {
    const sm = makeSm();
    sm.apply(scanStarted());
    expect(() => sm.apply(reportDelivered())).toThrow(InvalidTransitionError);
  });

  test("SCAN_FAILED from IDLE is invalid", () => {
    const sm = makeSm();
    expect(() => sm.apply(scanFailed())).toThrow(InvalidTransitionError);
  });

  test("error carries correct fromState and eventType", () => {
    const sm = makeSm();
    try {
      sm.apply(scanCompleted());
    } catch (e) {
      expect(e).toBeInstanceOf(InvalidTransitionError);
      const err = e as InvalidTransitionError;
      expect(err.fromState).toBe("IDLE");
      expect(err.event).toBe("SCAN_COMPLETED");
      expect(err.code).toBe("INVALID_TRANSITION");
    }
  });

  test("invalid transition does NOT change machine state", () => {
    const sm = makeSm();
    try { sm.apply(scanCompleted()); } catch (_) { /* expected */ }
    expect(sm.state).toBe("IDLE");
  });
});

// ---------------------------------------------------------------------------
// ScanId mismatch — adversarial/replay attacks
// ---------------------------------------------------------------------------

describe("ScanId mismatch detection", () => {
  test("SCAN_COMPLETED with wrong scanId throws ScanIdMismatchError", () => {
    const sm = makeSm();
    sm.apply(scanStarted("original-scan"));
    expect(() => sm.apply(scanCompleted("different-scan"))).toThrow(ScanIdMismatchError);
  });

  test("SCAN_FAILED with wrong scanId throws ScanIdMismatchError", () => {
    const sm = makeSm();
    sm.apply(scanStarted("s1"));
    expect(() => sm.apply(scanFailed("evil-replay"))).toThrow(ScanIdMismatchError);
  });

  test("REPORT_DELIVERED with wrong scanId throws ScanIdMismatchError", () => {
    const sm = makeSm();
    sm.apply(scanStarted("s1"));
    sm.apply(scanCompleted("s1"));
    expect(() => sm.apply(reportDelivered("s2"))).toThrow(ScanIdMismatchError);
  });

  test("REPORT_FAILED with wrong scanId throws ScanIdMismatchError", () => {
    const sm = makeSm();
    sm.apply(scanStarted("s1"));
    sm.apply(scanCompleted("s1"));
    expect(() => sm.apply(reportFailed("s2"))).toThrow(ScanIdMismatchError);
  });

  test("ScanIdMismatchError carries expected/received values", () => {
    const sm = makeSm();
    sm.apply(scanStarted("the-real-scan"));
    try {
      sm.apply(scanCompleted("the-fake-scan"));
    } catch (e) {
      expect(e).toBeInstanceOf(ScanIdMismatchError);
      const err = e as ScanIdMismatchError;
      expect(err.expected).toBe("the-real-scan");
      expect(err.received).toBe("the-fake-scan");
      expect(err.code).toBe("SCAN_ID_MISMATCH");
    }
  });

  test("scanId mismatch does NOT change machine state", () => {
    const sm = makeSm();
    sm.apply(scanStarted("s1"));
    try { sm.apply(scanCompleted("evil")); } catch (_) { /* expected */ }
    expect(sm.state).toBe("SCANNING");
    expect(sm.activeScanId).toBe("s1");
  });
});

// ---------------------------------------------------------------------------
// Timestamp / clock-skew validation
// ---------------------------------------------------------------------------

describe("clock-skew timestamp violations", () => {
  test("event > maxClockSkewMs in the future throws TimestampViolationError", () => {
    const sm = makeSm({ maxClockSkewMs: 5_000, nowFn: () => NOW });
    expect(() =>
      sm.apply(scanStarted("s1", "/t", NOW + 10_000))
    ).toThrow(TimestampViolationError);
  });

  test("event > maxClockSkewMs in the past throws TimestampViolationError", () => {
    const sm = makeSm({ maxClockSkewMs: 5_000, nowFn: () => NOW });
    expect(() =>
      sm.apply(scanStarted("s1", "/t", NOW - 10_000))
    ).toThrow(TimestampViolationError);
  });

  test("event within clock-skew window is accepted", () => {
    const sm = makeSm({ maxClockSkewMs: 5_000, nowFn: () => NOW });
    expect(() =>
      sm.apply(scanStarted("s1", "/t", NOW + 3_000))
    ).not.toThrow();
  });

  test("TimestampViolationError carries correct fields", () => {
    const sm = makeSm({ maxClockSkewMs: 5_000, nowFn: () => NOW });
    try {
      sm.apply(scanStarted("s1", "/t", NOW + 99_000));
    } catch (e) {
      expect(e).toBeInstanceOf(TimestampViolationError);
      const err = e as TimestampViolationError;
      expect(err.eventTimestamp).toBe(NOW + 99_000);
      expect(err.machineTimestamp).toBe(NOW);
      expect(err.windowMs).toBe(5_000);
      expect(err.code).toBe("TIMESTAMP_VIOLATION");
    }
  });

  test("maxClockSkewMs=0 disables timestamp checking", () => {
    const sm = makeSm({ maxClockSkewMs: 0, nowFn: () => NOW });
    expect(() =>
      sm.apply(scanStarted("s1", "/t", NOW + 999_999_999))
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Machine shutdown
// ---------------------------------------------------------------------------

describe("machine shutdown", () => {
  test("apply() after shutdown throws StateMachineShutdownError", () => {
    const sm = makeSm();
    sm.shutdown();
    expect(() => sm.apply(scanStarted())).toThrow(StateMachineShutdownError);
  });

  test("tryApply() after shutdown returns shutdown error without throwing", () => {
    const sm = makeSm();
    sm.shutdown();
    const { record, error } = sm.tryApply(scanStarted());
    expect(record).toBeNull();
    expect(error).toBeInstanceOf(StateMachineShutdownError);
  });

  test("isShutdown is true after shutdown()", () => {
    const sm = makeSm();
    expect(sm.isShutdown).toBe(false);
    sm.shutdown();
    expect(sm.isShutdown).toBe(true);
  });

  test("shutdown error code is correct", () => {
    const sm = makeSm();
    sm.shutdown();
    try {
      sm.apply(scanStarted());
    } catch (e) {
      expect((e as StateMachineShutdownError).code).toBe("STATE_MACHINE_SHUTDOWN");
    }
  });
});

// ---------------------------------------------------------------------------
// tryApply (non-throwing API)
// ---------------------------------------------------------------------------

describe("tryApply non-throwing API", () => {
  test("valid transition returns { record, error: null }", () => {
    const sm = makeSm();
    const { record, error } = sm.tryApply(scanStarted("s1"));
    expect(error).toBeNull();
    expect(record).not.toBeNull();
    expect(record!.toState).toBe("SCANNING");
  });

  test("invalid transition returns { record: null, error }", () => {
    const sm = makeSm();
    const { record, error } = sm.tryApply(scanCompleted());
    expect(record).toBeNull();
    expect(error).toBeInstanceOf(InvalidTransitionError);
  });

  test("scan-id mismatch returns ScanIdMismatchError without throwing", () => {
    const sm = makeSm();
    sm.apply(scanStarted("real"));
    const { record, error } = sm.tryApply(scanCompleted("fake"));
    expect(record).toBeNull();
    expect(error).toBeInstanceOf(ScanIdMismatchError);
  });

  test("machine state is unchanged after tryApply with invalid event", () => {
    const sm = makeSm();
    sm.tryApply(scanCompleted());
    expect(sm.state).toBe("IDLE");
    expect(sm.transitionCount).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Observer / telemetry wiring
// ---------------------------------------------------------------------------

describe("observer callbacks", () => {
  test("observer called with null error on valid transition", () => {
    const obs = jest.fn<void, [TransitionRecord, StateMachineErrorUnion | null]>();
    const sm = makeSm({ observers: [obs] });
    sm.apply(scanStarted("s1"));
    expect(obs).toHaveBeenCalledTimes(1);
    const [record, error] = obs.mock.calls[0];
    expect(error).toBeNull();
    expect(record.toState).toBe("SCANNING");
  });

  test("observer called with typed error on invalid transition", () => {
    const obs = jest.fn<void, [TransitionRecord, StateMachineErrorUnion | null]>();
    const sm = makeSm({ observers: [obs] });
    try { sm.apply(scanCompleted()); } catch (_) { /* expected */ }
    expect(obs).toHaveBeenCalledTimes(1);
    const [, error] = obs.mock.calls[0];
    expect(error).toBeInstanceOf(InvalidTransitionError);
  });

  test("observer called on scanId mismatch", () => {
    const obs = jest.fn<void, [TransitionRecord, StateMachineErrorUnion | null]>();
    const sm = makeSm({ observers: [obs] });
    sm.apply(scanStarted("s1"));
    obs.mockClear();
    try { sm.apply(scanCompleted("wrong")); } catch (_) { /* expected */ }
    expect(obs).toHaveBeenCalledTimes(1);
    const [, error] = obs.mock.calls[0];
    expect(error).toBeInstanceOf(ScanIdMismatchError);
  });

  test("multiple observers all receive each event", () => {
    const obs1 = jest.fn();
    const obs2 = jest.fn();
    const sm = makeSm({ observers: [obs1, obs2] });
    sm.apply(scanStarted());
    expect(obs1).toHaveBeenCalledTimes(1);
    expect(obs2).toHaveBeenCalledTimes(1);
  });

  test("observer that throws does not crash the state machine", () => {
    const badObs: TransitionObserver = () => { throw new Error("observer bug"); };
    const sm = makeSm({ observers: [badObs] });
    // Should not propagate
    expect(() => sm.apply(scanStarted())).not.toThrow(Error);
    expect(sm.state).toBe("SCANNING");
  });

  test("observer sees record with correct fromState before transition completes", () => {
    const seen: ProtocolState[] = [];
    const obs: TransitionObserver = (r) => {
      seen.push(r.fromState);
    };
    const sm = makeSm({ observers: [obs] });
    sm.apply(scanStarted());
    sm.apply(scanCompleted());
    expect(seen).toEqual(["IDLE", "SCANNING"]);
  });
});

// ---------------------------------------------------------------------------
// Snapshot & hash chaining (ZK-readiness)
// ---------------------------------------------------------------------------

describe("snapshot and hash chaining", () => {
  test("initial snapshot has IDLE state and null scanId", () => {
    const sm = makeSm();
    const snap = sm.snapshot();
    expect(snap.state).toBe("IDLE");
    expect(snap.activeScanId).toBeNull();
    expect(snap.transitionCount).toBe(0);
  });

  test("snapshot hash changes on each transition", () => {
    const sm = makeSm();
    const h0 = sm.snapshot().snapshotHash;
    sm.apply(scanStarted());
    const h1 = sm.snapshot().snapshotHash;
    sm.apply(scanCompleted());
    const h2 = sm.snapshot().snapshotHash;
    expect(h0).not.toBe(h1);
    expect(h1).not.toBe(h2);
    expect(h0).not.toBe(h2);
  });

  test("snapshot hash in TransitionRecord matches machine snapshotHash after commit", () => {
    const sm = makeSm();
    const record = sm.apply(scanStarted());
    expect(record.snapshotHash).toBe(sm.snapshot().snapshotHash);
  });

  test("two identical event sequences produce identical hash chains", () => {
    const sm1 = makeSm();
    const sm2 = makeSm();
    sm1.apply(scanStarted("s1", "/t", NOW));
    sm2.apply(scanStarted("s1", "/t", NOW));
    expect(sm1.snapshot().snapshotHash).toBe(sm2.snapshot().snapshotHash);
  });

  test("different scanIds produce different hash chains", () => {
    const sm1 = makeSm();
    const sm2 = makeSm();
    sm1.apply(scanStarted("scan-A", "/t", NOW));
    sm2.apply(scanStarted("scan-B", "/t", NOW));
    expect(sm1.snapshot().snapshotHash).not.toBe(sm2.snapshot().snapshotHash);
  });
});

// ---------------------------------------------------------------------------
// History depth cap
// ---------------------------------------------------------------------------

describe("history depth cap", () => {
  test("history is capped at maxHistoryDepth", () => {
    const sm = makeSm({ maxHistoryDepth: 3 });
    // Each full cycle produces 3 transitions; we run 2 full cycles
    for (let i = 0; i < 2; i++) {
      sm.apply({ type: "SCAN_STARTED", scanId: `s${i}`, target: "/t", timestamp: NOW });
      sm.apply({ type: "SCAN_COMPLETED", scanId: `s${i}`, findingCount: 0, timestamp: NOW });
      sm.apply({ type: "REPORT_DELIVERED", scanId: `s${i}`, reportHash: "x", timestamp: NOW });
      sm.apply({ type: "RESET", requestedBy: "test", timestamp: NOW });
    }
    expect(sm.history.length).toBeLessThanOrEqual(3);
  });

  test("oldest entries are evicted first", () => {
    const sm = makeSm({ maxHistoryDepth: 2 });
    sm.apply(scanStarted("s1"));
    sm.apply(scanCompleted("s1"));
    sm.apply(reportDelivered("s1"));
    sm.apply(reset());
    // Should only have the last 2 records
    expect(sm.history.length).toBe(2);
    const seqs = sm.history.map((r) => r.seq);
    // seqs should be monotonically increasing
    expect(seqs[0]).toBeLessThan(seqs[1]);
  });
});

// ---------------------------------------------------------------------------
// Adversarial / fuzz-style inputs
// ---------------------------------------------------------------------------

describe("adversarial inputs", () => {
  test("empty scanId is accepted (no undefined checks — callers own that)", () => {
    const sm = makeSm();
    // Empty string is a valid string — state machine doesn't validate business logic
    expect(() => sm.apply(scanStarted("", "/t", NOW))).not.toThrow();
  });

  test("very long scanId does not crash", () => {
    const sm = makeSm();
    const longId = "x".repeat(10_000);
    expect(() => sm.apply(scanStarted(longId))).not.toThrow();
    expect(sm.activeScanId).toBe(longId);
  });

  test("repeated RESET calls are idempotent", () => {
    const sm = makeSm();
    sm.apply(reset());
    sm.apply(reset());
    sm.apply(reset());
    expect(sm.state).toBe("IDLE");
  });

  test("RESET after DONE resets to IDLE allowing a new scan", () => {
    const sm = makeSm();
    sm.apply(scanStarted("s1"));
    sm.apply(scanCompleted("s1"));
    sm.apply(reportDelivered("s1"));
    sm.apply(reset("operator"));
    expect(sm.state).toBe("IDLE");
    // Should now accept a new scan
    expect(() => sm.apply(scanStarted("s2"))).not.toThrow();
    expect(sm.state).toBe("SCANNING");
    expect(sm.activeScanId).toBe("s2");
  });

  test("interleaved SCAN_STARTED events from two scanIds — second is rejected", () => {
    const sm = makeSm();
    sm.apply(scanStarted("legitimate"));
    // Adversary tries to inject a different scan
    expect(() => sm.apply({ type: "SCAN_COMPLETED", scanId: "injected", findingCount: 0, timestamp: NOW }))
      .toThrow(ScanIdMismatchError);
    // Machine state is unchanged
    expect(sm.state).toBe("SCANNING");
    expect(sm.activeScanId).toBe("legitimate");
  });

  test("rapid-fire invalid events do not corrupt state", () => {
    const sm = makeSm();
    for (let i = 0; i < 100; i++) {
      try { sm.apply(scanCompleted(`scan-${i}`)); } catch (_) { /* expected */ }
    }
    expect(sm.state).toBe("IDLE");
    expect(sm.transitionCount).toBe(0);
  });

  test("report events in IDLE state all throw InvalidTransitionError", () => {
    const sm = makeSm();
    const events: ProtocolEvent[] = [
      { type: "SCAN_COMPLETED", scanId: "x", findingCount: 0, timestamp: NOW },
      { type: "SCAN_FAILED",    scanId: "x", reason: "err",  timestamp: NOW },
      { type: "REPORT_STARTED", scanId: "x",                 timestamp: NOW },
      { type: "REPORT_DELIVERED", scanId: "x", reportHash: "h", timestamp: NOW },
      { type: "REPORT_FAILED",  scanId: "x", reason: "err",  timestamp: NOW },
    ];
    for (const event of events) {
      expect(() => sm.apply(event)).toThrow(InvalidTransitionError);
      expect(sm.state).toBe("IDLE");
    }
  });

  test("SCAN_STARTED with future timestamp beyond skew window is rejected", () => {
    const sm = makeSm({ maxClockSkewMs: 1_000, nowFn: () => NOW });
    expect(() =>
      sm.apply(scanStarted("s1", "/t", NOW + 5_000))
    ).toThrow(TimestampViolationError);
    expect(sm.state).toBe("IDLE");
  });
});

// ---------------------------------------------------------------------------
// buildStateMachineAlert utility
// ---------------------------------------------------------------------------

describe("buildStateMachineAlert", () => {
  test("InvalidTransitionError produces HIGH severity alert", () => {
    const err = new InvalidTransitionError("IDLE", "SCAN_COMPLETED");
    const alert = buildStateMachineAlert(err);
    expect(alert.severity).toBe("HIGH");
    expect(alert.type).toBe("INVALID_TRANSITION");
    expect(alert.source).toBe("protocol-state-machine");
    expect(alert.message).toContain("INVALID_TRANSITION");
  });

  test("ScanIdMismatchError produces CRITICAL severity alert", () => {
    const err = new ScanIdMismatchError("expected", "received");
    const alert = buildStateMachineAlert(err);
    expect(alert.severity).toBe("CRITICAL");
    expect(alert.type).toBe("SCAN_ID_MISMATCH");
  });

  test("TimestampViolationError produces HIGH severity alert", () => {
    const err = new TimestampViolationError(NOW + 99_000, NOW, 5_000);
    const alert = buildStateMachineAlert(err);
    expect(alert.severity).toBe("HIGH");
    expect(alert.type).toBe("TIMESTAMP_VIOLATION");
  });

  test("StateMachineShutdownError produces MEDIUM severity alert", () => {
    const err = new StateMachineShutdownError();
    const alert = buildStateMachineAlert(err);
    expect(alert.severity).toBe("MEDIUM");
    expect(alert.type).toBe("STATE_MACHINE_SHUTDOWN");
  });

  test("InvariantViolationError produces CRITICAL severity alert", () => {
    const err = new InvariantViolationError("bad internal state");
    const alert = buildStateMachineAlert(err);
    expect(alert.severity).toBe("CRITICAL");
    expect(alert.type).toBe("INVARIANT_VIOLATION");
  });

  test("alert payload includes context metadata", () => {
    const err = new InvalidTransitionError("IDLE", "SCAN_COMPLETED");
    const alert = buildStateMachineAlert(err, { prNumber: 42 });
    expect(alert.metadata).toMatchObject({ prNumber: 42, errorName: "InvalidTransitionError" });
  });

  test("alert timestamp is a valid ISO string", () => {
    const err = new InvalidTransitionError("IDLE", "SCAN_COMPLETED");
    const alert = buildStateMachineAlert(err);
    expect(() => new Date(alert.timestamp)).not.toThrow();
    expect(typeof alert.timestamp).toBe("string");
  });
});

// ---------------------------------------------------------------------------
// createConsoleAlertObserver
// ---------------------------------------------------------------------------

describe("createConsoleAlertObserver", () => {
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleSpy = jest.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  test("logs to console.error on invalid transition", () => {
    const obs = createConsoleAlertObserver("[TEST]");
    const sm = makeSm({ observers: [obs] });
    try { sm.apply(scanCompleted()); } catch (_) { /* expected */ }
    expect(consoleSpy).toHaveBeenCalledTimes(1);
    expect(consoleSpy.mock.calls[0][0]).toContain("[TEST]");
  });

  test("does NOT log on valid transition", () => {
    const obs = createConsoleAlertObserver("[TEST]");
    const sm = makeSm({ observers: [obs] });
    sm.apply(scanStarted());
    expect(consoleSpy).not.toHaveBeenCalled();
  });

  test("uses default prefix when none supplied", () => {
    const obs = createConsoleAlertObserver();
    const sm = makeSm({ observers: [obs] });
    try { sm.apply(scanCompleted()); } catch (_) { /* expected */ }
    expect(consoleSpy.mock.calls[0][0]).toContain("[VAG-004]");
  });
});

// ---------------------------------------------------------------------------
// Error hierarchy / instanceof checks
// ---------------------------------------------------------------------------

describe("error hierarchy and prototype chain", () => {
  test("InvalidTransitionError instanceof Error", () => {
    expect(new InvalidTransitionError("IDLE", "SCAN_COMPLETED")).toBeInstanceOf(Error);
  });

  test("ScanIdMismatchError instanceof Error", () => {
    expect(new ScanIdMismatchError("a", "b")).toBeInstanceOf(Error);
  });

  test("TimestampViolationError instanceof Error", () => {
    expect(new TimestampViolationError(1, 2, 3)).toBeInstanceOf(Error);
  });

  test("StateMachineShutdownError instanceof Error", () => {
    expect(new StateMachineShutdownError()).toBeInstanceOf(Error);
  });

  test("InvariantViolationError instanceof Error", () => {
    expect(new InvariantViolationError("detail")).toBeInstanceOf(Error);
  });

  test("error names match class names", () => {
    expect(new InvalidTransitionError("IDLE", "SCAN_COMPLETED").name).toBe("InvalidTransitionError");
    expect(new ScanIdMismatchError("a", "b").name).toBe("ScanIdMismatchError");
    expect(new TimestampViolationError(1, 2, 3).name).toBe("TimestampViolationError");
    expect(new StateMachineShutdownError().name).toBe("StateMachineShutdownError");
    expect(new InvariantViolationError("x").name).toBe("InvariantViolationError");
  });
});

// ---------------------------------------------------------------------------
// Default options
// ---------------------------------------------------------------------------

describe("default constructor options", () => {
  test("machine with no options initialises to IDLE", () => {
    const sm = new ProtocolStateMachine();
    expect(sm.state).toBe("IDLE");
    expect(sm.activeScanId).toBeNull();
    expect(sm.transitionCount).toBe(0);
    expect(sm.isShutdown).toBe(false);
  });

  test("history getter returns a copy (mutations do not affect internal history)", () => {
    const sm = makeSm();
    sm.apply(scanStarted());
    const history = sm.history as TransitionRecord[];
    const originalLength = history.length;
    history.push({} as TransitionRecord); // mutate the copy
    expect(sm.history.length).toBe(originalLength);
  });
});
