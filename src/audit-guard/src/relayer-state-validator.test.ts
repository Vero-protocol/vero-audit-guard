import RelayerStateValidator, {
  RelayerAccountState,
  ChainAccountState,
  PendingTransactionRecord
} from "../src/relayer-state-validator";

describe("RelayerStateValidator", () => {
  let validator: RelayerStateValidator;

  beforeEach(() => {
    validator = new RelayerStateValidator({
      maxAllowedSequenceDrift: 5,
      balanceToleranceAmount: 0.001,
      maxPendingTxStallSeconds: 300
    });
  });

  it("should report IN_SYNC when relayer and chain states match perfectly", () => {
    const relayerStates: RelayerAccountState[] = [
      { accountId: "G_RELAYER_1", sequenceNumber: 100, balance: "1000.50", pendingTxCount: 0, lastUpdatedTimestamp: Date.now() }
    ];
    const chainStates: ChainAccountState[] = [
      { accountId: "G_RELAYER_1", sequenceNumber: 100, balance: "1000.50", latestLedgerNumber: 123456, authoritativeTimestamp: Date.now() }
    ];

    const result = validator.reconcile(relayerStates, chainStates);
    expect(result.status).toBe("IN_SYNC");
    expect(result.discrepancies).toHaveLength(0);
  });

  it("should report CRITICAL_DESYNC when relayer sequence is behind chain sequence", () => {
    const relayerStates: RelayerAccountState[] = [
      { accountId: "G_RELAYER_1", sequenceNumber: 95, balance: "500", pendingTxCount: 0, lastUpdatedTimestamp: Date.now() }
    ];
    const chainStates: ChainAccountState[] = [
      { accountId: "G_RELAYER_1", sequenceNumber: 100, balance: "500", latestLedgerNumber: 123456, authoritativeTimestamp: Date.now() }
    ];

    const result = validator.reconcile(relayerStates, chainStates);
    expect(result.status).toBe("CRITICAL_DESYNC");
    expect(result.discrepancies).toHaveLength(1);
    expect(result.discrepancies[0].type).toBe("SEQUENCE_DRIFT");
    expect(result.discrepancies[0].severity).toBe("CRITICAL");
  });

  it("should report DRIFT_DETECTED when relayer sequence exceeds max drift threshold", () => {
    const relayerStates: RelayerAccountState[] = [
      { accountId: "G_RELAYER_1", sequenceNumber: 110, balance: "500", pendingTxCount: 5, lastUpdatedTimestamp: Date.now() }
    ];
    const chainStates: ChainAccountState[] = [
      { accountId: "G_RELAYER_1", sequenceNumber: 100, balance: "500", latestLedgerNumber: 123456, authoritativeTimestamp: Date.now() }
    ];

    const result = validator.reconcile(relayerStates, chainStates);
    expect(result.status).toBe("DRIFT_DETECTED");
    expect(result.discrepancies).toHaveLength(1);
    expect(result.discrepancies[0].type).toBe("SEQUENCE_DRIFT");
    expect(result.discrepancies[0].severity).toBe("MEDIUM");
  });

  it("should detect balance discrepancies exceeding tolerance", () => {
    const relayerStates: RelayerAccountState[] = [
      { accountId: "G_RELAYER_1", sequenceNumber: 100, balance: "1050.00", pendingTxCount: 0, lastUpdatedTimestamp: Date.now() }
    ];
    const chainStates: ChainAccountState[] = [
      { accountId: "G_RELAYER_1", sequenceNumber: 100, balance: "1000.00", latestLedgerNumber: 123456, authoritativeTimestamp: Date.now() }
    ];

    const result = validator.reconcile(relayerStates, chainStates);
    expect(result.status).toBe("CRITICAL_DESYNC");
    expect(result.discrepancies).toHaveLength(1);
    expect(result.discrepancies[0].type).toBe("BALANCE_DISCREPANCY");
  });

  it("should detect stalled pending transactions", () => {
    const now = 1700000000000;
    const pendingTxs: PendingTransactionRecord[] = [
      { txHash: "0x123abc", submittedSequence: 101, submittedTimestamp: now - 600000, status: "PENDING" }
    ];

    const result = validator.reconcile([], [], pendingTxs, now);
    expect(result.status).toBe("DRIFT_DETECTED");
    expect(result.discrepancies).toHaveLength(1);
    expect(result.discrepancies[0].type).toBe("STALLED_TRANSACTION");
  });

  it("should generate clean markdown report", () => {
    const relayerStates: RelayerAccountState[] = [
      { accountId: "G_RELAYER_1", sequenceNumber: 90, balance: "500", pendingTxCount: 0, lastUpdatedTimestamp: Date.now() }
    ];
    const chainStates: ChainAccountState[] = [
      { accountId: "G_RELAYER_1", sequenceNumber: 100, balance: "500", latestLedgerNumber: 123456, authoritativeTimestamp: Date.now() }
    ];

    const result = validator.reconcile(relayerStates, chainStates);
    const report = validator.generateReport(result);
    expect(report).toContain("Relayer State vs Chain State Reconciliation Report");
    expect(report).toContain("CRITICAL_DESYNC");
    expect(report).toContain("SEQ_DESYNC_G_RELAYER_1");
  });
});
