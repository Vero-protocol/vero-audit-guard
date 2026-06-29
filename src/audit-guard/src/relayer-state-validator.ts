/**
 * Relayer State Validator
 *
 * Issue #119: Validate relayer state vs chain state
 *
 * Standardizes security protocols and improves system resilience against vulnerabilities
 * by comparing local relayer transaction/account state against authoritative on-chain state.
 * Performs periodic reconciliation checks for sequence drift, balance discrepancies, and stalled transactions.
 */

export type RelayerStateSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface RelayerAccountState {
  accountId: string;
  sequenceNumber: number | bigint;
  balance: string | number;
  pendingTxCount: number;
  lastUpdatedTimestamp: number;
}

export interface ChainAccountState {
  accountId: string;
  sequenceNumber: number | bigint;
  balance: string | number;
  latestLedgerNumber: number;
  authoritativeTimestamp: number;
}

export interface PendingTransactionRecord {
  txHash: string;
  submittedSequence: number | bigint;
  submittedTimestamp: number;
  status: "PENDING" | "CONFIRMED" | "FAILED";
}

export interface RelayerStateDiscrepancy {
  checkId: string;
  type: "SEQUENCE_DRIFT" | "BALANCE_DISCREPANCY" | "STALLED_TRANSACTION" | "UNAUTHORIZED_STATE_CHANGE";
  severity: RelayerStateSeverity;
  accountId: string;
  message: string;
  relayerValue?: string | number | bigint;
  chainValue?: string | number | bigint;
  remediation: string;
}

export interface RelayerReconciliationResult {
  status: "IN_SYNC" | "DRIFT_DETECTED" | "CRITICAL_DESYNC";
  discrepancies: RelayerStateDiscrepancy[];
  totalCheckedAccounts: number;
  reconciliationTimestamp: string;
  summary: string;
}

export interface RelayerValidatorOptions {
  maxAllowedSequenceDrift?: number;
  balanceToleranceAmount?: number;
  maxPendingTxStallSeconds?: number;
}

export class RelayerStateValidator {
  private readonly maxAllowedSequenceDrift: number;
  private readonly balanceToleranceAmount: number;
  private readonly maxPendingTxStallSeconds: number;

  constructor(options: RelayerValidatorOptions = {}) {
    this.maxAllowedSequenceDrift = options.maxAllowedSequenceDrift ?? 5;
    this.balanceToleranceAmount = options.balanceToleranceAmount ?? 0.0001;
    this.maxPendingTxStallSeconds = options.maxPendingTxStallSeconds ?? 300;
  }

  /**
   * Validates relayer local states against verified on-chain account states.
   */
  public reconcile(
    relayerStates: RelayerAccountState[],
    chainStates: ChainAccountState[],
    pendingTxs: PendingTransactionRecord[] = [],
    currentTime: number = Date.now()
  ): RelayerReconciliationResult {
    const discrepancies: RelayerStateDiscrepancy[] = [];
    const chainStateMap = new Map<string, ChainAccountState>();

    for (const cs of chainStates) {
      chainStateMap.set(cs.accountId, cs);
    }

    for (const rs of relayerStates) {
      const cs = chainStateMap.get(rs.accountId);
      if (!cs) {
        discrepancies.push({
          checkId: `MISSING_CHAIN_STATE_${rs.accountId}`,
          type: "UNAUTHORIZED_STATE_CHANGE",
          severity: "HIGH",
          accountId: rs.accountId,
          message: `Relayer tracks account ${rs.accountId} but authoritative chain state is missing or unverified.`,
          relayerValue: rs.accountId,
          remediation: "Verify relayer configuration and ensure account is properly registered on-chain."
        });
        continue;
      }

      // Check Sequence Number Drift
      const relayerSeq = BigInt(rs.sequenceNumber);
      const chainSeq = BigInt(cs.sequenceNumber);

      if (relayerSeq < chainSeq) {
        discrepancies.push({
          checkId: `SEQ_DESYNC_${rs.accountId}`,
          type: "SEQUENCE_DRIFT",
          severity: "CRITICAL",
          accountId: rs.accountId,
          message: `Relayer sequence number (${relayerSeq}) is behind chain authoritative sequence (${chainSeq}). Potential state desync or rollback vulnerability.`,
          relayerValue: relayerSeq,
          chainValue: chainSeq,
          remediation: "Immediately force-resync relayer sequence number from authoritative chain state."
        });
      } else if (relayerSeq > chainSeq + BigInt(this.maxAllowedSequenceDrift)) {
        discrepancies.push({
          checkId: `SEQ_DRIFT_${rs.accountId}`,
          type: "SEQUENCE_DRIFT",
          severity: "MEDIUM",
          accountId: rs.accountId,
          message: `Relayer sequence number exceeds chain sequence by more than allowed threshold (${this.maxAllowedSequenceDrift}).`,
          relayerValue: relayerSeq,
          chainValue: chainSeq,
          remediation: "Check transaction submission pipeline for network congestion or dropped transactions."
        });
      }

      // Check Balance Discrepancies
      const relayerBal = Number(rs.balance);
      const chainBal = Number(cs.balance);
      const balDiff = Math.abs(relayerBal - chainBal);

      if (balDiff > this.balanceToleranceAmount) {
        const severity: RelayerStateSeverity = balDiff > 100 ? "CRITICAL" : "HIGH";
        discrepancies.push({
          checkId: `BAL_DISCREPANCY_${rs.accountId}`,
          type: "BALANCE_DISCREPANCY",
          severity,
          accountId: rs.accountId,
          message: `Relayer recorded balance (${relayerBal}) diverges from chain balance (${chainBal}) beyond tolerance (${this.balanceToleranceAmount}).`,
          relayerValue: relayerBal,
          chainValue: chainBal,
          remediation: "Audit recent outgoing transactions and reconcile ledger balance changes."
        });
      }
    }

    // Check Stalled Pending Transactions
    for (const tx of pendingTxs) {
      if (tx.status === "PENDING") {
        const stallDuration = (currentTime - tx.submittedTimestamp) / 1000;
        if (stallDuration > this.maxPendingTxStallSeconds) {
          discrepancies.push({
            checkId: `STALLED_TX_${tx.txHash}`,
            type: "STALLED_TRANSACTION",
            severity: "MEDIUM",
            accountId: "GLOBAL",
            message: `Transaction ${tx.txHash} has been pending for ${Math.round(stallDuration)}s, exceeding max stall duration (${this.maxPendingTxStallSeconds}s).`,
            relayerValue: `${Math.round(stallDuration)}s`,
            remediation: "Resubmit transaction with higher fee replacement or mark transaction as dropped."
          });
        }
      }
    }

    // Determine overall status
    let status: RelayerReconciliationResult["status"] = "IN_SYNC";
    const hasCriticalOrHigh = discrepancies.some(d => d.severity === "CRITICAL" || d.severity === "HIGH");
    
    if (hasCriticalOrHigh) {
      status = "CRITICAL_DESYNC";
    } else if (discrepancies.length > 0) {
      status = "DRIFT_DETECTED";
    }

    const summary = status === "IN_SYNC"
      ? `✅ Relayer state reconciled successfully across ${relayerStates.length} account(s). No state drift detected.`
      : `⚠️ Detected ${discrepancies.length} discrepancy(ies) during relayer state reconciliation across ${relayerStates.length} account(s). Status: ${status}`;

    return {
      status,
      discrepancies,
      totalCheckedAccounts: relayerStates.length,
      reconciliationTimestamp: new Date().toISOString(),
      summary
    };
  }

  /**
   * Generates a structured markdown audit report from a reconciliation result.
   */
  public generateReport(result: RelayerReconciliationResult): string {
    const icon = result.status === "IN_SYNC" ? "✅" : result.status === "CRITICAL_DESYNC" ? "🚨" : "⚠️";
    let report = `## ${icon} Relayer State vs Chain State Reconciliation Report\n\n`;
    report += `**Status:** \`${result.status}\`\n\n`;
    report += `**Reconciled at:** ${result.reconciliationTimestamp}\n\n`;
    report += `**Accounts Checked:** ${result.totalCheckedAccounts} | **Discrepancies:** ${result.discrepancies.length}\n\n`;
    report += `${result.summary}\n\n`;

    if (result.discrepancies.length === 0) {
      return report;
    }

    report += "---\n\n### Discrepancy Findings\n\n";

    for (const d of result.discrepancies) {
      report += `#### [${d.severity}] ${d.type} (${d.checkId})\n`;
      report += `- **Account / Target:** \`${d.accountId}\`\n`;
      report += `- **Message:** ${d.message}\n`;
      if (d.relayerValue !== undefined && d.chainValue !== undefined) {
        report += `- **Relayer State:** \`${d.relayerValue}\` | **Chain State:** \`${d.chainValue}\`\n`;
      } else if (d.relayerValue !== undefined) {
        report += `- **Observed Value:** \`${d.relayerValue}\`\n`;
      }
      report += `- **Remediation:** ${d.remediation}\n\n`;
    }

    return report;
  }
}

export default RelayerStateValidator;
