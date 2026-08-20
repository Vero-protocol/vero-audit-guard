/**
 * Transaction Gas Profiling Simulation
 *
 * Simulates transaction gas usage to detect potential out-of-gas errors or
 * excessively expensive operations before they are submitted.
 *
 * Designed with Rust safety standards in mind: uses Result-like pattern,
 * exhaustive types, and avoids throwing exceptions for predictable errors.
 */

export type GasSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface GasProfileRequest {
  transactionId?: string;
  operations: Array<{
    type: string;
    payloadSize: number; // in bytes
    complexity?: "LOW" | "MEDIUM" | "HIGH";
  }>;
  signaturesCount: number;
}

export interface GasProfileResult {
  ok: boolean;
  totalGas: number;
  breakdown: {
    baseFee: number;
    signaturesFee: number;
    operationsFee: number;
    payloadFee: number;
  };
  severity: GasSeverity;
  warnings: string[];
  error?: string;
}

const GAS_CONSTANTS = {
  BASE_FEE: 100,
  FEE_PER_SIGNATURE: 500,
  FEE_PER_BYTE: 2,
  OP_COMPLEXITY_MULTIPLIER: {
    LOW: 100,
    MEDIUM: 500,
    HIGH: 2000,
  },
  MAX_GAS_LIMIT: 10_000_000,
};

export class GasProfiler {
  /**
   * Simulates gas usage for a given transaction request.
   * Returns a structured result instead of throwing.
   */
  public simulate(request: GasProfileRequest): GasProfileResult {
    if (!request || typeof request !== "object") {
      return this.createErrorResult("Invalid request: must be an object");
    }

    if (!request.operations || !Array.isArray(request.operations)) {
      return this.createErrorResult("Invalid request: operations must be an array");
    }

    if (typeof request.signaturesCount !== "number" || request.signaturesCount < 0) {
      return this.createErrorResult("Invalid request: signaturesCount must be a non-negative number");
    }

    let operationsFee = 0;
    let payloadFee = 0;

    for (const op of request.operations) {
      if (!op || typeof op !== "object") {
        return this.createErrorResult("Invalid operation: must be an object");
      }

      if (typeof op.payloadSize !== "number" || op.payloadSize < 0) {
        return this.createErrorResult("Invalid operation: payloadSize must be a non-negative number");
      }
      
      payloadFee += op.payloadSize * GAS_CONSTANTS.FEE_PER_BYTE;
      
      const complexity = op.complexity ?? "LOW";
      operationsFee += GAS_CONSTANTS.OP_COMPLEXITY_MULTIPLIER[complexity] || GAS_CONSTANTS.OP_COMPLEXITY_MULTIPLIER.LOW;
    }

    const signaturesFee = request.signaturesCount * GAS_CONSTANTS.FEE_PER_SIGNATURE;
    const baseFee = GAS_CONSTANTS.BASE_FEE;
    const totalGas = baseFee + signaturesFee + operationsFee + payloadFee;

    const warnings: string[] = [];
    let severity: GasSeverity = "LOW";

    if (totalGas > GAS_CONSTANTS.MAX_GAS_LIMIT) {
      severity = "CRITICAL";
      warnings.push(`Total gas (${totalGas}) exceeds maximum limit (${GAS_CONSTANTS.MAX_GAS_LIMIT})`);
    } else if (totalGas > GAS_CONSTANTS.MAX_GAS_LIMIT * 0.8) {
      severity = "HIGH";
      warnings.push("Total gas is dangerously close to the maximum limit (over 80%)");
    } else if (totalGas > GAS_CONSTANTS.MAX_GAS_LIMIT * 0.5) {
      severity = "MEDIUM";
      warnings.push("Total gas is moderately high (over 50% of limit)");
    }

    if (request.signaturesCount > 10) {
      warnings.push("High number of signatures detected, which increases transaction size and cost");
    }

    return {
      ok: true,
      totalGas,
      breakdown: {
        baseFee,
        signaturesFee,
        operationsFee,
        payloadFee,
      },
      severity,
      warnings,
    };
  }

  private createErrorResult(error: string): GasProfileResult {
    return {
      ok: false,
      totalGas: 0,
      breakdown: { baseFee: 0, signaturesFee: 0, operationsFee: 0, payloadFee: 0 },
      severity: "LOW",
      warnings: [],
      error,
    };
  }
}

export default GasProfiler;
