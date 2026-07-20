export interface FeeOnTransferConfig {
  feeBps: number;
  feeCollector: string;
}

export interface FeeTransferResult {
  amount: bigint;
  fee: bigint;
  recipientAmount: bigint;
  senderBalanceAfter: bigint;
  feeCollector: string;
}

export type FeeErrorCode =
  | "INVALID_CONFIG"
  | "INVALID_AMOUNT"
  | "INSUFFICIENT_BALANCE";

export class FeeOnTransferError extends Error {
  public readonly code: FeeErrorCode;

  public constructor(code: FeeErrorCode, message: string) {
    super(message);
    this.name = "FeeOnTransferError";
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class ProtocolFeeOnTransfer {
  private readonly config: FeeOnTransferConfig;

  public constructor(config: FeeOnTransferConfig) {
    if (
      !config ||
      !Number.isInteger(config.feeBps) ||
      config.feeBps < 0 ||
      config.feeBps > 10_000 ||
      typeof config.feeCollector !== "string" ||
      config.feeCollector.trim().length === 0
    ) {
      throw new FeeOnTransferError(
        "INVALID_CONFIG",
        "feeBps must be an integer from 0 to 10000 and feeCollector must not be empty"
      );
    }

    this.config = {
      feeBps: config.feeBps,
      feeCollector: config.feeCollector.trim(),
    };
  }

  public calculate(amount: bigint | string, senderBalance: bigint | string): FeeTransferResult {
    const normalizedAmount = this.parseAmount(amount, "amount");
    const normalizedBalance = this.parseAmount(senderBalance, "sender balance");

    if (normalizedAmount === 0n) {
      throw new FeeOnTransferError("INVALID_AMOUNT", "amount must be greater than zero");
    }
    if (normalizedAmount > normalizedBalance) {
      throw new FeeOnTransferError(
        "INSUFFICIENT_BALANCE",
        "sender balance is insufficient for the transfer"
      );
    }

    const fee = (normalizedAmount * BigInt(this.config.feeBps)) / 10_000n;
    return {
      amount: normalizedAmount,
      fee,
      recipientAmount: normalizedAmount - fee,
      senderBalanceAfter: normalizedBalance - normalizedAmount,
      feeCollector: this.config.feeCollector,
    };
  }

  public getConfig(): FeeOnTransferConfig {
    return { ...this.config };
  }

  private parseAmount(value: bigint | string, label: string): bigint {
    if (typeof value === "bigint") {
      if (value < 0n) {
        throw new FeeOnTransferError("INVALID_AMOUNT", `${label} must not be negative`);
      }
      return value;
    }

    if (typeof value !== "string" || !/^\d+$/.test(value)) {
      throw new FeeOnTransferError(
        "INVALID_AMOUNT",
        `${label} must be a non-negative integer string or bigint`
      );
    }
    return BigInt(value);
  }
}

export default ProtocolFeeOnTransfer;
