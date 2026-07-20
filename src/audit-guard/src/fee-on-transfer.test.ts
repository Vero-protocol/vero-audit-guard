import ProtocolFeeOnTransfer, { FeeOnTransferError } from "./fee-on-transfer";

describe("ProtocolFeeOnTransfer", () => {
  const fee = () => new ProtocolFeeOnTransfer({ feeBps: 250, feeCollector: "treasury" });

  it("calculates fee, recipient credit, and sender debit exactly", () => {
    const result = fee().calculate("100000", "250000");

    expect(result).toEqual({
      amount: 100000n,
      fee: 2500n,
      recipientAmount: 97500n,
      senderBalanceAfter: 150000n,
      feeCollector: "treasury",
    });
    expect(result.recipientAmount + result.fee).toBe(result.amount);
  });

  it("rounds fractional base-unit fees down deterministically", () => {
    const result = fee().calculate(1n, 1n);
    expect(result.fee).toBe(0n);
    expect(result.recipientAmount).toBe(1n);
  });

  it("supports a zero-fee protocol configuration", () => {
    const result = new ProtocolFeeOnTransfer({ feeBps: 0, feeCollector: "treasury" })
      .calculate(500n, 500n);
    expect(result.fee).toBe(0n);
    expect(result.recipientAmount).toBe(500n);
    expect(result.senderBalanceAfter).toBe(0n);
  });

  it("rejects invalid configuration and amounts", () => {
    expect(() => new ProtocolFeeOnTransfer({ feeBps: 10_001, feeCollector: "treasury" }))
      .toThrow(FeeOnTransferError);
    expect(() => new ProtocolFeeOnTransfer({ feeBps: 10, feeCollector: "" }))
      .toThrow("feeCollector must not be empty");
    expect(() => fee().calculate(0n, 100n)).toThrow("amount must be greater than zero");
    expect(() => fee().calculate(-1n, 100n)).toThrow("must not be negative");
    expect(() => fee().calculate("1.5", "100")).toThrow("integer string or bigint");
  });

  it("rejects transfers larger than the sender balance", () => {
    expect(() => fee().calculate(101n, 100n)).toThrow(
      "sender balance is insufficient"
    );
  });

  it("does not mutate configuration after construction", () => {
    const processor = fee();
    const config = processor.getConfig();
    config.feeBps = 10_000;

    expect(processor.calculate(1000n, 1000n).fee).toBe(25n);
  });
});
