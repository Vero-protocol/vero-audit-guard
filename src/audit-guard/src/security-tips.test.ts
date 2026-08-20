import { SECURITY_TIPS, SecurityTip } from "./security-tips";

describe("security-tips", () => {
  it("exports a non-empty array of security tips", () => {
    expect(Array.isArray(SECURITY_TIPS)).toBe(true);
    expect(SECURITY_TIPS.length).toBeGreaterThan(0);
  });

  it("contains tips with valid structures", () => {
    SECURITY_TIPS.forEach((tip: SecurityTip) => {
      expect(typeof tip.id).toBe("string");
      expect(typeof tip.title).toBe("string");
      expect(typeof tip.content).toBe("string");
      expect(tip.id.startsWith("SEC_TIP_")).toBe(true);
    });
  });
  
  it("contains specific representative tips", () => {
    const tipIds = SECURITY_TIPS.map(tip => tip.id);
    expect(tipIds).toContain("SEC_TIP_SECRET_MGMT");
    expect(tipIds).toContain("SEC_TIP_DEP_SECURITY");
    expect(tipIds).toContain("SEC_TIP_INPUT_VAL");
  });
});
