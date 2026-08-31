import { SECURITY_TIPS, SecurityTip } from "./security-tips";

describe("SECURITY_TIPS", () => {
  it("contains security tips with the required fields", () => {
    expect(SECURITY_TIPS.length).toBeGreaterThan(0);

    SECURITY_TIPS.forEach((tip: SecurityTip) => {
      expect(tip.id).toEqual(expect.any(String));
      expect(tip.title).toEqual(expect.any(String));
      expect(tip.content).toEqual(expect.any(String));

      expect(tip.id.length).toBeGreaterThan(0);
      expect(tip.title.length).toBeGreaterThan(0);
      expect(tip.content.length).toBeGreaterThan(0);
    });
  });

  it("contains unique security tip IDs", () => {
    const ids = SECURITY_TIPS.map((tip) => tip.id);

    expect(new Set(ids).size).toBe(ids.length);
  });

  it("includes representative security guidance", () => {
    const titles = SECURITY_TIPS.map((tip) => tip.title);

    expect(titles).toContain("Secret Management");
    expect(titles).toContain("Dependency Security");
    expect(titles).toContain("Input Validation");
    expect(titles).toContain("Principle of Least Privilege");
    expect(titles).toContain("Secure Communication");
  });

  it("provides meaningful content for representative security tips", () => {
    const secretManagement = SECURITY_TIPS.find(
      (tip) => tip.id === "SEC_TTP_SECRET_MGMT",
    );

    const inputValidation = SECURITY_TIPS.find(
      (tip) => tip.id === "SEC_TTP_INPUT_VAL",
    );

    const secureCommunication = SECURITY_TIPS.find(
      (tip) => tip.id === "SEC_TTP_SEC_COMM",
    );

    expect(secretManagement?.content).toMatch(/secrets|private keys/i);
    expect(inputValidation?.content).toMatch(/validate|sanitize/i);
    expect(secureCommunication?.content).toMatch(/HTTPS|SSL\/TLS/i);
  });
});
