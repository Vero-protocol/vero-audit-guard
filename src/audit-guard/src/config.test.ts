describe("audit-guard configuration", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv, NODE_ENV: "test" };
    delete process.env.AUDIT_GUARD_WEBHOOK_URL;
    delete process.env.AUDIT_GUARD_WEBHOOK_TOKEN;
    delete process.env.ONCALL_CONTACTS;
    delete process.env.ONCALL_ROTATION_INTERVAL;
    delete process.env.ONCALL_PAGE_WEBHOOK_URL;
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("uses safe defaults when optional values are absent", async () => {
    const config = await import("./config");

    expect(config.WEBHOOK_URL).toBe("");
    expect(config.WEBHOOK_TOKEN).toBe("");
    expect(config.ONCALL_CONTACTS).toBe("");
    expect(config.ONCALL_ROTATION_INTERVAL).toBe("weekly");
    expect(config.ONCALL_PAGE_WEBHOOK_URL).toBe("");
  });

  it("loads configured values and falls back to the primary webhook", async () => {
    process.env.AUDIT_GUARD_WEBHOOK_URL = "https://audit.example/webhook";
    process.env.AUDIT_GUARD_WEBHOOK_TOKEN = "secret-token";
    process.env.ONCALL_CONTACTS = '[{"name":"Primary","email":"primary@example.com","role":"PRIMARY"}]';
    process.env.ONCALL_ROTATION_INTERVAL = "daily";

    const config = await import("./config");

    expect(config.WEBHOOK_URL).toBe("https://audit.example/webhook");
    expect(config.WEBHOOK_TOKEN).toBe("secret-token");
    expect(config.ONCALL_CONTACTS).toContain("primary@example.com");
    expect(config.ONCALL_ROTATION_INTERVAL).toBe("daily");
    expect(config.ONCALL_PAGE_WEBHOOK_URL).toBe("https://audit.example/webhook");
  });

  it("preserves an explicit page webhook URL", async () => {
    process.env.AUDIT_GUARD_WEBHOOK_URL = "https://audit.example/webhook";
    process.env.ONCALL_PAGE_WEBHOOK_URL = "https://pager.example/webhook";

    const config = await import("./config");

    expect(config.ONCALL_PAGE_WEBHOOK_URL).toBe("https://pager.example/webhook");
  });

  it.each(["hourly", "monthly", "", "DAILY"]) (
    "falls back to weekly for invalid rotation interval %s",
    async (value) => {
      process.env.ONCALL_ROTATION_INTERVAL = value;

      const config = await import("./config");

      expect(config.ONCALL_ROTATION_INTERVAL).toBe("weekly");
    }
  );
});
