import * as fs from "fs";
import * as path from "path";
import { sendAlert, AlertPayload } from "./webhook";
import * as config from "./config";

describe("webhook module", () => {
  const logDir = path.join(__dirname, "..", "logs");
  const logFile = path.join(logDir, "relay-events.log");

  let originalFetch: any;

  beforeEach(async () => {
    originalFetch = (globalThis as any).fetch;
    try {
      await fs.promises.unlink(logFile);
    } catch {
      // Ignore if file doesn't exist
    }
  });

  afterEach(() => {
    (globalThis as any).fetch = originalFetch;
  });

  afterAll(async () => {
    try {
      await fs.promises.unlink(logFile);
    } catch {
      // Ignore cleanup error
    }
  });

  it("should do nothing when WEBHOOK_URL is not configured", async () => {
    const mockFetch = jest.fn();
    (globalThis as any).fetch = mockFetch;
    (config as any).WEBHOOK_URL = "";

    const payload: AlertPayload = {
      repository: "test/repo",
      alert: "High severity finding",
      timestamp: new Date().toISOString(),
    };

    await sendAlert(payload);

    expect(mockFetch).not.toHaveBeenCalled();
    expect(fs.existsSync(logFile)).toBe(false);
  });

  it("should deliver webhook payload and log to relay-events.log", async () => {
    const mockFetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
    });
    (globalThis as any).fetch = mockFetch;
    (config as any).WEBHOOK_URL = "https://webhook.example.com/alerts";
    (config as any).WEBHOOK_TOKEN = "test-token-123";

    const payload: AlertPayload = {
      repository: "vero-protocol/audit-guard",
      alert: "Critical vulnerability detected",
      timestamp: "2026-08-19T12:00:00.000Z",
    };

    await sendAlert(payload);

    expect(mockFetch).toHaveBeenCalledWith(
      "https://webhook.example.com/alerts",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          Authorization: "Bearer test-token-123",
        }),
        body: JSON.stringify(payload),
      })
    );

    expect(fs.existsSync(logFile)).toBe(true);
    const content = await fs.promises.readFile(logFile, "utf-8");
    const logged = JSON.parse(content.trim());
    expect(logged.repository).toBe(payload.repository);
    expect(logged.alert).toBe(payload.alert);
  });

  it("should catch and log errors without crashing when fetch fails", async () => {
    const consoleSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    (globalThis as any).fetch = jest.fn().mockRejectedValue(new Error("Network connection error"));
    (config as any).WEBHOOK_URL = "https://webhook.example.com/alerts";

    const payload: AlertPayload = {
      repository: "test/repo",
      alert: "Test alert",
      timestamp: new Date().toISOString(),
    };

    await expect(sendAlert(payload)).resolves.not.toThrow();
    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});
