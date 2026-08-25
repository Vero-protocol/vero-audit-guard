import * as fs from "fs";
import * as crypto from "crypto";
import {
  sendAlert,
  WebhookNon2xxResponseError,
  WebhookTimeoutError,
  WebhookNetworkError,
} from "./webhook";

jest.mock("fs", () => ({
  promises: {
    mkdir: jest.fn().mockResolvedValue(undefined),
    appendFile: jest.fn().mockResolvedValue(undefined),
  },
}));

jest.mock("./config", () => ({
  WEBHOOK_URL: "http://example.com/webhook",
  WEBHOOK_TOKEN: "test-secret-token",
}));

describe("webhook sendAlert", () => {
  let fetchMock: jest.Mock;

  beforeEach(() => {
    fetchMock = jest.fn().mockResolvedValue({ status: 200, ok: true });
    (globalThis as any).fetch = fetchMock;
    jest.clearAllMocks();
  });

  afterEach(() => {
    delete (globalThis as any).fetch;
  });

  it("should append HMAC-SHA256 signature to headers when WEBHOOK_TOKEN is present", async () => {
    const payload = {
      repository: "test-repo",
      alert: "test-alert",
      timestamp: "2023-01-01T00:00:00Z",
    };

    const result = await sendAlert(payload);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, options] = fetchMock.mock.calls[0];
    
    expect(url).toBe("http://example.com/webhook");
    expect(options.method).toBe("POST");
    
    const headers = options.headers;
    expect(headers["Authorization"]).toBe("Bearer test-secret-token");
    
    // Verify HMAC
    const expectedPayloadStr = JSON.stringify(payload);
    const hmac = crypto.createHmac("sha256", Buffer.from("test-secret-token", "utf-8"));
    hmac.update(expectedPayloadStr, "utf-8");
    const expectedSignature = `sha256=${hmac.digest("hex")}`;
    
    expect(headers["X-Vero-Signature"]).toBe(expectedSignature);
    expect(options.body).toBe(expectedPayloadStr);
    
    // Verify result
    expect(result.delivered).toBe(true);
    expect(result.status).toBe(200);
    expect(result.error).toBeUndefined();
    expect(result.attemptedAt).toBeDefined();
  });

  it("should return failure result for non-2xx response", async () => {
    fetchMock.mockResolvedValue({ status: 500, ok: false });

    const payload = {
      repository: "test-repo",
      alert: "test-alert",
      timestamp: "2023-01-01T00:00:00Z",
    };

    const result = await sendAlert(payload);

    expect(result.delivered).toBe(false);
    expect(result.status).toBe(500);
    expect(result.error).toBeInstanceOf(WebhookNon2xxResponseError);
    expect((result.error as WebhookNon2xxResponseError).httpStatus).toBe(500);
    expect(result.attemptedAt).toBeDefined();
  });

  it("should return failure result for timeout", async () => {
    // Mock fetch to capture the AbortSignal and trigger abort
    fetchMock.mockImplementation(
      (_url: string, init: { signal?: AbortSignal }) => {
        return new Promise((_, reject) => {
          if (init.signal) {
            init.signal.addEventListener("abort", () => {
              reject(new DOMException("The operation was aborted.", "AbortError"));
            });
          }
        });
      }
    );

    const payload = {
      repository: "test-repo",
      alert: "test-alert",
      timestamp: "2023-01-01T00:00:00Z",
    };

    // Use a short timeout - the AbortController will fire and reject the promise
    const result = await sendAlert(payload, { timeoutMs: 100 });

    expect(result.delivered).toBe(false);
    expect(result.status).toBe("TIMEOUT");
    expect(result.error).toBeInstanceOf(WebhookTimeoutError);
    expect((result.error as WebhookTimeoutError).timeoutMs).toBe(100);
    expect(result.attemptedAt).toBeDefined();
  }, 10000);

  it("should return failure result for network error", async () => {
    fetchMock.mockRejectedValue(new Error("Network connection failed"));

    const payload = {
      repository: "test-repo",
      alert: "test-alert",
      timestamp: "2023-01-01T00:00:00Z",
    };

    const result = await sendAlert(payload);

    expect(result.delivered).toBe(false);
    expect(result.status).toBe("NETWORK_ERROR");
    expect(result.error).toBeInstanceOf(WebhookNetworkError);
    expect(result.error?.cause).toBeInstanceOf(Error);
    expect(result.attemptedAt).toBeDefined();
  });

  it("should log every attempt with delivery outcome", async () => {
    const payload = {
      repository: "test-repo",
      alert: "test-alert",
      timestamp: "2023-01-01T00:00:00Z",
    };

    await sendAlert(payload);

    expect(fs.promises.appendFile).toHaveBeenCalledTimes(1);
    const [logPath, logContent] = (fs.promises.appendFile as jest.Mock).mock.calls[0];
    
    expect(logPath).toContain("relay-events.log");
    const logEntry = JSON.parse(logContent);
    expect(logEntry.repository).toBe("test-repo");
    expect(logEntry.alert).toBe("test-alert");
    expect(logEntry._delivery).toBeDefined();
    expect(logEntry._delivery.delivered).toBe(true);
    expect(logEntry._delivery.status).toBe(200);
    expect(logEntry._delivery.attemptedAt).toBeDefined();
  });

  it("should log failed attempts with delivery outcome", async () => {
    fetchMock.mockResolvedValue({ status: 403, ok: false });

    const payload = {
      repository: "test-repo",
      alert: "test-alert",
      timestamp: "2023-01-01T00:00:00Z",
    };

    await sendAlert(payload);

    expect(fs.promises.appendFile).toHaveBeenCalledTimes(1);
    const [logPath, logContent] = (fs.promises.appendFile as jest.Mock).mock.calls[0];
    
    expect(logPath).toContain("relay-events.log");
    const logEntry = JSON.parse(logContent);
    expect(logEntry._delivery).toBeDefined();
    expect(logEntry._delivery.delivered).toBe(false);
    expect(logEntry._delivery.status).toBe(403);
    expect(logEntry._delivery.attemptedAt).toBeDefined();
  });

  it("should include AbortSignal in fetch call for timeout", async () => {
    const payload = {
      repository: "test-repo",
      alert: "test-alert",
      timestamp: "2023-01-01T00:00:00Z",
    };

    await sendAlert(payload);

    const [, options] = fetchMock.mock.calls[0];
    expect(options.signal).toBeInstanceOf(AbortSignal);
  });
});
