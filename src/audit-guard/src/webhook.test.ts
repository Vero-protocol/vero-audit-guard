import * as fs from "fs";
import * as crypto from "crypto";
import { sendAlert } from "./webhook";

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
    fetchMock = jest.fn().mockResolvedValue(undefined);
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

    await sendAlert(payload);

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
  });
});
