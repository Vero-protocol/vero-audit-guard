import * as http from "http";
import axios, { type AxiosResponse } from "axios";
import { createLocalBridgeHandler, startLocalServer } from "./local-server";

jest.mock("axios");

const mockedAxios = axios as jest.MockedFunction<typeof axios>;

function mockRpcResponse(data: unknown): void {
  const response: AxiosResponse = {
    data,
    status: 200,
    statusText: "OK",
    headers: {},
    config: {},
  };
  mockedAxios.mockResolvedValue(response);
}

function requestJson(
  port: number,
  path: string,
  token?: string
): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;

    http
      .get({ hostname: "127.0.0.1", port, path, headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk) => chunks.push(chunk as Buffer));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          resolve({ status: res.statusCode ?? 0, body: JSON.parse(raw) });
        });
      })
      .on("error", reject);
  });
}

describe("local-server", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.DISABLE_ATOMIC_VERIFICATION;
    jest.clearAllMocks();
  });

  afterEach(() => {
    process.env = originalEnv;
    jest.restoreAllMocks();
  });

  it("serves health and constant metrics", async () => {
    const server = startLocalServer({
      port: 0,
      host: "127.0.0.1",
      relayerAddress: "GTEST",
      initialNonce: 10,
      authToken: "test-token",
    });

    await new Promise<void>((resolve) => server.once("listening", () => resolve()));
    const address = server.address();
    if (!address || typeof address === "string") {
      server.close();
      throw new Error("expected TCP address");
    }

    try {
      const health = await requestJson(address.port, "/health");
      expect(health.status).toBe(200);
      expect(health.body).toMatchObject({ status: "ok", service: "atomic-rpc-relayer-bridge" });

      const first = await requestJson(address.port, "/metrics", "test-token");
      const second = await requestJson(address.port, "/metrics", "test-token");
      expect(first.status).toBe(200);
      expect(Array.isArray(first.body)).toBe(true);
      const firstMetrics = first.body as Array<{ address: string; nonce: number }>;
      const secondMetrics = second.body as Array<{ address: string; nonce: number }>;
      expect(firstMetrics[0].address).toBe("GTEST");
      expect(secondMetrics[0].nonce).toBe(firstMetrics[0].nonce);

      const missing = await requestJson(address.port, "/nope");
      expect(missing.status).toBe(404);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    }
  });

  it("rejects unauthenticated requests to metrics and audit-log", async () => {
    const server = startLocalServer({
      port: 0,
      host: "127.0.0.1",
      authToken: "secret",
    });

    await new Promise<void>((resolve) => server.once("listening", () => resolve()));
    const address = server.address();
    if (!address || typeof address === "string") {
      server.close();
      throw new Error("expected TCP address");
    }

    try {
      const metrics = await requestJson(address.port, "/metrics");
      expect(metrics.status).toBe(401);

      const audit = await requestJson(address.port, "/audit-log");
      expect(audit.status).toBe(401);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    }
  });

  it("builds a metrics payload without starting a listener", () => {
    const { getMetrics } = createLocalBridgeHandler({
      relayerAddress: "GFIXTURE",
      initialNonce: 42,
      initialFailedTxCount: 1,
    });
    const [row] = getMetrics();
    expect(row.address).toBe("GFIXTURE");
    expect(row.nonce).toBe(42);
    expect(row.failedTxCount).toBe(1);
  });

  it.each([
    ["unset", undefined],
    ["false", "false"],
  ])("enables atomic verification when the opt-out is %s", async (_case, flag) => {
    if (flag === undefined) {
      delete process.env.DISABLE_ATOMIC_VERIFICATION;
    } else {
      process.env.DISABLE_ATOMIC_VERIFICATION = flag;
    }
    mockRpcResponse({ ledger: 123 });
    const { getBridge } = createLocalBridgeHandler({
      endpoints: [
        { url: "https://primary.example", priority: 10 },
        { url: "https://secondary.example", priority: 5 },
      ],
    });

    const result = await getBridge().relay({
      id: "default-verification",
      method: "GET",
      endpoint: "/status",
      timestamp: Date.now(),
    });

    expect(result.success).toBe(true);
    expect(mockedAxios).toHaveBeenCalledTimes(2);
    expect(mockedAxios).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ url: "https://primary.example/status" })
    );
    expect(mockedAxios).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ url: "https://secondary.example/status" })
    );
  });

  it("requires an explicit opt-out and emits a security warning", async () => {
    process.env.DISABLE_ATOMIC_VERIFICATION = "true";
    const warning = jest.spyOn(console, "warn").mockImplementation(() => undefined);
    mockRpcResponse({ ledger: 123 });
    const { getBridge } = createLocalBridgeHandler({
      endpoints: [
        { url: "https://primary.example", priority: 10 },
        { url: "https://secondary.example", priority: 5 },
      ],
    });

    const result = await getBridge().relay({
      id: "explicit-opt-out",
      method: "GET",
      endpoint: "/status",
      timestamp: Date.now(),
    });

    expect(result.success).toBe(true);
    expect(mockedAxios).toHaveBeenCalledTimes(1);
    expect(mockedAxios).toHaveBeenCalledWith(
      expect.objectContaining({ url: "https://primary.example/status" })
    );
    expect(warning).toHaveBeenCalledWith(
      expect.stringContaining("atomic verification is disabled")
    );
  });

  it("rejects ambiguous atomic verification configuration", () => {
    process.env.DISABLE_ATOMIC_VERIFICATION = "yes";

    expect(() => createLocalBridgeHandler()).toThrow(
      'DISABLE_ATOMIC_VERIFICATION must be either "true" or "false"'
    );
  });
});
