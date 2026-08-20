import * as http from "http";
import { createLocalBridgeHandler, startLocalServer } from "./local-server";

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
});
