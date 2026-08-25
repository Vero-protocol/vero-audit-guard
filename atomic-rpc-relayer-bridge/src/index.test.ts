import axios from "axios";
import { AtomicRpcRelayerBridge, type BridgeEndpoint, type BridgeRequest } from "./index";

jest.mock("axios");

const mockedAxios = axios as jest.MockedFunction<typeof axios>;

function createRequest(
  endpoint: string,
  overrides: Partial<BridgeRequest> = {}
): BridgeRequest {
  return {
    id: `request-${endpoint}`,
    method: "GET",
    endpoint,
    timestamp: Date.now(),
    ...overrides
  };
}

function response(data: unknown): { data: unknown } {
  return { data };
}

describe("AtomicRpcRelayerBridge", () => {
  let bridge: AtomicRpcRelayerBridge;
  const testEndpoints: BridgeEndpoint[] = [
    { url: "http://localhost:8545", priority: 10 }
  ];

  beforeEach(() => {
    jest.clearAllMocks();
    bridge = new AtomicRpcRelayerBridge({
      endpoints: testEndpoints,
      maxRetries: 1,
      requireAtomicVerification: false
    });
  });

  test("should initialize with endpoints", () => {
    expect(bridge).toBeDefined();
  });

  test("should return audit log", () => {
    const log = bridge.getAuditLog();
    expect(Array.isArray(log)).toBe(true);
    expect(log.length).toBe(0);
  });

  test("should clear audit log", () => {
    bridge.clearAuditLog();
    expect(bridge.getAuditLog().length).toBe(0);
  });

  test("resolves relative request paths against the configured endpoint", async () => {
    mockedAxios.mockResolvedValue({ data: { ok: true } } as any);

    const result = await bridge.relay(createRequest("/status?full=true"));

    expect(result.success).toBe(true);
    expect(mockedAxios).toHaveBeenCalledTimes(1);
    expect(mockedAxios).toHaveBeenCalledWith(
      expect.objectContaining({
        method: "get",
        url: "http://localhost:8545/status?full=true"
      })
    );
  });

  test.each([
    ["an absolute URL", "https://attacker.example/rpc"],
    ["a scheme-relative URL", "//attacker.example/rpc"],
    ["a credential-style URL", "http://localhost:8545@attacker.example/rpc"]
  ])("rejects %s before sending a request", async (_description, requestEndpoint) => {
    const result = await bridge.relay(createRequest(requestEndpoint));

    expect(result).toMatchObject({
      success: false,
      error: "Request endpoint must resolve to the configured RPC origin",
      endpointUsed: "none"
    });
    expect(mockedAxios).not.toHaveBeenCalled();
  });

  test("rejects malformed endpoint URLs before sending a request", async () => {
    const result = await bridge.relay(createRequest("http://["));

    expect(result).toMatchObject({
      success: false,
      error: "Invalid RPC endpoint URL",
      endpointUsed: "none"
    });
    expect(mockedAxios).not.toHaveBeenCalled();
  });

  describe("non-replayable requests", () => {
    const endpoints: BridgeEndpoint[] = [
      { url: "https://primary.example", priority: 10 },
      { url: "https://secondary.example", priority: 5 }
    ];

    test.each(["POST", "PUT", "DELETE"] as const)(
      "%s is sent exactly once by default",
      async (method) => {
        const protectedBridge = new AtomicRpcRelayerBridge({
          endpoints,
          maxRetries: 3,
          requireAtomicVerification: true
        });
        mockedAxios.mockResolvedValue(response({ accepted: true }) as any);

        const result = await protectedBridge.relay(
          createRequest("/submit", { method, payload: { transaction: "signed" } })
        );

        expect(result).toMatchObject({
          success: true,
          verificationStatus: "skipped",
          endpointUsed: "https://primary.example"
        });
        expect(mockedAxios).toHaveBeenCalledTimes(1);
      }
    );

    test("a failed POST is not retried or failed over", async () => {
      const protectedBridge = new AtomicRpcRelayerBridge({
        endpoints,
        maxRetries: 3,
        requireAtomicVerification: true
      });
      mockedAxios.mockRejectedValue(new Error("response lost"));

      const result = await protectedBridge.relay(
        createRequest("/submit", { method: "POST" })
      );

      expect(result).toMatchObject({
        success: false,
        error: "response lost",
        verificationStatus: "skipped"
      });
      expect(mockedAxios).toHaveBeenCalledTimes(1);
      expect(mockedAxios).toHaveBeenCalledWith(
        expect.objectContaining({ url: "https://primary.example/submit" })
      );
    });

    test("an explicit idempotent declaration enables POST retries", async () => {
      const replayBridge = new AtomicRpcRelayerBridge({
        endpoints,
        maxRetries: 2,
        requireAtomicVerification: false
      });
      mockedAxios.mockRejectedValue(new Error("offline"));

      await replayBridge.relay(
        createRequest("/submit", { method: "POST", idempotent: true })
      );

      expect(mockedAxios).toHaveBeenCalledTimes(4);
    });

    test("an explicitly idempotent POST participates in cross-verification", async () => {
      const replayBridge = new AtomicRpcRelayerBridge({
        endpoints,
        maxRetries: 2
      });
      mockedAxios.mockResolvedValue(response({ accepted: true }) as any);

      const result = await replayBridge.relay(
        createRequest("/submit", { method: "POST", idempotent: true })
      );

      expect(result).toMatchObject({ success: true, verificationStatus: "verified" });
      expect(mockedAxios).toHaveBeenCalledTimes(2);
    });

    test("an idempotency key enables replay and is forwarded on every attempt", async () => {
      const replayBridge = new AtomicRpcRelayerBridge({
        endpoints: [endpoints[0]],
        maxRetries: 2,
        requireAtomicVerification: false
      });
      mockedAxios
        .mockRejectedValueOnce(new Error("temporary failure"))
        .mockResolvedValueOnce(response({ accepted: true }) as any);

      const result = await replayBridge.relay(
        createRequest("/submit", {
          method: "POST",
          idempotencyKey: "operation-123"
        })
      );

      expect(result.success).toBe(true);
      expect(mockedAxios).toHaveBeenCalledTimes(2);
      for (const call of mockedAxios.mock.calls) {
        expect(call[0]).toEqual(
          expect.objectContaining({
            headers: { "Idempotency-Key": "operation-123" }
          })
        );
      }
    });

    test("an empty idempotency key is rejected before network access", async () => {
      const protectedBridge = new AtomicRpcRelayerBridge({ endpoints });

      const result = await protectedBridge.relay(
        createRequest("/submit", { method: "POST", idempotencyKey: "   " })
      );

      expect(result).toMatchObject({
        success: false,
        error: "Idempotency key must not be empty",
        verificationStatus: "skipped"
      });
      expect(mockedAxios).not.toHaveBeenCalled();
    });
  });

  describe("canonical response verification", () => {
    const endpoints: BridgeEndpoint[] = [
      { url: "https://primary.example", priority: 10 },
      { url: "https://secondary.example", priority: 5 }
    ];

    test("responses differing only in nested object key order verify as equal", async () => {
      const verificationBridge = new AtomicRpcRelayerBridge({
        endpoints,
        maxRetries: 1
      });
      mockedAxios.mockImplementation(async (config: any) =>
        config.url.includes("primary")
          ? response({ outer: { alpha: 1, beta: 2 }, ok: true }) as any
          : response({ ok: true, outer: { beta: 2, alpha: 1 } }) as any
      );

      const result = await verificationBridge.relay(createRequest("/state"));

      expect(result).toMatchObject({ success: true, verificationStatus: "verified" });
      expect(mockedAxios).toHaveBeenCalledTimes(2);
    });

    test("special JSON property names are canonicalized as data", async () => {
      const verificationBridge = new AtomicRpcRelayerBridge({
        endpoints,
        maxRetries: 1
      });
      const primary = JSON.parse(
        '{"__proto__":{"polluted":true},"constructor":"safe"}'
      );
      const secondary = JSON.parse(
        '{"constructor":"safe","__proto__":{"polluted":true}}'
      );
      mockedAxios
        .mockResolvedValueOnce(response(primary) as any)
        .mockResolvedValueOnce(response(secondary) as any);

      const result = await verificationBridge.relay(createRequest("/state"));

      expect(result).toMatchObject({ success: true, verificationStatus: "verified" });
      expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    });

    test("array order remains significant", async () => {
      const verificationBridge = new AtomicRpcRelayerBridge({
        endpoints,
        maxRetries: 1
      });
      mockedAxios.mockImplementation(async (config: any) =>
        config.url.includes("primary")
          ? response({ values: [1, 2] }) as any
          : response({ values: [2, 1] }) as any
      );

      const result = await verificationBridge.relay(createRequest("/state"));

      expect(result).toMatchObject({ success: false, verificationStatus: "failed" });
    });

    test("a projection excludes volatile fields while retaining stable data", async () => {
      const verificationBridge = new AtomicRpcRelayerBridge({
        endpoints,
        maxRetries: 1,
        verificationProjection: (_request, value) => {
          const body = value as { result: { hash: string; latestLedger: number } };
          return { hash: body.result.hash };
        }
      });
      mockedAxios.mockImplementation(async (config: any) =>
        config.url.includes("primary")
          ? response({ result: { hash: "abc", latestLedger: 100 } }) as any
          : response({ result: { latestLedger: 101, hash: "abc" } }) as any
      );

      const result = await verificationBridge.relay(createRequest("/transaction"));

      expect(result).toMatchObject({ success: true, verificationStatus: "verified" });
    });

    test("an invalid projection is verification-unavailable and is not retried", async () => {
      const verificationBridge = new AtomicRpcRelayerBridge({
        endpoints,
        maxRetries: 3,
        verificationProjection: () => new Date()
      });
      mockedAxios.mockResolvedValue(response({ ok: true }) as any);

      const result = await verificationBridge.relay(createRequest("/state"));

      expect(result).toMatchObject({ success: false, verificationStatus: "unavailable" });
      expect(result.error).toContain("only JSON objects");
      expect(mockedAxios).toHaveBeenCalledTimes(1);
    });
  });

  describe("quorum verification", () => {
    const endpoints: BridgeEndpoint[] = [
      { url: "https://primary.example", priority: 10 },
      { url: "https://secondary-a.example", priority: 5 },
      { url: "https://secondary-b.example", priority: 1 }
    ];

    test("one agreeing secondary forms a majority even if another is unreachable", async () => {
      const quorumBridge = new AtomicRpcRelayerBridge({ endpoints, maxRetries: 1 });
      mockedAxios.mockImplementation(async (config: any) => {
        if (config.url.includes("secondary-b")) throw new Error("offline");
        return response({ state: "accepted" }) as any;
      });

      const result = await quorumBridge.relay(createRequest("/state"));

      expect(result).toMatchObject({ success: true, verificationStatus: "verified" });
      expect(mockedAxios).toHaveBeenCalledTimes(3);
    });

    test("a disagreement plus an unreachable voter is unavailable and not retried", async () => {
      const quorumBridge = new AtomicRpcRelayerBridge({ endpoints, maxRetries: 3 });
      mockedAxios.mockImplementation(async (config: any) => {
        if (config.url.includes("secondary-b")) throw new Error("offline");
        if (config.url.includes("secondary-a")) return response({ state: "different" }) as any;
        return response({ state: "primary" }) as any;
      });

      const result = await quorumBridge.relay(createRequest("/state"));

      expect(result).toMatchObject({ success: false, verificationStatus: "unavailable" });
      expect(mockedAxios).toHaveBeenCalledTimes(3);
    });

    test("an unreachable sole secondary is unavailable and does not trigger a retry", async () => {
      const quorumBridge = new AtomicRpcRelayerBridge({
        endpoints: endpoints.slice(0, 2),
        maxRetries: 3
      });
      mockedAxios
        .mockResolvedValueOnce(response({ state: "primary" }) as any)
        .mockRejectedValueOnce(new Error("offline"));

      const result = await quorumBridge.relay(createRequest("/state"));

      expect(result).toMatchObject({ success: false, verificationStatus: "unavailable" });
      expect(mockedAxios).toHaveBeenCalledTimes(2);
    });

    test("explicit disagreements that make quorum impossible fail verification", async () => {
      const quorumBridge = new AtomicRpcRelayerBridge({ endpoints, maxRetries: 1 });
      mockedAxios.mockImplementation(async (config: any) => {
        if (config.url.includes("primary")) return response({ state: "primary" }) as any;
        if (config.url.includes("secondary-a")) return response({ state: "secondary-a" }) as any;
        return response({ state: "secondary-b" }) as any;
      });

      const result = await quorumBridge.relay(createRequest("/state"));

      expect(result).toMatchObject({ success: false, verificationStatus: "failed" });
    });

    test("duplicate endpoint URLs do not count as independent voters", async () => {
      const duplicateBridge = new AtomicRpcRelayerBridge({
        endpoints: [endpoints[0], { ...endpoints[0], priority: 9 }, endpoints[1]],
        maxRetries: 3
      });
      mockedAxios.mockImplementation(async (config: any) => {
        if (config.url.includes("secondary-a")) throw new Error("offline");
        return response({ state: "primary" }) as any;
      });

      const result = await duplicateBridge.relay(createRequest("/state"));

      expect(result).toMatchObject({ success: false, verificationStatus: "unavailable" });
      expect(mockedAxios).toHaveBeenCalledTimes(2);
    });

    test("equivalent effective URLs do not count as independent voters", async () => {
      const equivalentBridge = new AtomicRpcRelayerBridge({
        endpoints: [
          { url: "https://RPC.example:443", priority: 10 },
          { url: "https://rpc.example/", priority: 5 }
        ],
        maxRetries: 3
      });
      mockedAxios.mockResolvedValue(response({ state: "primary" }) as any);

      const result = await equivalentBridge.relay(createRequest("/state"));

      expect(result).toMatchObject({ success: false, verificationStatus: "unavailable" });
      expect(mockedAxios).toHaveBeenCalledTimes(1);
    });

    test("verification with no distinct secondary is unavailable and not retried", async () => {
      const singleBridge = new AtomicRpcRelayerBridge({
        endpoints: [endpoints[0]],
        maxRetries: 3
      });
      mockedAxios.mockResolvedValue(response({ state: "primary" }) as any);

      const result = await singleBridge.relay(createRequest("/state"));

      expect(result).toMatchObject({ success: false, verificationStatus: "unavailable" });
      expect(mockedAxios).toHaveBeenCalledTimes(1);
    });
  });
});
