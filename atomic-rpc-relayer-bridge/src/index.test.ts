import axios from "axios";
import { AtomicRpcRelayerBridge, type BridgeEndpoint, type BridgeRequest } from "./index";

jest.mock("axios");

const mockedAxios = axios as jest.MockedFunction<typeof axios>;

function createRequest(endpoint: string): BridgeRequest {
  return {
    id: `request-${endpoint}`,
    method: "GET",
    endpoint,
    timestamp: Date.now()
  };
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
});
