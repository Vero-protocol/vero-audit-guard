import { AtomicRpcRelayerBridge, type BridgeEndpoint, type BridgeRequest } from "./index";

describe("AtomicRpcRelayerBridge", () => {
  let bridge: AtomicRpcRelayerBridge;
  const testEndpoints: BridgeEndpoint[] = [
    { url: "http://localhost:8545", priority: 10 },
    { url: "http://localhost:8546", priority: 5 }
  ];

  beforeEach(() => {
    bridge = new AtomicRpcRelayerBridge({
      endpoints: testEndpoints,
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
});
