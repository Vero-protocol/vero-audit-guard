import { LogAnalyzer, LogEntry } from "./log-analyzer";

describe("LogAnalyzer", () => {
  let analyzer: LogAnalyzer;
  const now = new Date("2024-01-01T12:00:00Z").getTime();

  beforeEach(() => {
    analyzer = new LogAnalyzer({
      errorThreshold: 3,
      windowMs: 10000, // 10 seconds
    });
  });

  it("detects fatal errors as critical", () => {
    const logs: LogEntry[] = [
      {
        timestamp: new Date(now).toISOString(),
        level: "fatal",
        message: "System crash",
      },
    ];

    const anomalies = analyzer.analyze(logs);
    expect(anomalies).toHaveLength(1);
    expect(anomalies[0].type).toBe("ERROR_PATTERN");
    expect(anomalies[0].severity).toBe("CRITICAL");
  });

  it("detects error patterns with high severity", () => {
    const logs: LogEntry[] = [
      {
        timestamp: new Date(now).toISOString(),
        level: "error",
        message: "Failed to connect to database",
      },
    ];

    const anomalies = analyzer.analyze(logs);
    expect(anomalies).toHaveLength(1);
    expect(anomalies[0].type).toBe("ERROR_PATTERN");
    expect(anomalies[0].severity).toBe("HIGH");
  });

  it("detects security-related error patterns as critical", () => {
    const logs: LogEntry[] = [
      {
        timestamp: new Date(now).toISOString(),
        level: "error",
        message: "Unauthorized access attempt detected",
      },
    ];

    const anomalies = analyzer.analyze(logs);
    expect(anomalies).toHaveLength(1);
    expect(anomalies[0].severity).toBe("CRITICAL");
  });

  it("detects error spikes within a time window", () => {
    const logs: LogEntry[] = [
      { timestamp: new Date(now).toISOString(), level: "error", message: "Err 1" },
      { timestamp: new Date(now + 1000).toISOString(), level: "error", message: "Err 2" },
      { timestamp: new Date(now + 2000).toISOString(), level: "error", message: "Err 3" },
      { timestamp: new Date(now + 3000).toISOString(), level: "info", message: "Just info" },
    ];

    const anomalies = analyzer.analyze(logs);
    // 3 ERROR_PATTERN anomalies + 1 ERROR_SPIKE anomaly
    expect(anomalies.filter(a => a.type === "ERROR_PATTERN")).toHaveLength(3);
    const spike = anomalies.find(a => a.type === "ERROR_SPIKE");
    expect(spike).toBeDefined();
    expect(spike?.count).toBe(3);
  });

  it("ignores errors spread across different windows", () => {
    const logs: LogEntry[] = [
      { timestamp: new Date(now).toISOString(), level: "error", message: "Err 1" },
      { timestamp: new Date(now + 15000).toISOString(), level: "error", message: "Err 2" },
      { timestamp: new Date(now + 30000).toISOString(), level: "error", message: "Err 3" },
    ];

    const anomalies = analyzer.analyze(logs);
    expect(anomalies.filter(a => a.type === "ERROR_SPIKE")).toHaveLength(0);
  });

  it("escalates spike severity for very high frequency", () => {
    const logs: LogEntry[] = [
      { timestamp: new Date(now).toISOString(), level: "error", message: "E1" },
      { timestamp: new Date(now + 100).toISOString(), level: "error", message: "E2" },
      { timestamp: new Date(now + 200).toISOString(), level: "error", message: "E3" },
      { timestamp: new Date(now + 300).toISOString(), level: "error", message: "E4" },
      { timestamp: new Date(now + 400).toISOString(), level: "error", message: "E5" },
      { timestamp: new Date(now + 500).toISOString(), level: "error", message: "E6" },
    ];

    const anomalies = analyzer.analyze(logs);
    const spike = anomalies.find(a => a.type === "ERROR_SPIKE");
    expect(spike?.severity).toBe("CRITICAL"); // 6 errors >= 2 * threshold(3)
  });
});
