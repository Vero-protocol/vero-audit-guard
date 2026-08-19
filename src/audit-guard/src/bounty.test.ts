import * as fs from "fs";
import * as path from "path";
import { submitBounty, BountyPayload } from "./bounty";

describe("bounty module", () => {
  const logDir = path.join(__dirname, "..", "logs");
  const logFile = path.join(logDir, "bounty-submissions.log");

  beforeEach(async () => {
    try {
      await fs.promises.unlink(logFile);
    } catch {
      // Ignore if file doesn't exist
    }
  });

  afterAll(async () => {
    try {
      await fs.promises.unlink(logFile);
    } catch {
      // Ignore cleanup error
    }
  });

  it("should append a bounty submission entry with valid timestamp", async () => {
    const payload: BountyPayload = {
      name: "Security Researcher",
      email: "researcher@example.com",
      description: "Found access control vulnerability in smart contract",
      severity: "High",
      timestamp: "2026-08-19T00:00:00.000Z",
    };

    await submitBounty(payload);

    expect(fs.existsSync(logFile)).toBe(true);
    const content = await fs.promises.readFile(logFile, "utf-8");
    const lines = content.trim().split("\n");
    expect(lines.length).toBe(1);

    const logged = JSON.parse(lines[0]);
    expect(logged.name).toBe(payload.name);
    expect(logged.email).toBe(payload.email);
    expect(logged.description).toBe(payload.description);
    expect(logged.severity).toBe(payload.severity);
    expect(logged.timestamp).toBeDefined();
  });

  it("should append multiple bounty submissions sequentially", async () => {
    const payload1: BountyPayload = {
      name: "User1",
      email: "u1@example.com",
      description: "Bug 1",
      severity: "Low",
      timestamp: new Date().toISOString(),
    };
    const payload2: BountyPayload = {
      name: "User2",
      email: "u2@example.com",
      description: "Bug 2",
      severity: "Critical",
      timestamp: new Date().toISOString(),
    };

    await submitBounty(payload1);
    await submitBounty(payload2);

    const content = await fs.promises.readFile(logFile, "utf-8");
    const lines = content.trim().split("\n");
    expect(lines.length).toBe(2);

    const first = JSON.parse(lines[0]);
    const second = JSON.parse(lines[1]);
    expect(first.name).toBe("User1");
    expect(second.name).toBe("User2");
  });
});
