import { OnCallRoster, OnCallContact } from "./oncall-roster";
import * as fs from "fs";
import * as path from "path";

const ONCALL_STATE_FILE = path.join(__dirname, "..", ".oncall-state.json");

describe("OnCallRoster", () => {
  const testContacts: OnCallContact[] = [
    { name: "Alice", email: "alice@test.xyz", role: "PRIMARY" },
    { name: "Bob", email: "bob@test.xyz", role: "PRIMARY" },
    { name: "Charlie", email: "charlie@test.xyz", role: "SECONDARY" },
    { name: "Diana", email: "diana@test.xyz", role: "SECONDARY" },
    { name: "Eve", email: "eve@test.xyz", role: "MANAGER" },
  ];

  beforeEach(() => {
    delete process.env.ONCALL_CONTACTS;
    delete process.env.ONCALL_ROTATION_INTERVAL;
    if (fs.existsSync(ONCALL_STATE_FILE)) {
      fs.unlinkSync(ONCALL_STATE_FILE);
    }
  });

  describe("constructor", () => {
    it("should use provided config", () => {
      const roster = new OnCallRoster({
        contacts: testContacts,
        rotationInterval: "daily",
      });
      const config = roster.getConfig();
      expect(config.contacts).toHaveLength(5);
      expect(config.rotationInterval).toBe("daily");
    });

    it("should use defaults when no config provided", () => {
      const roster = new OnCallRoster();
      const config = roster.getConfig();
      expect(config.contacts.length).toBeGreaterThanOrEqual(3);
      expect(config.rotationInterval).toBe("weekly");
    });
  });

  describe("getCurrentOnCall", () => {
    it("should return one contact per role", () => {
      const roster = new OnCallRoster({
        contacts: testContacts,
        rotationInterval: "weekly",
      });
      const onCall = roster.getCurrentOnCall();
      expect(onCall.primary.role).toBe("PRIMARY");
      expect(onCall.secondary.role).toBe("SECONDARY");
      expect(onCall.manager.role).toBe("MANAGER");
    });

    it("should start with the first primary contact", () => {
      const roster = new OnCallRoster({
        contacts: testContacts,
        rotationInterval: "weekly",
      });
      const onCall = roster.getCurrentOnCall();
      expect(onCall.primary.name).toBe("Alice");
      expect(onCall.rotationId).toBe(0);
    });

    it("should have a nextRotation date", () => {
      const roster = new OnCallRoster({
        contacts: testContacts,
        rotationInterval: "weekly",
      });
      const onCall = roster.getCurrentOnCall();
      expect(new Date(onCall.nextRotation).getTime()).toBeGreaterThan(
        Date.now() - 10000
      );
    });
  });

  describe("rotate", () => {
    it("should rotate to the next primary contact", () => {
      const roster = new OnCallRoster({
        contacts: testContacts,
        rotationInterval: "weekly",
      });
      expect(roster.getCurrentOnCall().primary.name).toBe("Alice");
      roster.rotate();
      expect(roster.getCurrentOnCall().primary.name).toBe("Bob");
    });

    it("should wrap around to first contact after last", () => {
      const roster = new OnCallRoster({
        contacts: testContacts,
        rotationInterval: "weekly",
      });
      roster.rotate();
      expect(roster.getCurrentOnCall().primary.name).toBe("Bob");
      roster.rotate();
      expect(roster.getCurrentOnCall().primary.name).toBe("Alice");
    });
  });

  describe("pageCurrentOnCall", () => {
    it("should page all contacts without throwing", async () => {
      const roster = new OnCallRoster({
        contacts: testContacts,
        rotationInterval: "weekly",
      });
      await expect(
        roster.pageCurrentOnCall("Test alert", "CRITICAL", "vero-core")
      ).resolves.toBeUndefined();
    });
  });

  describe("getActiveContacts", () => {
    it("should return all configured contacts", () => {
      const roster = new OnCallRoster({
        contacts: testContacts,
        rotationInterval: "weekly",
      });
      const contacts = roster.getActiveContacts();
      expect(contacts).toHaveLength(5);
    });
  });

  describe("fallback contacts from env", () => {
    it("should parse ONCALL_CONTACTS env var", () => {
      process.env.ONCALL_CONTACTS = JSON.stringify([
        { name: "EnvPrimary", email: "env@test.xyz", role: "PRIMARY" },
      ]);
      process.env.ONCALL_ROTATION_INTERVAL = "daily";
      const roster = new OnCallRoster();
      const config = roster.getConfig();
      expect(config.contacts).toHaveLength(1);
      expect(config.contacts[0].name).toBe("EnvPrimary");
      expect(config.rotationInterval).toBe("daily");
    });
  });
});
