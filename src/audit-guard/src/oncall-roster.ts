import { WEBHOOK_URL, WEBHOOK_TOKEN } from "./config";
import * as fs from "fs";
import * as path from "path";

export interface OnCallContact {
  name: string;
  email: string;
  slack?: string;
  phone?: string;
  role: "PRIMARY" | "SECONDARY" | "MANAGER";
}

export interface OnCallRosterConfig {
  contacts: OnCallContact[];
  rotationInterval: "daily" | "weekly";
}

export interface RotationState {
  currentPrimaryIndex: number;
  lastRotated: string;
}

export interface PagePayload {
  contact: OnCallContact;
  alert: string;
  severity: string;
  timestamp: string;
  repository: string;
  rotationId: number;
}

const ROSTER_STATE_FILE = path.join(
  __dirname,
  "..",
  ".oncall-state.json"
);

function defaultContacts(): OnCallContact[] {
  const raw = process.env.ONCALL_CONTACTS;
  if (raw) {
    try {
      return JSON.parse(raw) as OnCallContact[];
    } catch {
      console.warn("[OnCallRoster] Failed to parse ONCALL_CONTACTS env var, using defaults");
    }
  }
  return [
    { name: "Alice Primary", email: "alice@vero.xyz", role: "PRIMARY" },
    { name: "Bob Secondary", email: "bob@vero.xyz", role: "SECONDARY" },
    { name: "Carol Manager", email: "carol@vero.xyz", role: "MANAGER" },
  ];
}

function defaultRotationInterval(): "daily" | "weekly" {
  const val = process.env.ONCALL_ROTATION_INTERVAL;
  if (val === "daily" || val === "weekly") return val;
  return "weekly";
}

function loadState(): RotationState {
  try {
    if (fs.existsSync(ROSTER_STATE_FILE)) {
      return JSON.parse(fs.readFileSync(ROSTER_STATE_FILE, "utf-8")) as RotationState;
    }
  } catch {
    console.warn("[OnCallRoster] Could not load state file, starting fresh");
  }
  return { currentPrimaryIndex: 0, lastRotated: new Date().toISOString() };
}

function saveState(state: RotationState): void {
  try {
    fs.mkdirSync(path.dirname(ROSTER_STATE_FILE), { recursive: true });
    fs.writeFileSync(ROSTER_STATE_FILE, JSON.stringify(state, null, 2));
  } catch (e) {
    console.error("[OnCallRoster] Failed to save state:", e);
  }
}

function getDayOfRotation(state: RotationState, interval: "daily" | "weekly"): number {
  const last = new Date(state.lastRotated);
  const now = new Date();
  const diffMs = now.getTime() - last.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  if (interval === "daily") return diffDays;
  return Math.floor(diffDays / 7);
}

export class OnCallRoster {
  private config: OnCallRosterConfig;
  private state: RotationState;

  constructor(config?: Partial<OnCallRosterConfig>) {
    this.config = {
      contacts: config?.contacts ?? defaultContacts(),
      rotationInterval: config?.rotationInterval ?? defaultRotationInterval(),
    };
    this.state = loadState();
    this.autoRotate();
  }

  private autoRotate(): void {
    const cycles = getDayOfRotation(this.state, this.config.rotationInterval);
    if (cycles > 0) {
      const primaryCount = this.config.contacts.filter(
        (c) => c.role === "PRIMARY"
      ).length;
      if (primaryCount > 0) {
        this.state.currentPrimaryIndex =
          (this.state.currentPrimaryIndex + cycles) % primaryCount;
      }
      this.state.lastRotated = new Date().toISOString();
      saveState(this.state);
    }
  }

  getCurrentOnCall(): {
    primary: OnCallContact;
    secondary: OnCallContact;
    manager: OnCallContact;
    rotationId: number;
    nextRotation: string;
  } {
    const primaries = this.config.contacts.filter((c) => c.role === "PRIMARY");
    const secondaries = this.config.contacts.filter((c) => c.role === "SECONDARY");
    const managers = this.config.contacts.filter((c) => c.role === "MANAGER");

    const primary =
      primaries.length > 0
        ? primaries[this.state.currentPrimaryIndex % primaries.length]
        : { name: "N/A", email: "N/A", role: "PRIMARY" as const };

    const secondaryIndex = secondaries.length > 0
      ? this.state.currentPrimaryIndex % secondaries.length
      : 0;
    const secondary =
      secondaries.length > 0
        ? secondaries[secondaryIndex]
        : { name: "N/A", email: "N/A", role: "SECONDARY" as const };

    const managerIndex = managers.length > 0
      ? this.state.currentPrimaryIndex % managers.length
      : 0;
    const manager =
      managers.length > 0
        ? managers[managerIndex]
        : { name: "N/A", email: "N/A", role: "MANAGER" as const };

    const last = new Date(this.state.lastRotated);
    const next = new Date(last);
    if (this.config.rotationInterval === "daily") {
      next.setDate(next.getDate() + 1);
    } else {
      next.setDate(next.getDate() + 7);
    }

    return {
      primary,
      secondary,
      manager,
      rotationId: this.state.currentPrimaryIndex,
      nextRotation: next.toISOString(),
    };
  }

  rotate(): void {
    const primaryCount = this.config.contacts.filter(
      (c) => c.role === "PRIMARY"
    ).length;
    if (primaryCount > 0) {
      this.state.currentPrimaryIndex =
        (this.state.currentPrimaryIndex + 1) % primaryCount;
    }
    this.state.lastRotated = new Date().toISOString();
    saveState(this.state);
  }

  async pageCurrentOnCall(
    alert: string,
    severity: string,
    repository: string
  ): Promise<void> {
    const onCall = this.getCurrentOnCall();
    const timestamp = new Date().toISOString();

    const contacts = [onCall.primary, onCall.secondary, onCall.manager];

    for (const contact of contacts) {
      const payload: PagePayload = {
        contact,
        alert,
        severity,
        timestamp,
        repository,
        rotationId: onCall.rotationId,
      };
      await this.deliverPage(payload);
    }
  }

  private async deliverPage(payload: PagePayload): Promise<void> {
    const logDir = path.join(__dirname, "..", "logs");
    const pageLog = path.join(logDir, "oncall-pages.log");
    await fs.promises.mkdir(logDir, { recursive: true });
    await fs.promises.appendFile(pageLog, JSON.stringify(payload) + "\n");

    console.log(
      `[OnCallRoster] Paging ${payload.contact.name} (${payload.contact.role}) at ${payload.contact.email} — ${payload.alert}`
    );

    if (payload.contact.slack) {
      console.log(
        `[OnCallRoster] Slack DM to ${payload.contact.slack}: ${payload.alert}`
      );
    }

    if (payload.contact.phone) {
      console.log(
        `[OnCallRoster] SMS to ${payload.contact.phone}: [${payload.severity}] ${payload.alert}`
      );
    }

    if (WEBHOOK_URL) {
      try {
        const headers: Record<string, string> = {
          "Content-Type": "application/json",
        };
        if (WEBHOOK_TOKEN) {
          headers["Authorization"] = `Bearer ${WEBHOOK_TOKEN}`;
        }
        const fetchImpl = (globalThis as unknown as { fetch?: typeof fetch }).fetch;
        if (fetchImpl) {
          await fetchImpl(WEBHOOK_URL, {
            method: "POST",
            headers,
            body: JSON.stringify({
              type: "oncall_page",
              ...payload,
            }),
          });
        }
      } catch (e) {
        console.error("[OnCallRoster] Webhook delivery failed:", e);
      }
    }
  }

  getActiveContacts(): OnCallContact[] {
    return this.config.contacts;
  }

  getConfig(): OnCallRosterConfig {
    return { ...this.config };
  }
}

export default OnCallRoster;
