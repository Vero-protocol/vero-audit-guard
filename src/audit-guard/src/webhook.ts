import { WEBHOOK_URL, WEBHOOK_TOKEN } from "./config";
import fetch from "node-fetch";
import * as fs from "fs";
import * as path from "path";

export interface AlertPayload {
  repository: string;
  alert: string;
  timestamp: string;
}

// Log file for relay events
const LOG_FILE = path.join(__dirname, "..", "logs", "relay-events.log");

export async function sendAlert(payload: AlertPayload): Promise<void> {
  if (!WEBHOOK_URL) return; // No webhook configured
  // Ensure log directory exists
  await fs.promises.mkdir(path.dirname(LOG_FILE), { recursive: true });
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (WEBHOOK_TOKEN) headers["Authorization"] = `Bearer ${WEBHOOK_TOKEN}`;
  try {
    await fetch(WEBHOOK_URL, { method: "POST", headers, body: JSON.stringify(payload) });
    // Append payload to audit log
    await fs.promises.appendFile(LOG_FILE, JSON.stringify(payload) + "\n");
  } catch (e) {
    console.error("Failed to deliver audit‑guard webhook:", e);
  }
}
