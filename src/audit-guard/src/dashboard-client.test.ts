import axios from "axios";
import DashboardClient, { DashboardAlert } from "./dashboard-client";

jest.mock("axios");
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe("DashboardClient", () => {
  const url = "https://dashboard.example.com/api/alerts";
  const token = "test-token";
  let client: DashboardClient;

  beforeEach(() => {
    client = new DashboardClient(url, token);
    jest.clearAllMocks();
  });

  it("should send an alert successfully", async () => {
    mockedAxios.post.mockResolvedValueOnce({ status: 200 });

    const alert: DashboardAlert = {
      source: "audit-guard",
      type: "TEST_RULE",
      severity: "HIGH",
      message: "Test message",
      detail: "Test detail",
      timestamp: new Date().toISOString(),
      metadata: { pr: 123 },
    };

    const result = await client.sendAlert(alert);

    expect(result).toBe(true);
    expect(mockedAxios.post).toHaveBeenCalledWith(url, alert, {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      timeout: 5000,
    });
  });

  it("should return false if url is not provided", async () => {
    const emptyClient = new DashboardClient("", "");
    const alert: DashboardAlert = {
      source: "audit-guard",
      type: "TEST_RULE",
      severity: "HIGH",
      message: "Test message",
      detail: "Test detail",
      timestamp: new Date().toISOString(),
      metadata: {},
    };

    const result = await emptyClient.sendAlert(alert);
    expect(result).toBe(false);
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });

  it("should handle axios errors gracefully", async () => {
    mockedAxios.post.mockRejectedValueOnce(new Error("Network Error"));

    const alert: DashboardAlert = {
      source: "audit-guard",
      type: "TEST_RULE",
      severity: "LOW",
      message: "Test message",
      detail: "Test detail",
      timestamp: new Date().toISOString(),
      metadata: {},
    };

    const result = await client.sendAlert(alert);
    expect(result).toBe(false);
    expect(mockedAxios.post).toHaveBeenCalled();
  });
});
