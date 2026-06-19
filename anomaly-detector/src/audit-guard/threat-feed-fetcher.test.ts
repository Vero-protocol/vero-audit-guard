import axios from "axios";
import { ThreatFeedFetcher } from "./threat-feed-fetcher";

jest.mock("axios");
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe("ThreatFeedFetcher", () => {
  let fetcher: ThreatFeedFetcher;
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
    fetcher = new ThreatFeedFetcher();
    mockedAxios.get.mockReset();
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("handles empty config gracefully", async () => {
    process.env.THREAT_FEED_URL = "";
    process.env.THREAT_FEED_URLS = "";

    const warnSpy = jest.spyOn(console, "warn").mockImplementation();
    await fetcher.updateFeed();
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("No threat feed URLs configured")
    );
    expect(fetcher.getLastUpdated()).toBeNull();
    expect(fetcher.getThreatAddresses().size).toBe(0);
    warnSpy.mockRestore();
  });

  it("parses line-delimited plain text feed", async () => {
    process.env.THREAT_FEED_URL = "http://example.com/feed.txt";
    const rawData = `
      GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      # comment line
      GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
      not-an-address
    `;
    mockedAxios.get.mockResolvedValueOnce({ data: rawData });

    await fetcher.updateFeed();
    const threats = fetcher.getThreatAddresses();
    expect(threats.size).toBe(2);
    expect(threats.has("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBe(true);
    expect(threats.has("GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")).toBe(true);
    expect(fetcher.isThreat("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBe(true);
    expect(fetcher.isThreat("GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")).toBe(false);
    expect(fetcher.getLastUpdated()).toBeInstanceOf(Date);
  });

  it("parses JSON array feed", async () => {
    process.env.THREAT_FEED_URL = "http://example.com/feed.json";
    const rawData = [
      "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    ];
    mockedAxios.get.mockResolvedValueOnce({ data: rawData });

    await fetcher.updateFeed();
    const threats = fetcher.getThreatAddresses();
    expect(threats.size).toBe(2);
    expect(threats.has("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBe(true);
  });

  it("parses complex nested JSON feed", async () => {
    process.env.THREAT_FEED_URLS = "http://example.com/feed1.json";
    const rawData = {
      status: "success",
      indicators: [
        {
          id: "1",
          value: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          type: "crypto"
        },
        {
          id: "2",
          value: "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
          type: "crypto"
        }
      ],
      metadata: {
        other_stuff: "value"
      }
    };
    mockedAxios.get.mockResolvedValueOnce({ data: rawData });

    await fetcher.updateFeed();
    const threats = fetcher.getThreatAddresses();
    expect(threats.size).toBe(2);
    expect(threats.has("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBe(true);
  });

  it("falls back to cached threats if fetch fails", async () => {
    process.env.THREAT_FEED_URL = "http://example.com/feed.txt";
    
    // First fetch succeeds
    mockedAxios.get.mockResolvedValueOnce({ data: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" });
    await fetcher.updateFeed();
    expect(fetcher.getThreatAddresses().size).toBe(1);
    const firstUpdate = fetcher.getLastUpdated();
    expect(firstUpdate).not.toBeNull();

    // Second fetch fails
    mockedAxios.get.mockRejectedValueOnce(new Error("Network error"));
    const errorSpy = jest.spyOn(console, "error").mockImplementation();
    const warnSpy = jest.spyOn(console, "warn").mockImplementation();

    await fetcher.updateFeed();

    // Should retain previous data
    expect(fetcher.getThreatAddresses().size).toBe(1);
    expect(fetcher.isThreat("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBe(true);
    expect(fetcher.getLastUpdated()).toEqual(firstUpdate);

    errorSpy.mockRestore();
    warnSpy.mockRestore();
  });

  it("supports mock threats override for testing", () => {
    expect(fetcher.isThreat("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBe(false);
    fetcher.setMockThreats(["GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]);
    expect(fetcher.isThreat("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBe(true);
    fetcher.clearMockThreats();
    expect(fetcher.isThreat("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBe(false);
  });
});
