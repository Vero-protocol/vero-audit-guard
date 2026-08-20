import { getNextReportVersion } from "./report-version";
import * as fs from "fs";
import * as path from "path";

jest.mock("fs", () => ({
  existsSync: jest.fn(),
  readFileSync: jest.fn(),
  writeFileSync: jest.fn(),
}));

describe("report-version", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should return 1 if version file does not exist", () => {
    (fs.existsSync as jest.Mock).mockReturnValue(false);
    expect(getNextReportVersion()).toBe(1);
    expect(fs.writeFileSync).toHaveBeenCalledWith(
      expect.stringContaining(".audit-report-version.json"),
      JSON.stringify({ version: 1 }, null, 2)
    );
  });

  it("should bump version if file exists", () => {
    (fs.existsSync as jest.Mock).mockReturnValue(true);
    (fs.readFileSync as jest.Mock).mockReturnValue(JSON.stringify({ version: 5 }));
    expect(getNextReportVersion()).toBe(6);
    expect(fs.writeFileSync).toHaveBeenCalledWith(
      expect.stringContaining(".audit-report-version.json"),
      JSON.stringify({ version: 6 }, null, 2)
    );
  });

  it("should cover version-mismatch or corrupted json scenarios", () => {
    (fs.existsSync as jest.Mock).mockReturnValue(true);
    (fs.readFileSync as jest.Mock).mockReturnValue("corrupted-json");
    // Fallbacks to 1
    expect(getNextReportVersion()).toBe(1);
    expect(fs.writeFileSync).toHaveBeenCalledWith(
      expect.stringContaining(".audit-report-version.json"),
      JSON.stringify({ version: 1 }, null, 2)
    );
  });

  it("should handle write failure gracefully", () => {
    (fs.existsSync as jest.Mock).mockReturnValue(true);
    (fs.readFileSync as jest.Mock).mockReturnValue(JSON.stringify({ version: 2 }));
    (fs.writeFileSync as jest.Mock).mockImplementation(() => {
      throw new Error("Write failed");
    });
    // Should still return the bumped version despite write failure
    expect(getNextReportVersion()).toBe(3);
  });
});
