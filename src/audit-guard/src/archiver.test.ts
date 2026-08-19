import LogArchiver from "./archiver";
import * as fs from "fs";
import * as path from "path";

jest.mock("fs", () => ({
  promises: {
    readdir: jest.fn(),
    stat: jest.fn(),
    unlink: jest.fn(),
  },
  createReadStream: jest.fn(),
}));

jest.mock("zlib", () => ({
  createGzip: jest.fn(() => ({})),
}));

describe("LogArchiver", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should fail to initialize without required config", () => {
    expect(() => new LogArchiver({} as any)).toThrow("bucketName and region are required");
  });

  it("should archive old files and delete them", async () => {
    const archiver = new LogArchiver({ bucketName: "test-bucket", region: "us-east-1", retentionDays: 30 });
    
    // mock s3 client
    (archiver as any).s3 = {
      send: jest.fn().mockResolvedValue({}),
    };

    (fs.promises.readdir as jest.Mock).mockResolvedValue([
      { isFile: () => true, name: "old.log" },
      { isFile: () => true, name: "new.log" }
    ]);
    
    const now = Date.now();
    (fs.promises.stat as jest.Mock).mockImplementation(async (filePath) => {
      if (filePath.endsWith("old.log")) {
        return { mtimeMs: now - 40 * 24 * 60 * 60 * 1000 };
      }
      return { mtimeMs: now };
    });

    (fs.createReadStream as jest.Mock).mockReturnValue({
      pipe: jest.fn().mockReturnValue({}),
    });

    await archiver.archiveDirectory("/logs");

    expect((archiver as any).s3.send).toHaveBeenCalledTimes(1);
    expect(fs.promises.unlink).toHaveBeenCalledWith(path.join("/logs", "old.log"));
    expect(fs.promises.unlink).not.toHaveBeenCalledWith(path.join("/logs", "new.log"));
  });

  it("should handle archive-failure scenarios", async () => {
    const archiver = new LogArchiver({ bucketName: "test-bucket", region: "us-east-1", retentionDays: 30 });
    
    // mock s3 client to throw error
    (archiver as any).s3 = {
      send: jest.fn().mockRejectedValue(new Error("S3 Upload Failed")),
    };

    (fs.promises.readdir as jest.Mock).mockResolvedValue([
      { isFile: () => true, name: "old.log" },
    ]);
    
    const now = Date.now();
    (fs.promises.stat as jest.Mock).mockResolvedValue({ mtimeMs: now - 40 * 24 * 60 * 60 * 1000 });

    (fs.createReadStream as jest.Mock).mockReturnValue({
      pipe: jest.fn().mockReturnValue({}),
    });

    await expect(archiver.archiveDirectory("/logs")).rejects.toThrow("S3 Upload Failed");
    expect(fs.promises.unlink).not.toHaveBeenCalled();
  });
});
