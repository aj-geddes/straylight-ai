import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("child_process", () => ({
  execSync: vi.fn(),
  spawnSync: vi.fn(),
}));

import { execSync, spawnSync } from "child_process";
import {
  registerMCP,
  isClaudeAvailable,
  manualRegistrationInstructions,
} from "../mcp-register.js";

const mockExecSync = vi.mocked(execSync);
const mockSpawnSync = vi.mocked(spawnSync);

beforeEach(() => {
  vi.resetAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("isClaudeAvailable", () => {
  it("returns true when claude CLI is available", () => {
    mockExecSync.mockReturnValue(Buffer.from("claude version 1.0.0"));
    expect(isClaudeAvailable()).toBe(true);
  });

  it("returns false when claude CLI is not found", () => {
    mockExecSync.mockImplementation(() => {
      throw new Error("command not found: claude");
    });
    expect(isClaudeAvailable()).toBe(false);
  });
});

describe("registerMCP", () => {
  it("returns true and registers MCP when claude is available", async () => {
    // First call: claude --version succeeds
    mockExecSync.mockReturnValue(Buffer.from("claude version 1.0.0"));
    // spawnSync for the mcp add command
    mockSpawnSync.mockReturnValue({
      status: 0,
      stdout: Buffer.from(""),
      stderr: Buffer.from(""),
      pid: 1234,
      output: [],
      signal: null,
    });

    const result = await registerMCP();
    expect(result).toBe(true);
    expect(mockSpawnSync).toHaveBeenCalledWith(
      "claude",
      expect.arrayContaining(["mcp", "add"]),
      expect.any(Object)
    );
  });

  it("returns false when claude CLI is not available", async () => {
    mockExecSync.mockImplementation(() => {
      throw new Error("command not found: claude");
    });

    const result = await registerMCP();
    expect(result).toBe(false);
    expect(mockSpawnSync).not.toHaveBeenCalled();
  });

  it("returns false when mcp add command fails", async () => {
    mockExecSync.mockReturnValue(Buffer.from("claude version 1.0.0"));
    mockSpawnSync.mockReturnValue({
      status: 1,
      stdout: Buffer.from(""),
      stderr: Buffer.from("error: already exists"),
      pid: 1234,
      output: [],
      signal: null,
    });

    const result = await registerMCP();
    expect(result).toBe(false);
  });

  it("includes correct arguments in the registration command", async () => {
    mockExecSync.mockReturnValue(Buffer.from("claude version 1.0.0"));
    mockSpawnSync.mockReturnValue({
      status: 0,
      stdout: Buffer.from(""),
      stderr: Buffer.from(""),
      pid: 1234,
      output: [],
      signal: null,
    });

    await registerMCP();

    const args = mockSpawnSync.mock.calls[0][1] as string[];
    expect(args).toContain("mcp");
    expect(args).toContain("add");
    expect(args).toContain("straylight-ai");
    expect(args).toContain("--transport");
    expect(args).toContain("stdio");
  });
});

describe("manualRegistrationInstructions", () => {
  it("returns a non-empty string with the registration command", () => {
    const instructions = manualRegistrationInstructions();
    expect(typeof instructions).toBe("string");
    expect(instructions.length).toBeGreaterThan(0);
  });

  it("includes the claude mcp add command", () => {
    const instructions = manualRegistrationInstructions();
    expect(instructions).toContain("claude mcp add");
    expect(instructions).toContain("straylight-ai");
    expect(instructions).toContain("--transport stdio");
  });
});
