import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("child_process", () => ({
  execSync: vi.fn(),
  spawnSync: vi.fn(),
}));
vi.mock("fs");
vi.mock("os");

import { execSync } from "child_process";
import fs from "fs";
import os from "os";
import {
  registerMCP,
  isClaudeAvailable,
  manualRegistrationInstructions,
} from "../mcp-register.js";

const mockExecSync = vi.mocked(execSync);
const mockFs = vi.mocked(fs);
const mockOs = vi.mocked(os);

beforeEach(() => {
  vi.resetAllMocks();
  mockOs.homedir.mockReturnValue("/mock/home");
  mockFs.existsSync.mockReturnValue(false);
  mockFs.readFileSync.mockReturnValue("{}");
  mockFs.writeFileSync.mockReturnValue(undefined);
  mockFs.renameSync.mockReturnValue(undefined);
  mockFs.mkdirSync.mockReturnValue(undefined);
  mockExecSync.mockImplementation(() => {
    throw new Error("command not found: claude");
  });
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
  it("returns a RegisterResult object with registered/skipped/errors arrays", async () => {
    const result = await registerMCP();
    expect(result).toHaveProperty("registered");
    expect(result).toHaveProperty("skipped");
    expect(result).toHaveProperty("errors");
    expect(Array.isArray(result.registered)).toBe(true);
    expect(Array.isArray(result.skipped)).toBe(true);
    expect(Array.isArray(result.errors)).toBe(true);
  });

  it("includes Claude Code in registered when claude is available and mcp add succeeds", async () => {
    mockExecSync.mockImplementation((cmd) => {
      const cmdStr = String(cmd);
      if (cmdStr.includes("--version")) return Buffer.from("claude version 1.0.0");
      if (cmdStr.includes("mcp add")) return Buffer.from("");
      throw new Error("Unexpected: " + cmdStr);
    });

    const result = await registerMCP();
    expect(result.registered).toContain("Claude Code");
  });

  it("puts Claude Code in skipped when claude CLI is not available", async () => {
    mockExecSync.mockImplementation(() => {
      throw new Error("command not found: claude");
    });

    const result = await registerMCP();
    expect(result.skipped).toContain("Claude Code");
    expect(result.registered).not.toContain("Claude Code");
  });

  it("puts Claude Code in errors when mcp add command fails", async () => {
    mockExecSync.mockImplementation((cmd) => {
      const cmdStr = String(cmd);
      if (cmdStr.includes("--version")) return Buffer.from("claude version 1.0.0");
      throw new Error("mcp add failed");
    });

    const result = await registerMCP();
    expect(result.errors.some((e) => e.includes("Claude Code"))).toBe(true);
    expect(result.registered).not.toContain("Claude Code");
  });

  it("uses --scope user and correct server name in claude mcp add command", async () => {
    mockExecSync.mockImplementation((cmd) => {
      const cmdStr = String(cmd);
      if (cmdStr.includes("--version")) return Buffer.from("claude version 1.0.0");
      if (cmdStr.includes("mcp add")) return Buffer.from("");
      throw new Error("Unexpected: " + cmdStr);
    });

    await registerMCP();

    const addCall = mockExecSync.mock.calls.find(([cmd]) =>
      String(cmd).includes("mcp add")
    );
    expect(addCall).toBeDefined();
    const addCmd = String(addCall[0]);
    expect(addCmd).toContain("--scope user");
    expect(addCmd).toContain("straylight");
    expect(addCmd).toContain("npx");
    expect(addCmd).toContain("-y");
    expect(addCmd).toContain("straylight-ai");
    expect(addCmd).toContain("mcp");
  });
});

describe("manualRegistrationInstructions", () => {
  it("returns a non-empty string with the registration command", () => {
    const instructions = manualRegistrationInstructions();
    expect(typeof instructions).toBe("string");
    expect(instructions.length).toBeGreaterThan(0);
  });

  it("includes the claude mcp add command with --scope user", () => {
    const instructions = manualRegistrationInstructions();
    expect(instructions).toContain("claude mcp add");
    expect(instructions).toContain("straylight");
    expect(instructions).toContain("--scope user");
  });

  it("includes multi-CLI instructions for Cursor, Windsurf, VS Code", () => {
    const instructions = manualRegistrationInstructions();
    expect(instructions).toContain(".cursor");
    expect(instructions).toContain("windsurf");
    expect(instructions).toContain(".vscode");
  });
});
