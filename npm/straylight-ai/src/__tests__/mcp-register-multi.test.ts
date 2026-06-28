import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock ALL external dependencies before imports
vi.mock("fs");
vi.mock("os");
vi.mock("child_process", () => ({
  execSync: vi.fn(),
  spawnSync: vi.fn(),
}));

import fs from "fs";
import os from "os";
import { execSync } from "child_process";
import {
  registerMCP,
  unregisterMCP,
  isClaudeAvailable,
  manualRegistrationInstructions,
  getTelemetryConsent,
} from "../mcp-register.js";
import type { RegisterResult } from "../mcp-register.js";

const mockExecSync = vi.mocked(execSync);
const mockFs = vi.mocked(fs);
const mockOs = vi.mocked(os);

const MOCK_HOME = "/mock/home";

beforeEach(() => {
  vi.resetAllMocks();
  mockOs.homedir.mockReturnValue(MOCK_HOME);
  // Default: no config dirs exist
  mockFs.existsSync.mockReturnValue(false);
  // Default: readFileSync returns empty JSON
  mockFs.readFileSync.mockReturnValue("{}");
  // Default: file ops are no-ops
  mockFs.writeFileSync.mockReturnValue(undefined);
  mockFs.renameSync.mockReturnValue(undefined);
  mockFs.mkdirSync.mockReturnValue(undefined);
  // Default: claude CLI not available
  mockExecSync.mockImplementation(() => {
    throw new Error("command not found: claude");
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

// isClaudeAvailable
describe("isClaudeAvailable", () => {
  it("returns true when claude --version succeeds", () => {
    mockExecSync.mockReturnValue(Buffer.from("claude version 2.0.0"));
    expect(isClaudeAvailable()).toBe(true);
  });

  it("returns false when claude --version throws", () => {
    mockExecSync.mockImplementation(() => {
      throw new Error("command not found: claude");
    });
    expect(isClaudeAvailable()).toBe(false);
  });
});

// Multi-CLI detection and registration
describe("registerMCP - multi-CLI detection", () => {
  it("skips all CLIs when nothing is installed", async () => {
    mockFs.existsSync.mockReturnValue(false);
    const result: RegisterResult = await registerMCP();
    expect(result.registered).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
    expect(result.skipped.length).toBeGreaterThanOrEqual(5);
  });

  it("registers Cursor when ~/.cursor dir exists", async () => {
    const cursorDir = `${MOCK_HOME}/.cursor`;
    mockFs.existsSync.mockImplementation((p) => p === cursorDir);
    const result = await registerMCP();
    expect(result.registered).toContain("Cursor");
    expect(result.skipped).not.toContain("Cursor");
  });

  it("writes correct stdio JSON config for Cursor", async () => {
    const cursorDir = `${MOCK_HOME}/.cursor`;
    const cursorMcpPath = `${cursorDir}/mcp.json`;
    mockFs.existsSync.mockImplementation((p) => p === cursorDir);
    mockFs.readFileSync.mockReturnValue("{}");

    await registerMCP();

    const writeCalls = mockFs.writeFileSync.mock.calls;
    const cursorWrite = writeCalls.find(([filePath]) =>
      String(filePath).includes(".cursor")
    );
    expect(cursorWrite).toBeDefined();
    const writtenJson = JSON.parse(String(cursorWrite![1]));
    expect(writtenJson.mcpServers.straylight).toEqual({
      command: "npx",
      args: ["-y", "straylight-ai", "mcp"],
    });

    const cursorRename = mockFs.renameSync.mock.calls.find(
      ([, dest]) => String(dest) === cursorMcpPath
    );
    expect(cursorRename).toBeDefined();
  });

  it("writes stdio command/args for Windsurf (not serverUrl)", async () => {
    const windsurfDir = `${MOCK_HOME}/.codeium/windsurf`;
    mockFs.existsSync.mockImplementation((p) => p === windsurfDir);
    mockFs.readFileSync.mockReturnValue("{}");

    await registerMCP();

    const windsurfWrite = mockFs.writeFileSync.mock.calls.find(([filePath]) =>
      String(filePath).includes("windsurf")
    );
    expect(windsurfWrite).toBeDefined();
    const writtenJson = JSON.parse(String(windsurfWrite![1]));
    expect(writtenJson.mcpServers.straylight.command).toBe("npx");
    expect(writtenJson.mcpServers.straylight.args).toEqual([
      "-y",
      "straylight-ai",
      "mcp",
    ]);
    expect(writtenJson.mcpServers.straylight.serverUrl).toBeUndefined();
  });

  it("uses 'servers' key and type:stdio for VS Code", async () => {
    const vsCodeDir = `${MOCK_HOME}/.vscode`;
    mockFs.existsSync.mockImplementation((p) => p === vsCodeDir);
    mockFs.readFileSync.mockReturnValue("{}");

    await registerMCP();

    const vsCodeWrite = mockFs.writeFileSync.mock.calls.find(([filePath]) =>
      String(filePath).includes(".vscode")
    );
    expect(vsCodeWrite).toBeDefined();
    const writtenJson = JSON.parse(String(vsCodeWrite![1]));
    expect(writtenJson.servers).toBeDefined();
    expect(writtenJson.mcpServers).toBeUndefined();
    expect(writtenJson.servers.straylight).toEqual({
      type: "stdio",
      command: "npx",
      args: ["-y", "straylight-ai", "mcp"],
    });
  });

  it("writes correct JSON config for Codex", async () => {
    const codexDir = `${MOCK_HOME}/.codex`;
    mockFs.existsSync.mockImplementation((p) => p === codexDir);
    mockFs.readFileSync.mockReturnValue("{}");

    await registerMCP();

    const codexWrite = mockFs.writeFileSync.mock.calls.find(([filePath]) =>
      String(filePath).includes(".codex")
    );
    expect(codexWrite).toBeDefined();
    const writtenJson = JSON.parse(String(codexWrite![1]));
    expect(writtenJson.mcpServers.straylight).toEqual({
      command: "npx",
      args: ["-y", "straylight-ai", "mcp"],
    });
  });

  it("writes correct JSON config for Gemini CLI", async () => {
    const geminiDir = `${MOCK_HOME}/.gemini`;
    mockFs.existsSync.mockImplementation((p) => p === geminiDir);
    mockFs.readFileSync.mockReturnValue("{}");

    await registerMCP();

    const geminiWrite = mockFs.writeFileSync.mock.calls.find(([filePath]) =>
      String(filePath).includes(".gemini")
    );
    expect(geminiWrite).toBeDefined();
    const writtenJson = JSON.parse(String(geminiWrite![1]));
    expect(writtenJson.mcpServers.straylight).toEqual({
      command: "npx",
      args: ["-y", "straylight-ai", "mcp"],
    });
  });

  it("uses 'claude mcp add --scope user straylight' for Claude Code registration", async () => {
    mockExecSync.mockImplementation((cmd: unknown) => {
      const cmdStr = String(cmd);
      if (cmdStr.includes("--version")) return Buffer.from("claude version 2.0");
      if (cmdStr.includes("mcp add")) return Buffer.from("");
      throw new Error(`Unexpected execSync call: ${cmdStr}`);
    });

    const result = await registerMCP();

    expect(result.registered).toContain("Claude Code");
    const addCall = mockExecSync.mock.calls.find(([cmd]) =>
      String(cmd).includes("mcp add")
    );
    expect(addCall).toBeDefined();
    expect(String(addCall![0])).toContain("--scope user");
    expect(String(addCall![0])).toContain("straylight");
    expect(String(addCall![0])).toContain("npx -y straylight-ai mcp");
  });
});

// Idempotency
describe("registerMCP - idempotency", () => {
  it("does not duplicate straylight when already present in Cursor config", async () => {
    const cursorDir = `${MOCK_HOME}/.cursor`;
    const existingConfig = JSON.stringify({
      mcpServers: {
        straylight: { command: "npx", args: ["-y", "straylight-ai", "mcp"] },
        other: { command: "other-cmd", args: [] },
      },
    });
    mockFs.existsSync.mockImplementation((p) => p === cursorDir);
    mockFs.readFileSync.mockReturnValue(existingConfig);

    await registerMCP();

    const writeCall = mockFs.writeFileSync.mock.calls.find(([filePath]) =>
      String(filePath).includes(".cursor")
    );
    expect(writeCall).toBeDefined();
    const writtenJson = JSON.parse(String(writeCall![1]));
    const keys = Object.keys(
      writtenJson.mcpServers as Record<string, unknown>
    );
    expect(keys.filter((k) => k === "straylight")).toHaveLength(1);
  });

  it("preserves existing mcpServers entries when registering", async () => {
    const cursorDir = `${MOCK_HOME}/.cursor`;
    const existingConfig = JSON.stringify({
      mcpServers: {
        "some-other-mcp": { command: "other", args: [] },
      },
    });
    mockFs.existsSync.mockImplementation((p) => p === cursorDir);
    mockFs.readFileSync.mockReturnValue(existingConfig);

    await registerMCP();

    const writeCall = mockFs.writeFileSync.mock.calls.find(([filePath]) =>
      String(filePath).includes(".cursor")
    );
    expect(writeCall).toBeDefined();
    const writtenJson = JSON.parse(String(writeCall![1]));
    expect(
      (writtenJson.mcpServers as Record<string, unknown>)["some-other-mcp"]
    ).toBeDefined();
    expect(
      (writtenJson.mcpServers as Record<string, unknown>)["straylight"]
    ).toBeDefined();
  });
});

// Unregister
describe("unregisterMCP", () => {
  it("removes straylight key from Cursor config without removing other entries", async () => {
    const cursorDir = `${MOCK_HOME}/.cursor`;
    const existingConfig = JSON.stringify({
      mcpServers: {
        straylight: { command: "npx", args: ["-y", "straylight-ai", "mcp"] },
        "another-mcp": { command: "another", args: [] },
      },
    });
    mockFs.existsSync.mockImplementation((p) => p === cursorDir);
    mockFs.readFileSync.mockReturnValue(existingConfig);

    await unregisterMCP();

    const writeCall = mockFs.writeFileSync.mock.calls.find(([filePath]) =>
      String(filePath).includes(".cursor")
    );
    expect(writeCall).toBeDefined();
    const writtenJson = JSON.parse(String(writeCall![1]));
    expect(
      (writtenJson.mcpServers as Record<string, unknown>)["straylight"]
    ).toBeUndefined();
    expect(
      (writtenJson.mcpServers as Record<string, unknown>)["another-mcp"]
    ).toBeDefined();
  });

  it("calls 'claude mcp remove straylight' for Claude Code unregister", async () => {
    mockExecSync.mockImplementation((cmd: unknown) => {
      const cmdStr = String(cmd);
      if (cmdStr.includes("--version")) return Buffer.from("claude version 2.0");
      if (cmdStr.includes("mcp remove")) return Buffer.from("");
      throw new Error(`Unexpected: ${cmdStr}`);
    });

    await unregisterMCP();

    const removeCall = mockExecSync.mock.calls.find(([cmd]) =>
      String(cmd).includes("mcp remove")
    );
    expect(removeCall).toBeDefined();
    expect(String(removeCall![0])).toContain("straylight");
  });
});

// Telemetry
describe("getTelemetryConsent", () => {
  it("returns false by default when no env vars are set", () => {
    const savedDNT = process.env["DO_NOT_TRACK"];
    const savedTel = process.env["STRAYLIGHT_TELEMETRY"];
    delete process.env["DO_NOT_TRACK"];
    delete process.env["STRAYLIGHT_TELEMETRY"];

    const consent = getTelemetryConsent();

    if (savedDNT !== undefined) process.env["DO_NOT_TRACK"] = savedDNT;
    if (savedTel !== undefined)
      process.env["STRAYLIGHT_TELEMETRY"] = savedTel;
    expect(consent).toBe(false);
  });

  it("returns false when DO_NOT_TRACK=1 even if STRAYLIGHT_TELEMETRY=true", () => {
    const savedDNT = process.env["DO_NOT_TRACK"];
    const savedTel = process.env["STRAYLIGHT_TELEMETRY"];
    process.env["DO_NOT_TRACK"] = "1";
    process.env["STRAYLIGHT_TELEMETRY"] = "true";

    const consent = getTelemetryConsent();

    if (savedDNT !== undefined) process.env["DO_NOT_TRACK"] = savedDNT;
    else delete process.env["DO_NOT_TRACK"];
    if (savedTel !== undefined)
      process.env["STRAYLIGHT_TELEMETRY"] = savedTel;
    else delete process.env["STRAYLIGHT_TELEMETRY"];
    expect(consent).toBe(false);
  });

  it("returns false when DO_NOT_TRACK=true", () => {
    const savedDNT = process.env["DO_NOT_TRACK"];
    process.env["DO_NOT_TRACK"] = "true";

    const consent = getTelemetryConsent();

    if (savedDNT !== undefined) process.env["DO_NOT_TRACK"] = savedDNT;
    else delete process.env["DO_NOT_TRACK"];
    expect(consent).toBe(false);
  });

  it("returns true only when STRAYLIGHT_TELEMETRY=true and DO_NOT_TRACK not set", () => {
    const savedDNT = process.env["DO_NOT_TRACK"];
    const savedTel = process.env["STRAYLIGHT_TELEMETRY"];
    delete process.env["DO_NOT_TRACK"];
    process.env["STRAYLIGHT_TELEMETRY"] = "true";

    const consent = getTelemetryConsent();

    if (savedDNT !== undefined) process.env["DO_NOT_TRACK"] = savedDNT;
    else delete process.env["DO_NOT_TRACK"];
    if (savedTel !== undefined)
      process.env["STRAYLIGHT_TELEMETRY"] = savedTel;
    else delete process.env["STRAYLIGHT_TELEMETRY"];
    expect(consent).toBe(true);
  });
});

// manualRegistrationInstructions
describe("manualRegistrationInstructions", () => {
  it("returns a non-empty string", () => {
    const instructions = manualRegistrationInstructions();
    expect(typeof instructions).toBe("string");
    expect(instructions.length).toBeGreaterThan(0);
  });

  it("includes claude mcp add with --scope user straylight", () => {
    const instructions = manualRegistrationInstructions();
    expect(instructions).toContain("claude mcp add");
    expect(instructions).toContain("--scope user");
    expect(instructions).toContain("straylight");
  });

  it("includes Cursor config path", () => {
    const instructions = manualRegistrationInstructions();
    expect(instructions).toContain(".cursor");
    expect(instructions).toContain("mcpServers");
  });

  it("includes Windsurf config path", () => {
    const instructions = manualRegistrationInstructions();
    expect(instructions).toContain("windsurf");
    expect(instructions).toContain("mcp_config.json");
  });
});
