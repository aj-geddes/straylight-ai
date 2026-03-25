import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock all external dependencies
vi.mock("child_process", () => ({
  execSync: vi.fn(),
  spawnSync: vi.fn(),
  spawn: vi.fn(),
}));

vi.mock("../docker.js", () => ({
  detectRuntime: vi.fn(),
  getContainerStatus: vi.fn(),
  isContainerRunning: vi.fn(),
  buildRunCommand: vi.fn(),
  buildStartCommand: vi.fn(),
  buildStopCommand: vi.fn(),
}));

vi.mock("../health.js", () => ({
  waitForHealth: vi.fn(),
  checkHealth: vi.fn(),
}));

vi.mock("../mcp-register.js", () => ({
  registerMCP: vi.fn(),
  isClaudeAvailable: vi.fn(),
  manualRegistrationInstructions: vi.fn().mockReturnValue("Manual instructions"),
}));

// Mock open (browser opening)
vi.mock("../open.js", () => ({
  openBrowser: vi.fn(),
}));

import { execSync } from "child_process";
import {
  detectRuntime,
  getContainerStatus,
  isContainerRunning,
  buildRunCommand,
  buildStartCommand,
  buildStopCommand,
} from "../docker.js";
import { waitForHealth, checkHealth } from "../health.js";
import { registerMCP, isClaudeAvailable } from "../mcp-register.js";
import { openBrowser } from "../open.js";

import { runSetup } from "../commands/setup.js";
import { runStart } from "../commands/start.js";
import { runStop } from "../commands/stop.js";
import { runStatus } from "../commands/status.js";

const mockDetectRuntime = vi.mocked(detectRuntime);
const mockGetContainerStatus = vi.mocked(getContainerStatus);
const mockIsContainerRunning = vi.mocked(isContainerRunning);
const mockBuildRunCommand = vi.mocked(buildRunCommand);
const mockBuildStartCommand = vi.mocked(buildStartCommand);
const mockBuildStopCommand = vi.mocked(buildStopCommand);
const mockWaitForHealth = vi.mocked(waitForHealth);
const mockCheckHealth = vi.mocked(checkHealth);
const mockRegisterMCP = vi.mocked(registerMCP);
const mockIsClaudeAvailable = vi.mocked(isClaudeAvailable);
const mockOpenBrowser = vi.mocked(openBrowser);
const mockExecSync = vi.mocked(execSync);

const HEALTH_URL = "http://localhost:9470/api/v1/health";
const HEALTH_RESPONSE = { status: "ok", version: "0.1.0" };

beforeEach(() => {
  vi.resetAllMocks();
  // Default: docker available, claude not available
  mockDetectRuntime.mockReturnValue("docker");
  mockBuildRunCommand.mockReturnValue(
    "docker run -d --name straylight-ai -p 9470:9470 ghcr.io/aj-geddes/straylight-ai:latest"
  );
  mockBuildStartCommand.mockReturnValue("docker start straylight-ai");
  mockBuildStopCommand.mockReturnValue("docker stop straylight-ai");
  mockWaitForHealth.mockResolvedValue(HEALTH_RESPONSE);
  mockCheckHealth.mockResolvedValue(HEALTH_RESPONSE);
  mockRegisterMCP.mockResolvedValue(false);
  mockIsClaudeAvailable.mockReturnValue(false);
  mockOpenBrowser.mockResolvedValue(undefined);
  mockExecSync.mockReturnValue(Buffer.from(""));
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("runSetup", () => {
  it("errors when no container runtime is found", async () => {
    mockDetectRuntime.mockReturnValue(null);
    await expect(runSetup()).rejects.toThrow(/docker|podman/i);
  });

  it("creates and starts container when not found", async () => {
    mockGetContainerStatus.mockResolvedValue("not_found");

    await runSetup();

    expect(mockExecSync).toHaveBeenCalledWith(
      expect.stringContaining("docker run"),
      expect.any(Object)
    );
    expect(mockWaitForHealth).toHaveBeenCalledWith(HEALTH_URL, 30_000);
  });

  it("starts stopped container without re-creating it", async () => {
    mockGetContainerStatus.mockResolvedValue("stopped");

    await runSetup();

    expect(mockExecSync).toHaveBeenCalledWith(
      expect.stringContaining("docker start"),
      expect.any(Object)
    );
    // Should NOT call docker run
    const calls = mockExecSync.mock.calls.map((c) => c[0] as string);
    expect(calls.some((c) => c.includes("docker run"))).toBe(false);
  });

  it("skips container creation when already running", async () => {
    mockGetContainerStatus.mockResolvedValue("running");

    await runSetup();

    // Should not call docker run or docker start
    const calls = mockExecSync.mock.calls.map((c) => c[0] as string);
    expect(calls.some((c) => c.includes("docker run"))).toBe(false);
    expect(calls.some((c) => c.includes("docker start"))).toBe(false);
    // Should still check health
    expect(mockWaitForHealth).toHaveBeenCalled();
  });

  it("registers MCP when claude is available", async () => {
    mockGetContainerStatus.mockResolvedValue("not_found");
    mockRegisterMCP.mockResolvedValue(true);

    await runSetup();

    expect(mockRegisterMCP).toHaveBeenCalled();
  });

  it("opens browser after health check passes", async () => {
    mockGetContainerStatus.mockResolvedValue("not_found");

    await runSetup();

    expect(mockOpenBrowser).toHaveBeenCalledWith("http://localhost:9470");
  });

  it("is idempotent: running twice does not create duplicate containers", async () => {
    // First call: not found -> create
    mockGetContainerStatus.mockResolvedValueOnce("not_found");
    await runSetup();
    const firstCallCount = mockExecSync.mock.calls.filter((c) =>
      (c[0] as string).includes("docker run")
    ).length;

    vi.resetAllMocks();
    mockDetectRuntime.mockReturnValue("docker");
    mockBuildRunCommand.mockReturnValue(
      "docker run -d --name straylight-ai -p 9470:9470 ghcr.io/aj-geddes/straylight-ai:latest"
    );
    mockBuildStartCommand.mockReturnValue("docker start straylight-ai");
    mockWaitForHealth.mockResolvedValue(HEALTH_RESPONSE);
    mockRegisterMCP.mockResolvedValue(false);
    mockOpenBrowser.mockResolvedValue(undefined);
    mockExecSync.mockReturnValue(Buffer.from(""));

    // Second call: already running -> skip create
    mockGetContainerStatus.mockResolvedValueOnce("running");
    await runSetup();
    const secondCallCount = mockExecSync.mock.calls.filter((c) =>
      (c[0] as string).includes("docker run")
    ).length;

    expect(firstCallCount).toBe(1);
    expect(secondCallCount).toBe(0);
  });
});

describe("runStart", () => {
  it("errors when no container runtime is found", async () => {
    mockDetectRuntime.mockReturnValue(null);
    await expect(runStart()).rejects.toThrow(/docker|podman/i);
  });

  it("starts stopped container", async () => {
    mockGetContainerStatus.mockResolvedValue("stopped");

    await runStart();

    expect(mockExecSync).toHaveBeenCalledWith(
      expect.stringContaining("docker start"),
      expect.any(Object)
    );
    expect(mockWaitForHealth).toHaveBeenCalledWith(HEALTH_URL, 30_000);
  });

  it("does not restart already-running container", async () => {
    mockGetContainerStatus.mockResolvedValue("running");

    await runStart();

    expect(mockExecSync).not.toHaveBeenCalled();
  });

  it("errors when container does not exist", async () => {
    mockGetContainerStatus.mockResolvedValue("not_found");
    await expect(runStart()).rejects.toThrow(/not found|setup/i);
  });
});

describe("runStop", () => {
  it("errors when no container runtime is found", async () => {
    mockDetectRuntime.mockReturnValue(null);
    await expect(runStop()).rejects.toThrow(/docker|podman/i);
  });

  it("stops running container", async () => {
    mockIsContainerRunning.mockResolvedValue(true);

    await runStop();

    expect(mockExecSync).toHaveBeenCalledWith(
      expect.stringContaining("docker stop"),
      expect.any(Object)
    );
  });

  it("skips stop when container is not running", async () => {
    mockIsContainerRunning.mockResolvedValue(false);

    await runStop();

    expect(mockExecSync).not.toHaveBeenCalled();
  });
});

describe("runStatus", () => {
  it("errors when no container runtime is found", async () => {
    mockDetectRuntime.mockReturnValue(null);
    await expect(runStatus()).rejects.toThrow(/docker|podman/i);
  });

  it("returns status with health info when container is running", async () => {
    mockGetContainerStatus.mockResolvedValue("running");

    const result = await runStatus();

    expect(result.containerStatus).toBe("running");
    expect(mockCheckHealth).toHaveBeenCalledWith(HEALTH_URL);
  });

  it("returns status without health check when container is stopped", async () => {
    mockGetContainerStatus.mockResolvedValue("stopped");

    const result = await runStatus();

    expect(result.containerStatus).toBe("stopped");
    expect(mockCheckHealth).not.toHaveBeenCalled();
  });

  it("returns not_found status when container does not exist", async () => {
    mockGetContainerStatus.mockResolvedValue("not_found");

    const result = await runStatus();

    expect(result.containerStatus).toBe("not_found");
  });
});
