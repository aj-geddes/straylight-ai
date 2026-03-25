import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock child_process before importing the module under test
vi.mock("child_process", () => ({
  execSync: vi.fn(),
  spawn: vi.fn(),
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

const mockExecSync = vi.mocked(execSync);

beforeEach(() => {
  vi.resetAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("detectRuntime", () => {
  it("returns docker when docker is available", () => {
    mockExecSync.mockImplementation((cmd: unknown) => {
      const cmdStr = cmd as string;
      if (cmdStr.includes("docker")) return Buffer.from("Docker version 24.0");
      throw new Error("not found");
    });
    expect(detectRuntime()).toBe("docker");
  });

  it("returns podman when only podman is available", () => {
    mockExecSync.mockImplementation((cmd: unknown) => {
      const cmdStr = cmd as string;
      if (cmdStr.includes("docker")) throw new Error("not found");
      if (cmdStr.includes("podman")) return Buffer.from("podman version 4.0");
      throw new Error("not found");
    });
    expect(detectRuntime()).toBe("podman");
  });

  it("returns null when neither docker nor podman is available", () => {
    mockExecSync.mockImplementation(() => {
      throw new Error("command not found");
    });
    expect(detectRuntime()).toBeNull();
  });
});

describe("getContainerStatus", () => {
  it("returns running when container is running", async () => {
    mockExecSync.mockReturnValue(Buffer.from("running\n"));
    const status = await getContainerStatus("docker");
    expect(status).toBe("running");
  });

  it("returns stopped when container is exited", async () => {
    mockExecSync.mockReturnValue(Buffer.from("exited\n"));
    const status = await getContainerStatus("docker");
    expect(status).toBe("stopped");
  });

  it("returns not_found when container does not exist", async () => {
    mockExecSync.mockImplementation(() => {
      throw new Error("No such container");
    });
    const status = await getContainerStatus("docker");
    expect(status).toBe("not_found");
  });
});

describe("isContainerRunning", () => {
  it("returns true when container status is running", async () => {
    mockExecSync.mockReturnValue(Buffer.from("running\n"));
    expect(await isContainerRunning("docker")).toBe(true);
  });

  it("returns false when container status is stopped", async () => {
    mockExecSync.mockReturnValue(Buffer.from("exited\n"));
    expect(await isContainerRunning("docker")).toBe(false);
  });

  it("returns false when container does not exist", async () => {
    mockExecSync.mockImplementation(() => {
      throw new Error("No such container");
    });
    expect(await isContainerRunning("docker")).toBe(false);
  });
});

describe("buildRunCommand", () => {
  it("builds a valid docker run command with required flags", () => {
    const cmd = buildRunCommand("docker");
    expect(cmd).toContain("docker run");
    expect(cmd).toContain("-d");
    expect(cmd).toContain("--name straylight-ai");
    expect(cmd).toContain("-p 9470:9470");
    expect(cmd).toContain("/data");
    expect(cmd).toContain("--restart unless-stopped");
    expect(cmd).toContain("ghcr.io/aj-geddes/straylight-ai:latest");
  });

  it("builds a valid podman run command", () => {
    const cmd = buildRunCommand("podman");
    expect(cmd).toContain("podman run");
    expect(cmd).toContain("--name straylight-ai");
  });
});

describe("buildStartCommand", () => {
  it("builds a docker start command", () => {
    const cmd = buildStartCommand("docker");
    expect(cmd).toBe("docker start straylight-ai");
  });

  it("builds a podman start command", () => {
    const cmd = buildStartCommand("podman");
    expect(cmd).toBe("podman start straylight-ai");
  });
});

describe("buildStopCommand", () => {
  it("builds a docker stop command", () => {
    const cmd = buildStopCommand("docker");
    expect(cmd).toBe("docker stop straylight-ai");
  });

  it("builds a podman stop command", () => {
    const cmd = buildStopCommand("podman");
    expect(cmd).toBe("podman stop straylight-ai");
  });
});
