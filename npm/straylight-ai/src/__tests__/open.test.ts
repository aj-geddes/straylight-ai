import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("child_process", () => ({
  spawn: vi.fn(),
}));

import { spawn } from "child_process";
import { openBrowser } from "../open.js";

const mockSpawn = vi.mocked(spawn);

/** Creates a minimal EventEmitter-like mock child process. */
function makeChildMock() {
  return {
    unref: vi.fn(),
    on: vi.fn(),
  };
}

beforeEach(() => {
  vi.resetAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("openBrowser", () => {
  it("calls spawn with the URL and detached option", async () => {
    const child = makeChildMock();
    // Return typed mock - cast needed because spawn returns full ChildProcess
    mockSpawn.mockReturnValue(child as unknown as ReturnType<typeof spawn>);

    await openBrowser("http://localhost:9470");

    expect(mockSpawn).toHaveBeenCalledWith(
      expect.any(String),
      ["http://localhost:9470"],
      expect.objectContaining({ detached: true })
    );
  });

  it("calls unref on the child process to detach it", async () => {
    const child = makeChildMock();
    mockSpawn.mockReturnValue(child as unknown as ReturnType<typeof spawn>);

    await openBrowser("http://localhost:9470");

    expect(child.unref).toHaveBeenCalled();
  });

  it("resolves without error even when spawn fails", async () => {
    // spawn throws synchronously
    mockSpawn.mockImplementation(() => {
      throw new Error("spawn ENOENT");
    });

    // Should not throw (best-effort open)
    await expect(openBrowser("http://localhost:9470")).resolves.toBeUndefined();
  });
});
