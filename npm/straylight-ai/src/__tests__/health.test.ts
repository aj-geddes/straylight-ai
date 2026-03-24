import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

import { waitForHealth, checkHealth } from "../health.js";

beforeEach(() => {
  vi.resetAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("checkHealth", () => {
  it("returns health response when endpoint is healthy", async () => {
    const healthData = { status: "ok", version: "0.1.0" };
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => healthData,
    });

    const result = await checkHealth("http://localhost:9470/api/v1/health");
    expect(result).toEqual(healthData);
  });

  it("throws when fetch returns non-ok status", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 503,
    });

    await expect(
      checkHealth("http://localhost:9470/api/v1/health")
    ).rejects.toThrow();
  });

  it("throws when fetch rejects (connection refused)", async () => {
    mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));

    await expect(
      checkHealth("http://localhost:9470/api/v1/health")
    ).rejects.toThrow("ECONNREFUSED");
  });
});

describe("waitForHealth", () => {
  it("resolves immediately when health check passes on first attempt", async () => {
    const healthData = { status: "ok", version: "0.1.0" };
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => healthData,
    });

    const result = await waitForHealth(
      "http://localhost:9470/api/v1/health",
      30_000
    );
    expect(result).toEqual(healthData);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("retries until health check passes within timeout", async () => {
    const healthData = { status: "ok", version: "0.1.0" };
    // Fail 2 times, then succeed
    mockFetch
      .mockRejectedValueOnce(new Error("ECONNREFUSED"))
      .mockRejectedValueOnce(new Error("ECONNREFUSED"))
      .mockResolvedValue({
        ok: true,
        json: async () => healthData,
      });

    // Use fake timers so we don't actually wait 2 seconds
    vi.useFakeTimers();
    const promise = waitForHealth(
      "http://localhost:9470/api/v1/health",
      30_000
    );
    // Advance past the sleep intervals
    await vi.runAllTimersAsync();
    const result = await promise;
    vi.useRealTimers();

    expect(result).toEqual(healthData);
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it("rejects when health check never passes within timeout", async () => {
    mockFetch.mockRejectedValue(new Error("ECONNREFUSED"));

    vi.useFakeTimers();

    // Attach rejection handler before advancing timers so the rejection
    // is never unhandled.
    const promise = waitForHealth("http://localhost:9470/api/v1/health", 1_000);
    const rejection = expect(promise).rejects.toThrow(/timed out|timeout/i);

    // Advance time past the deadline and flush all microtasks
    await vi.advanceTimersByTimeAsync(2_000);
    vi.useRealTimers();

    await rejection;
  });
});
