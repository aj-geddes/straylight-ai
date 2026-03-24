import { execSync } from "child_process";
import {
  detectRuntime,
  getContainerStatus,
  buildStartCommand,
} from "../docker.js";
import { waitForHealth } from "../health.js";

const HEALTH_URL = "http://localhost:9470/api/v1/health";
const HEALTH_TIMEOUT_MS = 30_000;

/**
 * Start an existing stopped container and wait for health.
 * Errors if the container does not exist (use `setup` instead).
 */
export async function runStart(): Promise<void> {
  const runtime = detectRuntime();
  if (!runtime) {
    throw new Error(
      "Neither Docker nor Podman was found on your PATH.\n" +
        "Install Docker Desktop: https://docs.docker.com/get-docker/"
    );
  }

  const status = await getContainerStatus(runtime);

  if (status === "not_found") {
    throw new Error(
      "Straylight-AI container not found. Run `npx straylight-ai setup` first."
    );
  }

  if (status === "running") {
    console.log("Straylight-AI is already running.");
    return;
  }

  console.log("Starting Straylight-AI...");
  execSync(buildStartCommand(runtime), { stdio: "inherit" });

  console.log("Waiting for Straylight-AI to be ready...");
  await waitForHealth(HEALTH_URL, HEALTH_TIMEOUT_MS);
  console.log("Straylight-AI is ready at http://localhost:9470");
}
