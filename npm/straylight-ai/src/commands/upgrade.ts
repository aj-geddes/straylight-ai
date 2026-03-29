import { execSync } from "child_process";
import {
  detectRuntime,
  getContainerStatus,
  getContainerImageId,
  getImageId,
  pullImage,
  removeContainer,
  buildRunCommand,
} from "../docker.js";
import { waitForHealth } from "../health.js";

const HEALTH_URL = "http://localhost:9470/api/v1/health";
const HEALTH_TIMEOUT_MS = 30_000;

/**
 * Upgrade Straylight-AI to the latest image.
 * Pulls the latest image, stops and removes the old container (preserving
 * the data volume), and starts a new container from the updated image.
 */
export async function runUpgrade(): Promise<void> {
  const runtime = detectRuntime();
  if (!runtime) {
    throw new Error(
      "Neither Docker nor Podman was found on your PATH.\n" +
        "Install Docker Desktop: https://docs.docker.com/get-docker/\n" +
        "or Podman: https://podman.io/getting-started/installation"
    );
  }

  console.log(`Using container runtime: ${runtime}`);

  // Pull the latest image.
  console.log("Pulling latest Straylight-AI image...");
  const changed = pullImage(runtime);

  const status = await getContainerStatus(runtime);

  if (status === "not_found") {
    console.log("No existing container found. Creating...");
    execSync(buildRunCommand(runtime), { stdio: "inherit" });
  } else {
    const containerImage = getContainerImageId(runtime);
    const latestImage = getImageId(runtime);

    if (!changed && containerImage === latestImage) {
      console.log("Already running the latest image. Nothing to upgrade.");
      return;
    }

    console.log("Stopping and replacing container (data volume preserved)...");
    removeContainer(runtime);
    execSync(buildRunCommand(runtime), { stdio: "inherit" });
  }

  console.log("Waiting for Straylight-AI to be ready...");
  await waitForHealth(HEALTH_URL, HEALTH_TIMEOUT_MS);
  console.log("Straylight-AI upgraded and running at http://localhost:9470");
}
