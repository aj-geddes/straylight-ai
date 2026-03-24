import { execSync } from "child_process";
import {
  detectRuntime,
  isContainerRunning,
  buildStopCommand,
} from "../docker.js";

/**
 * Stop the running Straylight-AI container.
 * No-op if the container is not currently running.
 */
export async function runStop(): Promise<void> {
  const runtime = detectRuntime();
  if (!runtime) {
    throw new Error(
      "Neither Docker nor Podman was found on your PATH.\n" +
        "Install Docker Desktop: https://docs.docker.com/get-docker/"
    );
  }

  const running = await isContainerRunning(runtime);

  if (!running) {
    console.log("Straylight-AI is not currently running.");
    return;
  }

  console.log("Stopping Straylight-AI...");
  execSync(buildStopCommand(runtime), { stdio: "inherit" });
  console.log("Straylight-AI stopped.");
}
