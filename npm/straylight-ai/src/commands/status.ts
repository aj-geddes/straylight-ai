import { detectRuntime, getContainerStatus } from "../docker.js";
import { checkHealth, HealthResponse } from "../health.js";

const HEALTH_URL = "http://localhost:9470/api/v1/health";

/** Result returned by runStatus */
export interface StatusResult {
  containerStatus: "running" | "stopped" | "not_found";
  health?: HealthResponse;
}

/**
 * Check the container status and, if running, fetch and display health info.
 */
export async function runStatus(): Promise<StatusResult> {
  const runtime = detectRuntime();
  if (!runtime) {
    throw new Error(
      "Neither Docker nor Podman was found on your PATH.\n" +
        "Install Docker Desktop: https://docs.docker.com/get-docker/"
    );
  }

  const containerStatus = await getContainerStatus(runtime);

  const result: StatusResult = { containerStatus };

  if (containerStatus === "running") {
    try {
      result.health = await checkHealth(HEALTH_URL);
      console.log("Straylight-AI is running.");
      console.log(`  Status: ${result.health.status}`);
      if (result.health.version) {
        console.log(`  Version: ${result.health.version}`);
      }
      console.log("  URL: http://localhost:9470");
    } catch {
      console.log("Straylight-AI container is running but not yet healthy.");
    }
  } else if (containerStatus === "stopped") {
    console.log(
      'Straylight-AI container is stopped. Run `npx straylight-ai start` to start it.'
    );
  } else {
    console.log(
      'Straylight-AI is not installed. Run `npx straylight-ai setup` to get started.'
    );
  }

  return result;
}
