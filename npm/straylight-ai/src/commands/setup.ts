import { execSync } from "child_process";
import {
  detectRuntime,
  getContainerStatus,
  buildRunCommand,
  buildStartCommand,
} from "../docker.js";
import { waitForHealth } from "../health.js";
import { registerMCP, manualRegistrationInstructions } from "../mcp-register.js";
import { openBrowser } from "../open.js";

const HEALTH_URL = "http://localhost:9470/api/v1/health";
const HEALTH_TIMEOUT_MS = 30_000;
const UI_URL = "http://localhost:9470";

/**
 * Full bootstrap: pull image if needed, create/start container, wait for
 * health check, register MCP server, and open the browser.
 *
 * This operation is idempotent: calling it when the container is already
 * running will skip the create/start steps and go straight to health + open.
 */
export async function runSetup(): Promise<void> {
  const runtime = detectRuntime();
  if (!runtime) {
    throw new Error(
      "Neither Docker nor Podman was found on your PATH.\n" +
        "Install Docker Desktop: https://docs.docker.com/get-docker/\n" +
        "or Podman: https://podman.io/getting-started/installation"
    );
  }

  console.log(`Using container runtime: ${runtime}`);

  const status = await getContainerStatus(runtime);

  if (status === "not_found") {
    console.log("Creating and starting Straylight-AI container...");
    execSync(buildRunCommand(runtime), { stdio: "inherit" });
  } else if (status === "stopped") {
    console.log("Starting existing Straylight-AI container...");
    execSync(buildStartCommand(runtime), { stdio: "inherit" });
  } else {
    console.log("Straylight-AI container is already running.");
  }

  console.log("Waiting for Straylight-AI to be ready...");
  await waitForHealth(HEALTH_URL, HEALTH_TIMEOUT_MS);
  console.log("Straylight-AI is ready.");

  const registered = await registerMCP();
  if (registered) {
    console.log("MCP server registered with Claude Code.");
  } else {
    console.log(manualRegistrationInstructions());
  }

  await openBrowser(UI_URL);

  console.log(
    [
      "",
      "Straylight-AI is running at http://localhost:9470",
      "",
      "Next steps:",
      "  1. Open http://localhost:9470 in your browser",
      "  2. Add your service credentials via the Web UI",
      "  3. Use Claude Code with the straylight-ai MCP server",
      "",
    ].join("\n")
  );
}
