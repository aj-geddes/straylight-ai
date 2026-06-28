import { execSync } from "child_process";
import {
  detectRuntime,
  getContainerStatus,
  getContainerImageId,
  getImageId,
  pullImage,
  removeContainer,
  buildRunCommand,
  buildStartCommand,
} from "../docker.js";
import { waitForHealth } from "../health.js";
import {
  registerMCP,
  manualRegistrationInstructions,
} from "../mcp-register.js";
import { openBrowser } from "../open.js";

const HEALTH_URL = "http://localhost:9470/api/v1/health";
const HEALTH_TIMEOUT_MS = 30_000;
const UI_URL = "http://localhost:9470";

/**
 * Check Docker is installed and reachable. Throws with an actionable error
 * message if not.
 */
function assertDockerRunning(runtime: string): void {
  try {
    execSync(`${runtime} info`, { stdio: "pipe" });
  } catch {
    throw new Error(
      `${runtime} is installed but not running.\n` +
        `Start Docker Desktop (or run 'sudo systemctl start docker') and try again.\n` +
        `Install guide: https://docs.docker.com/get-docker/`
    );
  }
}

/**
 * Full bootstrap: preflight → pull latest image → create/start container
 * (upgrading if the image changed) → wait for health → register MCP server
 * across all detected CLIs → print success block → auto-open browser.
 *
 * This operation is idempotent: calling it when the container is already
 * running on the latest image will skip the create/start steps and go
 * straight to health + open.
 *
 * Telemetry is opt-in only (off by default). The getTelemetryConsent()
 * function gates any future telemetry; no data is transmitted here.
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

  // Preflight: verify Docker/Podman is actually running
  assertDockerRunning(runtime);

  console.log(`Using container runtime: ${runtime}`);

  // Always pull the latest image first.
  console.log("Pulling latest Straylight-AI image...");
  pullImage(runtime);

  const status = await getContainerStatus(runtime);

  if (status === "not_found") {
    console.log("Creating and starting Straylight-AI container...");
    execSync(buildRunCommand(runtime), { stdio: "inherit" });
  } else {
    // Container exists — check if it needs upgrading.
    const containerImage = getContainerImageId(runtime);
    const latestImage = getImageId(runtime);

    if (containerImage && latestImage && containerImage !== latestImage) {
      console.log("New image available — upgrading container...");
      removeContainer(runtime);
      execSync(buildRunCommand(runtime), { stdio: "inherit" });
    } else if (status === "stopped") {
      console.log("Starting existing Straylight-AI container...");
      execSync(buildStartCommand(runtime), { stdio: "inherit" });
    } else {
      console.log("Straylight-AI container is already running (up to date).");
    }
  }

  console.log("Waiting for Straylight-AI to be ready...");
  await waitForHealth(HEALTH_URL, HEALTH_TIMEOUT_MS);
  console.log("Straylight-AI is ready.");

  // Register across all detected AI CLIs
  const mcpResult = await registerMCP();


  // Print success block
  const registeredLine =
    mcpResult.registered.length > 0
      ? `Registered with: ${mcpResult.registered.join(", ")}`
      : manualRegistrationInstructions();

  const skippedLine =
    mcpResult.skipped.length > 0
      ? `Skipped (not installed): ${mcpResult.skipped.join(", ")}`
      : null;

  const errorLine =
    mcpResult.errors.length > 0
      ? `Registration errors: ${mcpResult.errors.join("; ")}`
      : null;

  console.log(
    [
      "",
      "Straylight-AI is ready at http://localhost:9470",
      "",
      registeredLine,
      skippedLine,
      errorLine,
      "",
      "Next steps:",
      "  1. Open http://localhost:9470 in your browser",
      "  2. Add your service credentials via the Services page",
      "  3. Use your AI coding tool with the straylight MCP server",
      "",
      "Telemetry: off by default. Set STRAYLIGHT_TELEMETRY=true to opt in.",
      "",
    ]
      .filter((line) => line !== null)
      .join("\n")
  );

  await openBrowser(UI_URL);
}
