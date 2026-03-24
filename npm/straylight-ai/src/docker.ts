import { execSync } from "child_process";
import * as os from "os";
import * as path from "path";

/** Name of the managed container */
export const CONTAINER_NAME = "straylight-ai";

/** Docker image to pull and run */
export const CONTAINER_IMAGE = "ghcr.io/straylight-ai/straylight:latest";

/** Host port mapped to container port 9470 */
export const CONTAINER_PORT = 9470;

/** Host data directory mounted at /data inside the container */
export const DATA_DIR = path.join(os.homedir(), ".straylight-ai", "data");

/** Container status values */
export type ContainerStatus = "running" | "stopped" | "not_found";

/** Supported container runtimes */
export type Runtime = "docker" | "podman";

/**
 * Detect whether docker or podman is available on the host.
 * Returns the first available runtime, or null if neither is found.
 */
export function detectRuntime(): Runtime | null {
  for (const runtime of ["docker", "podman"] as Runtime[]) {
    try {
      execSync(`${runtime} --version`, { stdio: "pipe" });
      return runtime;
    } catch {
      // try the next one
    }
  }
  return null;
}

/**
 * Get the status of the straylight-ai container.
 */
export async function getContainerStatus(
  runtime: string
): Promise<ContainerStatus> {
  try {
    const output = execSync(
      `${runtime} inspect --format "{{.State.Status}}" ${CONTAINER_NAME}`,
      { stdio: "pipe" }
    )
      .toString()
      .trim()
      .replace(/^"|"$/g, ""); // strip surrounding quotes if present

    if (output === "running") return "running";
    return "stopped";
  } catch {
    return "not_found";
  }
}

/**
 * Returns true when the container is currently running.
 */
export async function isContainerRunning(runtime: string): Promise<boolean> {
  return (await getContainerStatus(runtime)) === "running";
}

/**
 * Build the docker/podman run command string.
 */
export function buildRunCommand(runtime: string): string {
  return [
    `${runtime} run`,
    "-d",
    `--name ${CONTAINER_NAME}`,
    `-p ${CONTAINER_PORT}:${CONTAINER_PORT}`,
    `-v ${DATA_DIR}:/data`,
    "--restart unless-stopped",
    CONTAINER_IMAGE,
  ].join(" ");
}

/**
 * Build the docker/podman start command string.
 */
export function buildStartCommand(runtime: string): string {
  return `${runtime} start ${CONTAINER_NAME}`;
}

/**
 * Build the docker/podman stop command string.
 */
export function buildStopCommand(runtime: string): string {
  return `${runtime} stop ${CONTAINER_NAME}`;
}

/**
 * Pull the container image.
 */
export function pullImage(runtime: string): void {
  execSync(`${runtime} pull ${CONTAINER_IMAGE}`, { stdio: "inherit" });
}
