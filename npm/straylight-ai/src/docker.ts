import { execSync } from "child_process";

/** Name of the managed container */
export const CONTAINER_NAME = "straylight-ai";

/** Docker image to pull and run */
export const CONTAINER_IMAGE = "ghcr.io/aj-geddes/straylight-ai:latest";

/** Host port mapped to container port 9470 */
export const CONTAINER_PORT = 9470;

/** Named Docker volume mounted at /data inside the container */
export const VOLUME_NAME = "straylight-ai-data";

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
    `-v ${VOLUME_NAME}:/data`,
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
 * Pull the container image. Returns true if a newer image was downloaded.
 */
export function pullImage(runtime: string): boolean {
  const before = getImageId(runtime);
  execSync(`${runtime} pull ${CONTAINER_IMAGE}`, { stdio: "inherit" });
  const after = getImageId(runtime);
  return before !== after;
}

/**
 * Returns the image ID for the container image, or null if not present.
 */
export function getImageId(runtime: string): string | null {
  try {
    return execSync(
      `${runtime} image inspect --format "{{.Id}}" ${CONTAINER_IMAGE}`,
      { stdio: "pipe" }
    )
      .toString()
      .trim()
      .replace(/^"|"$/g, "");
  } catch {
    return null;
  }
}

/**
 * Returns the image ID that a running/stopped container was created from.
 */
export function getContainerImageId(runtime: string): string | null {
  try {
    return execSync(
      `${runtime} inspect --format "{{.Image}}" ${CONTAINER_NAME}`,
      { stdio: "pipe" }
    )
      .toString()
      .trim()
      .replace(/^"|"$/g, "");
  } catch {
    return null;
  }
}

/**
 * Stop and remove the container (preserves the named volume).
 */
export function removeContainer(runtime: string): void {
  try {
    execSync(`${runtime} stop ${CONTAINER_NAME}`, { stdio: "pipe" });
  } catch {
    // already stopped
  }
  try {
    execSync(`${runtime} rm ${CONTAINER_NAME}`, { stdio: "pipe" });
  } catch {
    // already removed
  }
}
