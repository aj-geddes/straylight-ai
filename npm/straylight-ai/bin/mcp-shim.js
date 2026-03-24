#!/usr/bin/env node
"use strict";

/**
 * MCP binary launcher for Straylight-AI.
 *
 * Resolution order:
 *   1. Platform-specific binary from optionalDependencies
 *      (@straylight-ai/bin-<platform>-<arch>)
 *   2. Docker exec fallback: `docker exec -i straylight-ai straylight-mcp`
 *
 * stdin/stdout/stderr are passed through so the MCP host can communicate
 * over stdio as required by the MCP protocol.
 */

const { spawn } = require("child_process");
const path = require("path");
const os = require("os");

const CONTAINER_NAME = "straylight-ai";
const BIN_NAME = os.platform() === "win32" ? "straylight-mcp.exe" : "straylight-mcp";

function tryLocalBinary() {
  const platform = os.platform();
  // Map Node's os.arch() to the arch strings used in package names
  const archMap = { x64: "x64", arm64: "arm64" };
  const arch = archMap[os.arch()];
  if (!arch) return null;

  const pkgName = `@straylight-ai/bin-${platform}-${arch}`;

  try {
    const pkgJsonPath = require.resolve(`${pkgName}/package.json`);
    const binPath = path.join(path.dirname(pkgJsonPath), BIN_NAME);
    return binPath;
  } catch {
    return null;
  }
}

function execBinary(binPath, args) {
  const child = spawn(binPath, args, { stdio: "inherit" });
  child.on("error", (err) => {
    console.error(`Failed to launch ${binPath}: ${err.message}`);
    process.exit(1);
  });
  child.on("exit", (code) => {
    process.exit(code ?? 1);
  });
}

function execDockerFallback(args) {
  // Check that docker (or podman) is available
  const { execSync } = require("child_process");
  let runtime = null;
  for (const rt of ["docker", "podman"]) {
    try {
      execSync(`${rt} --version`, { stdio: "pipe" });
      runtime = rt;
      break;
    } catch {
      // continue
    }
  }

  if (!runtime) {
    console.error(
      "straylight-mcp: no local binary and no container runtime found.\n" +
        "Install Docker: https://docs.docker.com/get-docker/\n" +
        "or run `npx straylight-ai setup` first."
    );
    process.exit(1);
  }

  execBinary(runtime, ["exec", "-i", CONTAINER_NAME, "straylight-mcp", ...args]);
}

const localBin = tryLocalBinary();
const extraArgs = process.argv.slice(2);

if (localBin) {
  execBinary(localBin, extraArgs);
} else {
  execDockerFallback(extraArgs);
}
