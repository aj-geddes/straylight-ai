import { execSync, spawnSync } from "child_process";

/** Name to use when registering the MCP server */
const MCP_SERVER_NAME = "straylight-ai";

/**
 * Check whether the Claude Code CLI is available on PATH.
 */
export function isClaudeAvailable(): boolean {
  try {
    execSync("claude --version", { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

/**
 * Register the Straylight-AI MCP server with Claude Code.
 *
 * Runs:
 *   claude mcp add straylight-ai --transport stdio -- npx straylight-ai mcp
 *
 * @returns true on success, false if claude is unavailable or the command fails.
 */
export async function registerMCP(): Promise<boolean> {
  if (!isClaudeAvailable()) {
    return false;
  }

  const result = spawnSync(
    "claude",
    [
      "mcp",
      "add",
      MCP_SERVER_NAME,
      "--transport",
      "stdio",
      "--",
      "npx",
      "straylight-ai",
      "mcp",
    ],
    { stdio: "pipe" }
  );

  return result.status === 0;
}

/**
 * Build the manual registration instructions string for users who do not have
 * Claude Code installed.
 */
export function manualRegistrationInstructions(): string {
  return [
    "To register the MCP server manually, run:",
    "",
    "  claude mcp add straylight-ai --transport stdio -- npx straylight-ai mcp",
    "",
    "Or add it directly to your Claude Code settings.",
  ].join("\n");
}
