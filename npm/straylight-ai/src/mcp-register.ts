import fs from "fs";
import os from "os";
import path from "path";
import { execSync } from "child_process";

/** Name used when registering the MCP server */
const MCP_SERVER_NAME = "straylight";

/** Command to launch the MCP stdio server */
const MCP_COMMAND = "npx";

/** Arguments passed to MCP_COMMAND */
const MCP_ARGS: string[] = ["-y", "straylight-ai", "mcp"];

/**
 * Result of a register/unregister operation across all detected AI CLIs.
 */
export interface RegisterResult {
  /** CLI names successfully registered (or unregistered) */
  registered: string[];
  /** CLI names not detected on this machine — skipped cleanly */
  skipped: string[];
  /** Error messages for CLIs that were detected but failed */
  errors: string[];
}

/** Internal per-CLI handler definition */
interface CliHandler {
  name: string;
  isDetected: () => boolean;
  register: () => void;
  unregister: () => void;
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/**
 * Read a JSON file as a plain object. Returns {} if missing or unparseable.
 * Catches ENOENT directly rather than guarding with existsSync, so test mocks
 * only need to stub readFileSync rather than existsSync for file-level checks.
 */
function readJsonFile(filePath: string): Record<string, unknown> {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    return JSON.parse(String(raw)) as Record<string, unknown>;
  } catch {
    // File not found or invalid JSON — start from empty config
    return {};
  }
}

/**
 * Atomically write a JSON object: write to temp file, then rename.
 * Creates parent directories as needed.
 */
function writeJsonFile(
  filePath: string,
  data: Record<string, unknown>
): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.tmp.${Date.now()}`;
  try {
    fs.writeFileSync(tempPath, JSON.stringify(data, null, 2), "utf8");
    fs.renameSync(tempPath, filePath);
  } catch (err) {
    // Clean up temp file on failure
    try {
      if (fs.existsSync(tempPath)) fs.renameSync(tempPath, tempPath + ".err");
    } catch {
      // ignore cleanup failure
    }
    throw err;
  }
}

/**
 * Idempotently set a key under a namespace in a JSON file.
 * Reads → merges → atomic write. Preserves all other keys.
 *
 * @param filePath     Absolute path to the config file
 * @param namespace    Top-level key (e.g. "mcpServers" or "servers")
 * @param serverKey    Key inside the namespace (e.g. "straylight")
 * @param value        Value to set for that key
 */
function setServerEntry(
  filePath: string,
  namespace: string,
  serverKey: string,
  value: Record<string, unknown>
): void {
  const config = readJsonFile(filePath);
  const ns = (config[namespace] ?? {}) as Record<string, unknown>;
  ns[serverKey] = value;
  config[namespace] = ns;
  writeJsonFile(filePath, config);
}

/**
 * Remove a key under a namespace in a JSON file.
 * No-op if the file does not exist or the key is not present.
 * Uses readJsonFile (which handles missing files via catch) to avoid a
 * separate existsSync call, keeping the mock contract simple in tests.
 */
function removeServerEntry(
  filePath: string,
  namespace: string,
  serverKey: string
): void {
  const config = readJsonFile(filePath);
  const ns = config[namespace] as Record<string, unknown> | undefined;
  if (!ns || !(serverKey in ns)) return;
  delete ns[serverKey];
  config[namespace] = ns;
  writeJsonFile(filePath, config);
}

// ─── per-CLI handler factories ───────────────────────────────────────────────

function makeClaudeCodeHandler(): CliHandler {
  return {
    name: "Claude Code",
    isDetected: () => isClaudeAvailable(),
    register: () => {
      execSync(
        `claude mcp add --scope user ${MCP_SERVER_NAME} -- ${MCP_COMMAND} ${MCP_ARGS.join(" ")}`,
        { stdio: "ignore" }
      );
    },
    unregister: () => {
      try {
        execSync(`claude mcp remove ${MCP_SERVER_NAME}`, { stdio: "ignore" });
      } catch {
        // Not registered — treat as success
      }
    },
  };
}

function makeCursorHandler(): CliHandler {
  const configDir = path.join(os.homedir(), ".cursor");
  const configFile = path.join(configDir, "mcp.json");
  return {
    name: "Cursor",
    isDetected: () => fs.existsSync(configDir),
    register: () =>
      setServerEntry(configFile, "mcpServers", MCP_SERVER_NAME, {
        command: MCP_COMMAND,
        args: MCP_ARGS,
      }),
    unregister: () =>
      removeServerEntry(configFile, "mcpServers", MCP_SERVER_NAME),
  };
}

function makeWindsurfHandler(): CliHandler {
  const configDir = path.join(os.homedir(), ".codeium", "windsurf");
  const configFile = path.join(configDir, "mcp_config.json");
  return {
    name: "Windsurf",
    // Windsurf HTTP entries use 'serverUrl'; stdio entries use command/args (no serverUrl)
    isDetected: () => fs.existsSync(configDir),
    register: () =>
      setServerEntry(configFile, "mcpServers", MCP_SERVER_NAME, {
        command: MCP_COMMAND,
        args: MCP_ARGS,
      }),
    unregister: () =>
      removeServerEntry(configFile, "mcpServers", MCP_SERVER_NAME),
  };
}

function makeVsCodeHandler(): CliHandler {
  const configDir = path.join(os.homedir(), ".vscode");
  const configFile = path.join(configDir, "mcp.json");
  return {
    name: "VS Code",
    isDetected: () => fs.existsSync(configDir),
    register: () =>
      setServerEntry(configFile, "servers", MCP_SERVER_NAME, {
        type: "stdio",
        command: MCP_COMMAND,
        args: MCP_ARGS,
      }),
    unregister: () =>
      removeServerEntry(configFile, "servers", MCP_SERVER_NAME),
  };
}

function makeCodexHandler(): CliHandler {
  const configDir = path.join(os.homedir(), ".codex");
  const configFile = path.join(configDir, "mcp.json");
  return {
    name: "Codex",
    isDetected: () => fs.existsSync(configDir),
    register: () =>
      setServerEntry(configFile, "mcpServers", MCP_SERVER_NAME, {
        command: MCP_COMMAND,
        args: MCP_ARGS,
      }),
    unregister: () =>
      removeServerEntry(configFile, "mcpServers", MCP_SERVER_NAME),
  };
}

function makeGeminiHandler(): CliHandler {
  const configDir = path.join(os.homedir(), ".gemini");
  const configFile = path.join(configDir, "settings.json");
  return {
    name: "Gemini CLI",
    isDetected: () => fs.existsSync(configDir),
    register: () =>
      setServerEntry(configFile, "mcpServers", MCP_SERVER_NAME, {
        command: MCP_COMMAND,
        args: MCP_ARGS,
      }),
    unregister: () =>
      removeServerEntry(configFile, "mcpServers", MCP_SERVER_NAME),
  };
}

function buildHandlers(): CliHandler[] {
  return [
    makeClaudeCodeHandler(),
    makeCursorHandler(),
    makeWindsurfHandler(),
    makeVsCodeHandler(),
    makeCodexHandler(),
    makeGeminiHandler(),
  ];
}

// ─── Public API ──────────────────────────────────────────────────────────────

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
 * Register the Straylight MCP stdio server across all detected AI CLIs.
 *
 * - Claude Code: uses `claude mcp add --scope user straylight -- npx -y straylight-ai mcp`
 * - All others: atomic read-merge-write to each tool's config JSON
 * - Idempotent on re-run: existing straylight entry is replaced, not duplicated
 * - Other servers in each config are preserved
 *
 * @returns RegisterResult describing which CLIs were registered, skipped, or errored
 */
export async function registerMCP(): Promise<RegisterResult> {
  const result: RegisterResult = { registered: [], skipped: [], errors: [] };
  for (const handler of buildHandlers()) {
    try {
      if (handler.isDetected()) {
        handler.register();
        result.registered.push(handler.name);
      } else {
        result.skipped.push(handler.name);
      }
    } catch (err) {
      result.errors.push(`${handler.name}: ${(err as Error).message}`);
    }
  }
  return result;
}

/**
 * Unregister the Straylight MCP server from all detected AI CLIs.
 *
 * @returns RegisterResult where `registered` lists CLIs successfully unregistered
 */
export async function unregisterMCP(): Promise<RegisterResult> {
  const result: RegisterResult = { registered: [], skipped: [], errors: [] };
  for (const handler of buildHandlers()) {
    try {
      if (handler.isDetected()) {
        handler.unregister();
        result.registered.push(handler.name);
      } else {
        result.skipped.push(handler.name);
      }
    } catch (err) {
      result.errors.push(`${handler.name}: ${(err as Error).message}`);
    }
  }
  return result;
}

/**
 * Return manual registration instructions for users who prefer to configure
 * each tool themselves.
 */
export function manualRegistrationInstructions(): string {
  return [
    "To register the Straylight MCP server manually:",
    "",
    "Claude Code:",
    `  claude mcp add --scope user ${MCP_SERVER_NAME} -- npx -y straylight-ai mcp`,
    "",
    "Cursor (~/.cursor/mcp.json):",
    `  { "mcpServers": { "${MCP_SERVER_NAME}": { "command": "npx", "args": ["-y", "straylight-ai", "mcp"] } } }`,
    "",
    "Windsurf (~/.codeium/windsurf/mcp_config.json):",
    `  { "mcpServers": { "${MCP_SERVER_NAME}": { "command": "npx", "args": ["-y", "straylight-ai", "mcp"] } } }`,
    "",
    "VS Code (~/.vscode/mcp.json):",
    `  { "servers": { "${MCP_SERVER_NAME}": { "type": "stdio", "command": "npx", "args": ["-y", "straylight-ai", "mcp"] } } }`,
    "",
    "Codex (~/.codex/mcp.json):",
    `  { "mcpServers": { "${MCP_SERVER_NAME}": { "command": "npx", "args": ["-y", "straylight-ai", "mcp"] } } }`,
    "",
    "Gemini CLI (~/.gemini/settings.json):",
    `  { "mcpServers": { "${MCP_SERVER_NAME}": { "command": "npx", "args": ["-y", "straylight-ai", "mcp"] } } }`,
  ].join("\n");
}

/**
 * Return telemetry consent status.
 *
 * Rules (opt-in, off by default):
 * - DO_NOT_TRACK=1 or DO_NOT_TRACK=true → always false
 * - STRAYLIGHT_TELEMETRY=true → true (only if DO_NOT_TRACK not set)
 * - All other cases → false
 *
 * No telemetry data is transmitted by this package; this function exists only
 * to provide a single source of truth for consent gating.
 */
export function getTelemetryConsent(): boolean {
  const dnt = process.env["DO_NOT_TRACK"];
  if (dnt === "1" || dnt === "true") return false;
  return process.env["STRAYLIGHT_TELEMETRY"] === "true";
}
