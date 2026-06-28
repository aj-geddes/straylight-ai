import { unregisterMCP } from "../mcp-register.js";

/**
 * Unregister the Straylight MCP server from all detected AI CLIs.
 *
 * Prints a summary of which CLIs were unregistered, which were skipped,
 * and which encountered errors.
 */
export async function runUnregister(): Promise<void> {
  console.log("Unregistering Straylight MCP server from detected AI CLIs...");

  const result = await unregisterMCP();

  if (result.registered.length > 0) {
    console.log(`Unregistered from: ${result.registered.join(", ")}`);
  }

  if (result.skipped.length > 0) {
    console.log(`Skipped (not installed): ${result.skipped.join(", ")}`);
  }

  if (result.errors.length > 0) {
    console.log(`Errors: ${result.errors.join("; ")}`);
  }

  if (result.registered.length === 0 && result.errors.length === 0) {
    console.log("No AI CLI tools detected. Nothing was unregistered.");
  }
}
