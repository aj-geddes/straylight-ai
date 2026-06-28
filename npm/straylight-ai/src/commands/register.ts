import { registerMCP } from "../mcp-register.js";

/**
 * Register the Straylight MCP server across all detected AI CLIs.
 *
 * Prints a summary of which CLIs were registered, which were skipped
 * (not installed), and which encountered errors.
 */
export async function runRegister(): Promise<void> {
  console.log("Registering Straylight MCP server across detected AI CLIs...");

  const result = await registerMCP();

  if (result.registered.length > 0) {
    console.log(`Registered with: ${result.registered.join(", ")}`);
  }

  if (result.skipped.length > 0) {
    console.log(`Skipped (not installed): ${result.skipped.join(", ")}`);
  }

  if (result.errors.length > 0) {
    console.log(`Errors: ${result.errors.join("; ")}`);
  }

  if (result.registered.length === 0 && result.errors.length === 0) {
    console.log("No AI CLI tools detected. Nothing was registered.");
  }
}
