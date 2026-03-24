import { spawn } from "child_process";
import * as os from "os";

/**
 * Open the given URL in the system's default browser.
 * Best-effort: failure is silent to avoid blocking the setup flow.
 */
export async function openBrowser(url: string): Promise<void> {
  const platform = os.platform();
  let command: string;

  if (platform === "darwin") {
    command = "open";
  } else if (platform === "win32") {
    command = "start";
  } else {
    command = "xdg-open";
  }

  return new Promise<void>((resolve) => {
    try {
      const child = spawn(command, [url], {
        stdio: "ignore",
        detached: true,
      });
      child.unref();
    } catch {
      // Best-effort: ignore errors opening the browser
    }
    // Resolve immediately; we don't wait for the browser to finish
    resolve();
  });
}
