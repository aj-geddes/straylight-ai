#!/usr/bin/env node
"use strict";

const path = require("path");

const command = process.argv[2] || "setup";

const validCommands = ["setup", "start", "stop", "status", "upgrade", "mcp"];

if (!validCommands.includes(command)) {
  console.error(`Unknown command: ${command}`);
  console.error(`Valid commands: ${validCommands.join(", ")}`);
  process.exit(1);
}

// The MCP command proxies to the mcp-shim
if (command === "mcp") {
  require(path.join(__dirname, "mcp-shim.js"));
  return;
}

// Dynamically require compiled TypeScript output from dist/
const commandModule = require(path.join(__dirname, "..", "dist", "commands", command + ".js"));

let runner;
if (command === "setup") runner = commandModule.runSetup;
else if (command === "start") runner = commandModule.runStart;
else if (command === "stop") runner = commandModule.runStop;
else if (command === "status") runner = commandModule.runStatus;
else if (command === "upgrade") runner = commandModule.runUpgrade;

if (typeof runner !== "function") {
  console.error(`Internal error: could not find runner for command "${command}"`);
  process.exit(1);
}

runner().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
