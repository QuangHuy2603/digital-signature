import "../src/config/env.config.js";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backend = path.resolve(__dirname, "..");
const project = path.resolve(backend, "..");
const children = [
  spawn(process.execPath, [path.join(project, "tsp-service/src/server.js")], { cwd: backend, stdio: "inherit", env: process.env }),
  spawn(process.execPath, [path.join(project, "archive-service/src/server.js")], { cwd: backend, stdio: "inherit", env: process.env }),
  spawn(process.execPath, [path.join(project, "client-agent/src/server.js")], { cwd: backend, stdio: "inherit", env: process.env }),
  spawn(process.execPath, [path.join(backend, "src/server.js")], { cwd: backend, stdio: "inherit", env: process.env }),
];
let stopping = false;
function stop(code = 0) {
  if (stopping) return; stopping = true;
  for (const child of children) if (!child.killed) child.kill("SIGTERM");
  setTimeout(() => process.exit(code), 300);
}
for (const child of children) child.on("exit", (code) => { if (!stopping && code) stop(code); });
process.on("SIGINT", () => stop(0));
process.on("SIGTERM", () => stop(0));
