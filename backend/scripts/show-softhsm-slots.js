import "dotenv/config";
import { spawnSync } from "node:child_process";
const bin = process.env.SOFTHSM2_UTIL_BIN || "softhsm2-util";
const result = spawnSync(bin, ["--show-slots"], { encoding: "utf8", stdio: "pipe", windowsHide: true, env: process.env });
if (result.error) { console.error(`SoftHSM tool unavailable: ${result.error.message}`); process.exit(2); }
process.stdout.write(result.stdout || "");
process.stderr.write(result.stderr || "");
process.exit(result.status || 0);
