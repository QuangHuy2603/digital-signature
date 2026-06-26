import "dotenv/config";
import { spawnSync } from "node:child_process";
const bin = process.env.SOFTHSM2_UTIL_BIN || "softhsm2-util";
const label = process.env.SOFTHSM_TOKEN_LABEL || "NT219-TSP";
const soPin = process.env.SOFTHSM_SO_PIN;
const userPin = process.env.SOFTHSM_USER_PIN;
if (!soPin || !userPin) { console.error("Set SOFTHSM_SO_PIN and SOFTHSM_USER_PIN in backend/.env"); process.exit(2); }
const result = spawnSync(bin, ["--init-token", "--free", "--label", label, "--so-pin", soPin, "--pin", userPin], {
  encoding: "utf8", stdio: "pipe", windowsHide: true, env: process.env,
});
if (result.error) { console.error(`SoftHSM tool unavailable: ${result.error.message}`); process.exit(2); }
process.stdout.write(result.stdout || ""); process.stderr.write(result.stderr || ""); process.exit(result.status || 0);
