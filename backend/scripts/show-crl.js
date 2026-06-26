import "dotenv/config";
import { spawnSync } from "node:child_process";
import { PKI_CRL_PATH, OPENSSL_BIN } from "../src/config/env.config.js";

const result = spawnSync(OPENSSL_BIN, [
    "crl", "-in", PKI_CRL_PATH, "-text", "-noout",
], {
    cwd: process.cwd(),
    encoding: "utf8",
    windowsHide: true,
});

if (result.error || result.status !== 0) {
    console.error(result.error?.message || result.stderr || "Unable to show CRL");
    process.exitCode = 1;
} else {
    console.log(result.stdout);
}
