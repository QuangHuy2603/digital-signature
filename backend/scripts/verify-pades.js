import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import { verifyPadesPdf } from "../src/crypto/pades.service.js";

const args = process.argv.slice(2);
const valueOf = (name) => {
    const index = args.indexOf(name);
    return index >= 0 ? args[index + 1] : null;
};
const file = valueOf("--file") || args[0];
const fingerprint = valueOf("--fingerprint") || "";
if (!file) {
    console.error("Usage: npm run pades:verify -- --file <signed.pdf> [--fingerprint <sha256>]");
    process.exit(2);
}
const resolved = path.resolve(file);
if (!fs.existsSync(resolved)) {
    console.error(`File not found: ${resolved}`);
    process.exit(2);
}
const result = verifyPadesPdf({ pdfPath: resolved, expectedFingerprint: fingerprint });
console.log(JSON.stringify(result, null, 2));
console.log(`PADES VERIFICATION: ${result.valid ? "PASS" : "FAIL"}`);
if (!result.valid) process.exitCode = 1;
