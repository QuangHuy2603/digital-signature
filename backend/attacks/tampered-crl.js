import "dotenv/config";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { verifyCertificateRevocationList } from "../src/crypto/crl.service.js";
import { PKI_CRL_PATH } from "../src/config/env.config.js";

const sourcePath = path.resolve(process.cwd(), PKI_CRL_PATH);
const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-crl-attack-"));
const tamperedPath = path.join(tempDirectory, "tampered-root-ca.crl");

try {
    const original = verifyCertificateRevocationList();
    const pem = fs.readFileSync(sourcePath, "utf8");
    const lines = pem.trim().split(/\r?\n/);
    const bodyIndex = lines.findIndex((line) => !line.startsWith("-----"));
    if (bodyIndex < 0) throw new Error("CRL PEM body was not found");

    const line = lines[bodyIndex];
    const replacement = line[0] === "A" ? "B" : "A";
    lines[bodyIndex] = replacement + line.slice(1);
    fs.writeFileSync(tamperedPath, `${lines.join("\n")}\n`, "ascii");

    const attacked = verifyCertificateRevocationList({
        crlPath: tamperedPath,
    });
    const passed = original.signature_valid === true && attacked.signature_valid === false;

    console.log("\n=== ATTACK 11 - TAMPERED CRL ===");
    console.log("Original CRL:", original.signature_valid ? "VALID" : "INVALID");
    console.log("Tampered CRL:", attacked.signature_valid ? "VALID" : "REJECTED");
    console.log("Reason:", attacked.reason);
    console.log("Expected reason: CRL_SIGNATURE_INVALID");
    console.log("Test result:", passed ? "PASS" : "FAIL");
    if (!passed) process.exitCode = 1;
} finally {
    fs.rmSync(tempDirectory, { recursive: true, force: true });
}
