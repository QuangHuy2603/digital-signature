import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import { verifyOfficerCertificate } from "../src/crypto/x509-pki.service.js";

const officerCertificatePem = fs.readFileSync(
    path.resolve("../pki/officers/OFFICER-001/v1/officer.crt"),
    "utf8"
);
const rootCertificatePem = fs.readFileSync(
    path.resolve("../pki/root-ca/root-ca.crt"),
    "utf8"
);

let trustedAccepted = false;
let crossOfficerRejected = false;
let reason = null;

try {
    verifyOfficerCertificate({
        officerCertificatePem,
        rootCertificatePem,
        expectedOfficerId: "OFFICER-001",
        expectedEmail: "officer@test.com",
    });
    trustedAccepted = true;
} catch {
    trustedAccepted = false;
}

try {
    verifyOfficerCertificate({
        officerCertificatePem,
        rootCertificatePem,
        expectedOfficerId: "OFFICER-999",
    });
} catch (error) {
    crossOfficerRejected = true;
    reason = error.code;
}

const passed = trustedAccepted &&
    crossOfficerRejected &&
    reason === "OFFICER_CERTIFICATE_OWNER_MISMATCH";

console.log("\n=== ATTACK 9 - CROSS-OFFICER CERTIFICATE MISUSE ===");
console.log("Correct officer binding:", trustedAccepted ? "ACCEPTED" : "REJECTED");
console.log("Certificate used as another officer:", crossOfficerRejected ? "REJECTED" : "ACCEPTED");
console.log("Reason:", reason || "NONE");
console.log("Expected reason: OFFICER_CERTIFICATE_OWNER_MISMATCH");
console.log("Test result:", passed ? "PASS" : "FAIL");

if (!passed) process.exitCode = 1;
