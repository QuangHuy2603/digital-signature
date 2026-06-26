import fs from "node:fs";
import path from "node:path";
import {
    loadOfficerCertificateIdentity,
    verifyOfficerCertificate,
} from "../src/crypto/x509-pki.service.js";

const rootPem = fs.readFileSync(
    path.resolve("../pki/root-ca/root-ca.crt"),
    "utf8"
);
const roguePem = fs.readFileSync(
    path.resolve("../pki/test-fixtures/rogue/rogue-officer.crt"),
    "utf8"
);

let trustedAccepted = false;
let rogueRejected = false;
let reason = "NONE";

try {
    trustedAccepted = loadOfficerCertificateIdentity().metadata.chain_valid === true;
} catch {}

try {
    verifyOfficerCertificate({
        officerCertificatePem: roguePem,
        rootCertificatePem: rootPem,
    });
} catch (error) {
    rogueRejected = true;
    reason = error.code || error.name;
}

const passed = trustedAccepted && rogueRejected &&
    reason === "UNTRUSTED_CERTIFICATE_ISSUER";

console.log("\n=== ATTACK 7 - UNTRUSTED OFFICER CERTIFICATE ===");
console.log("Trusted officer certificate:", trustedAccepted ? "ACCEPTED" : "REJECTED");
console.log("Certificate from rogue CA:", rogueRejected ? "REJECTED" : "ACCEPTED");
console.log("Reason:", reason);
console.log("Expected reason: UNTRUSTED_CERTIFICATE_ISSUER");
console.log("Test result:", passed ? "PASS" : "FAIL");
if (!passed) process.exitCode = 1;
