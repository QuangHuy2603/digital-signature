import fs from "node:fs";
import path from "node:path";
import {
    loadOfficerCertificateIdentity,
    verifyOfficerCertificate,
} from "../src/crypto/x509-pki.service.js";

const rootPem = fs.readFileSync(path.resolve("../pki/root-ca/root-ca.crt"), "utf8");
const certPem = fs.readFileSync(path.resolve("../pki/officers/OFFICER-001/v1/officer.crt"), "utf8");

function tamperPem(pem) {
    const body = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, "");
    const der = Buffer.from(body, "base64");
    der[Math.floor(der.length * 0.7)] ^= 0x01;
    return `-----BEGIN CERTIFICATE-----\n${der.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
}

let originalAccepted = false;
let tamperedRejected = false;
let reason = "NONE";
try { originalAccepted = loadOfficerCertificateIdentity().metadata.chain_valid === true; } catch {}
try {
    verifyOfficerCertificate({
        officerCertificatePem: tamperPem(certPem),
        rootCertificatePem: rootPem,
    });
} catch (error) {
    tamperedRejected = true;
    reason = error.code || error.name;
}
const passed = originalAccepted && tamperedRejected;
console.log("\n=== ATTACK 8 - TAMPERED OFFICER CERTIFICATE ===");
console.log("Original certificate:", originalAccepted ? "ACCEPTED" : "REJECTED");
console.log("Tampered certificate:", tamperedRejected ? "REJECTED" : "ACCEPTED");
console.log("Reason:", reason);
console.log("Test result:", passed ? "PASS" : "FAIL");
if (!passed) process.exitCode = 1;
