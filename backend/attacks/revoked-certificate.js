import "dotenv/config";
import { findActiveCertificateByOfficerId } from "../src/services/certificate.repository.js";
import { ensureCertificateRecordActive } from "../src/crypto/officer-pki.service.js";

const active = findActiveCertificateByOfficerId("OFFICER-001");
let originalAccepted = false;
let revokedRejected = false;
let reason = null;

try {
    ensureCertificateRecordActive(active);
    originalAccepted = true;
} catch {
    originalAccepted = false;
}

try {
    ensureCertificateRecordActive({
        ...active,
        status: "revoked",
        revoked_at: new Date().toISOString(),
        revocation_reason: "keyCompromise",
    });
} catch (error) {
    revokedRejected = error.code === "OFFICER_CERTIFICATE_REVOKED";
    reason = error.code || error.message;
}

const passed = originalAccepted && revokedRejected;
console.log("\n=== ATTACK 10 - REVOKED OFFICER CERTIFICATE ===");
console.log("Active certificate signing:", originalAccepted ? "ACCEPTED" : "REJECTED");
console.log("Revoked certificate signing:", revokedRejected ? "REJECTED" : "ACCEPTED");
console.log("Reason:", reason || "-");
console.log("Expected reason: OFFICER_CERTIFICATE_REVOKED");
console.log("Test result:", passed ? "PASS" : "FAIL");
if (!passed) process.exitCode = 1;
