import "dotenv/config";
import { findActiveCertificateByOfficerId } from "../src/services/certificate.repository.js";
import { checkCertificateStatusWithOcsp } from "../src/crypto/ocsp.service.js";
const record = findActiveCertificateByOfficerId("OFFICER-001");
const result = checkCertificateStatusWithOcsp({
    certificateRecord: record,
    responderCertPath: "../pki/ocsp/missing-responder.crt",
    allowCrlFallback: true,
    includeDer: false,
});
const passed = result.source === "CRL_FALLBACK" && result.trusted === true && result.revoked === false;
console.log("\n=== ATTACK 14 - OCSP OUTAGE WITH CRL FALLBACK ===");
console.log("OCSP source:", result.source);
console.log("CRL fallback trusted:", result.trusted ? "YES" : "NO");
console.log("Certificate revoked:", result.revoked ? "YES" : "NO");
console.log("Test result:", passed ? "PASS" : "FAIL");
if (!passed) process.exitCode = 1;
