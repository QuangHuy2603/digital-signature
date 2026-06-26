import crypto from "node:crypto";
import { executeCitizenDigestSigningJob } from "../../client-agent/src/agent-core.js";
console.log("\n=== ATTACK 27 - OFFICER CERTIFICATE USED AS CITIZEN CERTIFICATE ===");
let reason = null;
try {
    await executeCitizenDigestSigningJob({ request_id: crypto.randomUUID(), document_id: "HS-ROLE", user_id: 1, citizen_id: "OFFICER-001", certificate_id: "CERT-OFFICER-001-V1", provider: "software", created_at: new Date().toISOString(), document_digest_sha256: "AA".repeat(32) });
} catch (error) { reason = error.code; }
console.log(`Officer certificate as citizen: ${reason ? "REJECTED" : "ACCEPTED"}`);
console.log(`Reason: ${reason}`);
console.log(`Test result: ${reason === "CERTIFICATE_ROLE_MISMATCH" ? "PASS" : "FAIL"}`);
if (reason !== "CERTIFICATE_ROLE_MISMATCH") process.exitCode = 1;
