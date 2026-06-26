import "dotenv/config";
import { verifyCertificateRevocationList } from "../src/crypto/crl.service.js";
import { writeAuditLog } from "../src/services/audit.service.js";

const result = verifyCertificateRevocationList();
await writeAuditLog({
    action: "CRL_VERIFIED",
    userId: "pki-cli",
    result: result.signature_valid ? "success" : "fail",
    details: {
        reason: result.reason,
        crl_number: result.crl_number ?? null,
        revoked_count: result.revoked_count ?? 0,
    },
});

console.log("\nCRL VERIFICATION:", result.signature_valid ? "PASS" : "FAIL");
console.log(JSON.stringify(result, null, 2));
if (!result.signature_valid) process.exitCode = 1;
