import "dotenv/config";
import { generateCertificateRevocationList } from "../src/crypto/crl.service.js";
import { writeAuditLog } from "../src/services/audit.service.js";

try {
    const result = generateCertificateRevocationList();
    await writeAuditLog({
        action: "CRL_GENERATED",
        userId: "pki-cli",
        result: "success",
        details: {
            crl_number: result.crl_number,
            revoked_count: result.revoked_count,
            fingerprint_sha256: result.fingerprint_sha256,
        },
    });
    console.log("\nCRL GENERATION: PASS");
    console.log(JSON.stringify(result, null, 2));
} catch (error) {
    console.error("\nCRL GENERATION: FAIL");
    console.error(error.code || error.message);
    console.error(error.message);
    process.exitCode = 1;
}
