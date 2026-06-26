import "dotenv/config";
import { parseCliArgs, requireArg } from "./cli-args.js";
import { revokeOfficerCertificate } from "../src/services/certificate-revocation.service.js";

try {
    const args = parseCliArgs();
    const certificateId = requireArg(args, "certificate-id");
    const reason = args.reason || "unspecified";

    const result = await revokeOfficerCertificate({
        certificateId,
        reason,
        actorId: "pki-cli",
    });

    console.log("\nCERTIFICATE REVOCATION: PASS");
    console.log(JSON.stringify({
        certificate_id: result.certificate.certificate_id,
        officer_id: result.certificate.officer_id,
        status: result.certificate.status,
        revoked_at: result.certificate.revoked_at,
        revocation_reason: result.certificate.revocation_reason,
        active_certificate_id: result.officer?.active_certificate_id || null,
        crl_signature_valid: result.crl.signature_valid,
        crl_number: result.crl.crl_number,
        crl_revoked_count: result.crl.revoked_count,
    }, null, 2));
} catch (error) {
    console.error("\nCERTIFICATE REVOCATION: FAIL");
    console.error(error.code || error.message);
    console.error(error.message);
    process.exitCode = 1;
}
