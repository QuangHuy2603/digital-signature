import "dotenv/config";
import { X509Certificate } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { parseCliArgs, requireArg } from "./cli-args.js";
import { normalizeOfficerId, findOfficerByOfficerId } from "../src/services/officer-account.service.js";
import { findActiveCertificateByOfficerId } from "../src/services/certificate.repository.js";

try {
    const args = parseCliArgs();
    const officerId = normalizeOfficerId(requireArg(args, "officer-id"));
    const officer = findOfficerByOfficerId(officerId);
    if (!officer) throw new Error("OFFICER_NOT_FOUND");
    const record = findActiveCertificateByOfficerId(officerId);
    if (!record) throw new Error("OFFICER_CERTIFICATE_NOT_ASSIGNED");

    const certPath = path.resolve(process.cwd(), record.certificate_path);
    const cert = new X509Certificate(fs.readFileSync(certPath, "utf8"));
    console.log(JSON.stringify({
        officer: {
            user_id: officer.id,
            officer_id: officer.officer_id,
            full_name: officer.full_name,
            email: officer.email,
        },
        certificate: {
            certificate_id: record.certificate_id,
            status: record.status,
            subject: cert.subject,
            issuer: cert.issuer,
            serial_number: cert.serialNumber,
            valid_from: cert.validFrom,
            valid_to: cert.validTo,
            fingerprint_sha256: cert.fingerprint256.replace(/:/g, ""),
            subject_alt_name: cert.subjectAltName,
            public_key_type: cert.publicKey.asymmetricKeyType,
            named_curve: cert.publicKey.asymmetricKeyDetails?.namedCurve || null,
            certificate_path: record.certificate_path,
        },
    }, null, 2));
} catch (error) {
    console.error(error.message);
    process.exitCode = 1;
}
