import "dotenv/config";
import fs from "node:fs";
import { sign, verify, createPrivateKey } from "node:crypto";
import { parseCliArgs, requireArg } from "./cli-args.js";
import { findOfficerByOfficerId, normalizeOfficerId } from "../src/services/officer-account.service.js";
import { findActiveCertificateByOfficerId } from "../src/services/certificate.repository.js";
import { loadOfficerCertificateIdentity, readRequiredPkiFile } from "../src/crypto/x509-pki.service.js";

try {
    const args = parseCliArgs();
    const officerId = normalizeOfficerId(requireArg(args, "officer-id"));
    const officer = findOfficerByOfficerId(officerId);
    if (!officer) throw new Error("OFFICER_NOT_FOUND");

    const record = findActiveCertificateByOfficerId(officerId);
    if (!record) throw new Error("OFFICER_CERTIFICATE_NOT_ASSIGNED");

    const identity = loadOfficerCertificateIdentity({
        officerCertPath: record.certificate_path,
        rootCertPath: record.root_ca_certificate_path,
        expectedFingerprint: record.fingerprint_sha256,
        expectedOfficerId: officerId,
        expectedEmail: officer.email,
    });

    const privateKeyPem = readRequiredPkiFile(
        record.private_key_path,
        "OFFICER_PRIVATE_KEY_NOT_FOUND"
    ).content;
    const privateKey = createPrivateKey(privateKeyPem);
    const message = Buffer.from(`NT219 officer certificate check ${officerId}`, "utf8");
    const signature = sign("sha256", message, privateKey);
    const keyMatches = verify(
        "sha256",
        message,
        identity.officerCertificate.publicKey,
        signature
    );
    if (!keyMatches) throw new Error("OFFICER_CERTIFICATE_KEY_MISMATCH");

    if (!fs.existsSync(identity.officerCertificatePath)) {
        throw new Error("OFFICER_CERTIFICATE_NOT_FOUND");
    }

    console.log("\nOFFICER CERTIFICATE VERIFICATION: PASS");
    console.log(JSON.stringify({
        officer_id: officerId,
        full_name: officer.full_name,
        email: officer.email,
        certificate_id: record.certificate_id,
        status: record.status,
        subject: identity.metadata.subject,
        issuer: identity.metadata.issuer,
        fingerprint_sha256: identity.metadata.fingerprint_sha256,
        chain_valid: identity.metadata.chain_valid,
        private_key_matches: keyMatches,
        valid_from: identity.metadata.valid_from,
        valid_to: identity.metadata.valid_to,
    }, null, 2));
} catch (error) {
    console.error("\nOFFICER CERTIFICATE VERIFICATION: FAIL");
    console.error(error.message);
    process.exitCode = 1;
}
