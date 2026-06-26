import { describe, expect, it } from "vitest";
import {
    loadOfficerSigningIdentity,
    signPayloadForOfficer,
    getMultiOfficerPkiStatus,
} from "../../src/crypto/officer-pki.service.js";
import {
    verifyCertificateBackedSignature,
    verifyOfficerCertificate,
} from "../../src/crypto/x509-pki.service.js";
import { findCertificateById } from "../../src/services/certificate.repository.js";
import { findOfficerByOfficerId } from "../../src/services/officer-account.service.js";
import fs from "node:fs";
import path from "node:path";

const read = (relativePath) => fs.readFileSync(
    path.resolve(process.cwd(), relativePath),
    "utf8"
);

describe("multi-officer PKI multi-officer certificate binding", () => {
    it("binds OFFICER-001 to its own active certificate", async () => {
        const officer = findOfficerByOfficerId("OFFICER-001");
        expect(officer.active_certificate_id).toBe("CERT-OFFICER-001-V1");

        const record = findCertificateById(officer.active_certificate_id);
        expect(record.user_id).toBe(officer.id);
        expect(record.officer_id).toBe(officer.officer_id);
        expect(record.status).toBe("active");

        const loaded = await loadOfficerSigningIdentity(officer.id);
        expect(loaded.identity.metadata.officer_id).toBe("OFFICER-001");
        expect(loaded.identity.metadata.email).toBe("officer@test.com");
    });

    it("signs with the certificate selected from the authenticated user id", async () => {
        const payload = JSON.stringify({ document_id: "HS-MULTI-001", hash: "abc" });
        const signed = await signPayloadForOfficer(payload, 1);

        const verified = verifyCertificateBackedSignature({
            payload,
            signatureBase64: signed.signature,
            officerCertificatePem: signed.certificate_pem,
            expectedFingerprint: signed.certificate_metadata.fingerprint_sha256,
            expectedOfficerId: signed.user.officer_id,
            expectedEmail: signed.user.email,
        });

        expect(signed.certificate_record.certificate_id).toBe("CERT-OFFICER-001-V1");
        expect(verified.chain_valid).toBe(true);
        expect(verified.signature_valid).toBe(true);
        expect(verified.metadata.officer_id).toBe("OFFICER-001");
    });

    it("rejects a citizen account as a certificate-backed officer signer", async () => {
        await expect(loadOfficerSigningIdentity(4)).rejects.toMatchObject({
            code: "USER_IS_NOT_OFFICER",
        });
    });

    it("rejects a certificate when the expected officer_id is different", () => {
        const officerCert = read("../pki/officers/OFFICER-001/v1/officer.crt");
        const rootCert = read("../pki/root-ca/root-ca.crt");

        expect(() => verifyOfficerCertificate({
            officerCertificatePem: officerCert,
            rootCertificatePem: rootCert,
            expectedOfficerId: "OFFICER-999",
        })).toThrowError(expect.objectContaining({
            code: "OFFICER_CERTIFICATE_OWNER_MISMATCH",
        }));
    });

    it("reports the active multi-officer PKI registry", () => {
        const status = getMultiOfficerPkiStatus();
        expect(status.status).toBe("ready");
        expect(status.active_certificates).toBeGreaterThanOrEqual(1);
        expect(status.certificates).toEqual(expect.arrayContaining([
            expect.objectContaining({
                certificate_id: "CERT-OFFICER-001-V1",
                officer_id: "OFFICER-001",
                status: "active",
            }),
        ]));
    });
});
