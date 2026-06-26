import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
    loadOfficerCertificateIdentity,
    signPayloadWithOfficerCertificate,
    verifyCertificateBackedSignature,
    verifyOfficerCertificate,
    OfficerCertificateError,
} from "../../src/crypto/x509-pki.service.js";

const read = (relativePath) => fs.readFileSync(
    path.resolve(process.cwd(), relativePath),
    "utf8"
);

const officerCert = read("../pki/officers/OFFICER-001/v1/officer.crt");
const rootCert = read("../pki/root-ca/root-ca.crt");
const rogueOfficerCert = read("../pki/test-fixtures/rogue/rogue-officer.crt");

function tamperPem(pem) {
    const body = pem
        .replace(/-----BEGIN CERTIFICATE-----/g, "")
        .replace(/-----END CERTIFICATE-----/g, "")
        .replace(/\s/g, "");
    const der = Buffer.from(body, "base64");
    der[Math.floor(der.length * 0.7)] ^= 0x01;
    const changed = der.toString("base64").match(/.{1,64}/g).join("\n");
    return `-----BEGIN CERTIFICATE-----\n${changed}\n-----END CERTIFICATE-----\n`;
}

describe("multi-officer PKI X.509 officer identity", () => {
    it("accepts the configured officer certificate issued by the NT219 Test Root CA", () => {
        const identity = loadOfficerCertificateIdentity();
        expect(identity.metadata.chain_valid).toBe(true);
        expect(identity.metadata.subject).toContain("Can bo Nguyen");
        expect(identity.metadata.officer_id).toBe("OFFICER-001");
        expect(identity.metadata.issuer).toContain("NT219 Test Root CA");
        expect(identity.metadata.public_key_type).toBe("ec");
    });

    it("signs and verifies the canonical payload with the certificate-backed ECDSA key", () => {
        const payload = JSON.stringify({ document_id: "HS-PKI-001", hash: "abc" });
        const signed = signPayloadWithOfficerCertificate(payload);
        const verified = verifyCertificateBackedSignature({
            payload,
            signatureBase64: signed.signature,
            officerCertificatePem: signed.certificate_pem,
            expectedFingerprint: signed.certificate_metadata.fingerprint_sha256,
        });
        expect(signed.algorithm).toBe("ECDSA-P256-SHA256");
        expect(verified.chain_valid).toBe(true);
        expect(verified.signature_valid).toBe(true);
    });

    it("rejects a certificate issued by a rogue CA", () => {
        expect(() => verifyOfficerCertificate({
            officerCertificatePem: rogueOfficerCert,
            rootCertificatePem: rootCert,
        })).toThrowError(expect.objectContaining({
            code: "UNTRUSTED_CERTIFICATE_ISSUER",
        }));
    });

    it("rejects a tampered officer certificate", () => {
        expect(() => verifyOfficerCertificate({
            officerCertificatePem: tamperPem(officerCert),
            rootCertificatePem: rootCert,
        })).toThrow(OfficerCertificateError);
    });

    it("rejects a pinned fingerprint mismatch", () => {
        expect(() => verifyOfficerCertificate({
            officerCertificatePem: officerCert,
            rootCertificatePem: rootCert,
            expectedFingerprint: "00".repeat(32),
        })).toThrowError(expect.objectContaining({
            code: "OFFICER_CERTIFICATE_FINGERPRINT_MISMATCH",
        }));
    });

    it("rejects the officer certificate after its validity period", () => {
        expect(() => verifyOfficerCertificate({
            officerCertificatePem: officerCert,
            rootCertificatePem: rootCert,
            now: new Date("2034-01-01T00:00:00.000Z"),
        })).toThrowError(expect.objectContaining({
            code: "OFFICER_CERTIFICATE_EXPIRED",
        }));
    });

    it("rejects a private key that does not match the officer certificate", () => {
        expect(() => signPayloadWithOfficerCertificate("payload", {
            officerPrivateKeyPath: "../pki/root-ca/root-ca.key",
        })).toThrowError(expect.objectContaining({
            code: "OFFICER_CERTIFICATE_KEY_MISMATCH",
        }));
    });
});
