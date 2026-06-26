import { describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
    buildOpenSslIndex,
    checkCertificateRevocation,
    normalizeCertificateSerial,
    normalizeRevocationReason,
    verifyCertificateRevocationList,
} from "../../src/crypto/crl.service.js";
import { ensureCertificateRecordActive } from "../../src/crypto/officer-pki.service.js";
import { findActiveCertificateByOfficerId } from "../../src/services/certificate.repository.js";
import { PKI_CRL_PATH } from "../../src/config/env.config.js";

describe("Certificate lifecycle and CRL", () => {
    it("accepts an active certificate record before signing", () => {
        const record = findActiveCertificateByOfficerId("OFFICER-001");
        expect(() => ensureCertificateRecordActive(record)).not.toThrow();
    });

    it("rejects a revoked certificate record before signing", () => {
        const record = findActiveCertificateByOfficerId("OFFICER-001");
        expect(() => ensureCertificateRecordActive({
            ...record,
            status: "revoked",
            revoked_at: new Date().toISOString(),
        })).toThrowError(expect.objectContaining({
            code: "OFFICER_CERTIFICATE_REVOKED",
        }));
    });

    it("rejects a superseded certificate for new signatures", () => {
        const record = findActiveCertificateByOfficerId("OFFICER-001");
        expect(() => ensureCertificateRecordActive({
            ...record,
            status: "superseded",
        })).toThrowError(expect.objectContaining({
            code: "OFFICER_CERTIFICATE_NOT_ACTIVE",
        }));
    });

    it("builds an OpenSSL CA database row with revocation reason", () => {
        const index = buildOpenSslIndex([{
            certificate_id: "CERT-TEST-V1",
            status: "revoked",
            serial_number: "00A1B2",
            subject: "C=VN\nCN=Revoked Test",
            valid_to: "2028-06-24T00:00:00.000Z",
            revoked_at: "2026-06-24T00:00:00.000Z",
            revocation_reason: "keyCompromise",
        }]);
        expect(index).toContain("R\t280624000000Z\t260624000000Z,keyCompromise");
        expect(index).toContain("A1B2");
        expect(index).toContain("/C=VN/CN=Revoked Test");
    });

    it("verifies the live CRL signature with the trusted Root CA", () => {
        const result = verifyCertificateRevocationList();
        expect(result.available).toBe(true);
        expect(result.signature_valid).toBe(true);
        expect(result.reason).toBe("CRL_VALID");
    });

    it("reports the active officer certificate as not revoked", () => {
        const record = findActiveCertificateByOfficerId("OFFICER-001");
        const result = checkCertificateRevocation({ certificateRecord: record });
        expect(result.checked).toBe(true);
        expect(result.trusted).toBe(true);
        expect(result.revoked).toBe(false);
    });

    it("rejects a modified CRL", () => {
        const source = path.resolve(process.cwd(), PKI_CRL_PATH);
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-crl-test-"));
        const target = path.join(directory, "tampered.crl");
        try {
            const lines = fs.readFileSync(source, "utf8").trim().split(/\r?\n/);
            const bodyIndex = lines.findIndex((line) => !line.startsWith("-----"));
            lines[bodyIndex] = (lines[bodyIndex][0] === "A" ? "B" : "A") + lines[bodyIndex].slice(1);
            fs.writeFileSync(target, `${lines.join("\n")}\n`, "ascii");
            const result = verifyCertificateRevocationList({ crlPath: target });
            expect(result.signature_valid).toBe(false);
            expect(result.reason).toBe("CRL_SIGNATURE_INVALID");
        } finally {
            fs.rmSync(directory, { recursive: true, force: true });
        }
    });

    it("normalizes certificate serial numbers consistently", () => {
        expect(normalizeCertificateSerial("00:0a:bC")).toBe("ABC");
    });

    it("rejects unsupported revocation reasons", () => {
        expect(() => normalizeRevocationReason("madeUpReason"))
            .toThrowError(expect.objectContaining({
                code: "INVALID_REVOCATION_REASON",
            }));
    });
});
