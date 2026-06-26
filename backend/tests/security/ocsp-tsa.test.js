import { describe, expect, it } from "vitest";
import { findActiveCertificateByOfficerId } from "../../src/services/certificate.repository.js";
import {
    generateOcspResponse,
    verifyOcspResponse,
    checkCertificateStatusWithOcsp,
    parseOcspResponseText,
} from "../../src/crypto/ocsp.service.js";
import {
    createTimestampToken,
    verifyTimestampToken,
    getTsaStatus,
} from "../../src/crypto/tsa.service.js";

describe("OCSP validation RFC 6960 OCSP", () => {
    const record = findActiveCertificateByOfficerId("OFFICER-001");

    it("returns GOOD for the active officer certificate", () => {
        const response = generateOcspResponse({ serialNumber: record.serial_number, certificateId: record.certificate_id });
        expect(response.certificate_status).toBe("good");
        expect(response.response_signature_valid).toBe(true);
        expect(response.stale).toBe(false);
    }, 30000);

    it("verifies the signed DER OCSP response", () => {
        const response = generateOcspResponse({ serialNumber: record.serial_number, certificateId: record.certificate_id });
        const verified = verifyOcspResponse({ requestDerBase64: response.request_der_base64, responseDerBase64: response.response_der_base64 });
        expect(verified.valid).toBe(true);
        expect(verified.certificate_status).toBe("good");
    }, 30000);

    it("rejects a modified OCSP response", () => {
        const response = generateOcspResponse({ serialNumber: record.serial_number });
        const bytes = Buffer.from(response.response_der_base64, "base64");
        const tampered = bytes.subarray(0, Math.max(1, bytes.length - 17));
        const verified = verifyOcspResponse({ requestDerBase64: response.request_der_base64, responseDerBase64: tampered.toString("base64") });
        expect(verified.valid).toBe(false);
        expect(verified.reason).toBe("OCSP_RESPONSE_SIGNATURE_INVALID");
    }, 30000);

    it("rejects a stale OCSP response", () => {
        const response = generateOcspResponse({ serialNumber: record.serial_number });
        const future = new Date(new Date(response.next_update).getTime() + 1000);
        const verified = verifyOcspResponse({ requestDerBase64: response.request_der_base64, responseDerBase64: response.response_der_base64, now: future });
        expect(verified.valid).toBe(false);
        expect(verified.reason).toBe("OCSP_RESPONSE_STALE");
    }, 30000);

    it("falls back to a signed CRL when OCSP is unavailable", () => {
        const checked = checkCertificateStatusWithOcsp({ certificateRecord: record, responderCertPath: "../pki/ocsp/not-found.crt", allowCrlFallback: true, includeDer: false });
        expect(checked.source).toBe("CRL_FALLBACK");
        expect(checked.trusted).toBe(true);
        expect(checked.revoked).toBe(false);
    });

    it("parses an unknown OCSP status", () => {
        expect(parseOcspResponseText("Cert Status: unknown\nSerial Number: DEADBEEF").certificate_status).toBe("unknown");
    });
});

describe("RFC 3161 timestamping", () => {
    it("reports the test TSA as ready", () => {
        expect(getTsaStatus().ready).toBe(true);
    });

    it("creates and verifies a timestamp token", () => {
        const data = Buffer.from("certificate signature bytes", "utf8");
        const token = createTimestampToken({ dataBuffer: data });
        const verified = verifyTimestampToken({ dataBuffer: data, responseDerBase64: token.response_der_base64 });
        expect(token.protocol).toBe("RFC3161");
        expect(verified.valid).toBe(true);
        expect(verified.policy_oid).toBeTruthy();
        expect(verified.timestamp).toBeTruthy();
    }, 30000);

    it("rejects a timestamp for different data", () => {
        const token = createTimestampToken({ dataBuffer: Buffer.from("original", "utf8") });
        const verified = verifyTimestampToken({ dataBuffer: Buffer.from("changed", "utf8"), responseDerBase64: token.response_der_base64 });
        expect(verified.valid).toBe(false);
    }, 30000);

    it("rejects a modified timestamp response", () => {
        const data = Buffer.from("original", "utf8");
        const token = createTimestampToken({ dataBuffer: data });
        const bytes = Buffer.from(token.response_der_base64, "base64");
        bytes[Math.floor(bytes.length / 2)] ^= 1;
        const verified = verifyTimestampToken({ dataBuffer: data, responseDerBase64: bytes.toString("base64") });
        expect(verified.valid).toBe(false);
    }, 30000);
});
