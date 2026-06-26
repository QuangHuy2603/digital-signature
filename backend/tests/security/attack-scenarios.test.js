import fs from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createPadesFixture } from "../helpers/pades-fixture.js";
import { extractPadesContainer, verifyPadesPdf } from "../../src/crypto/pades.service.js";

let fixture;
let original;

beforeAll(async () => {
    fixture = await createPadesFixture();
    original = verifyPadesPdf({
        pdfPath: fixture.signedPdfPath,
        expectedFingerprint: fixture.certificateRecord.fingerprint_sha256,
    });
}, 60000);
afterAll(() => fixture?.cleanup());

describe("PAdES-B-T security PAdES-B-T security scenarios", () => {
    it("creates a valid PAdES-B-T PDF", () => {
        expect(original.valid).toBe(true);
        expect(original.baseline_level).toBe("PAdES-B-T");
        expect(original.subfilter).toBe("ETSI.CAdES.detached");
    });
    it("uses a valid ByteRange and CMS signature", () => {
        expect(original.byte_range_valid).toBe(true);
        expect(original.cms_signature_valid).toBe(true);
    });
    it("contains the CAdES signing-certificate attribute and RFC3161 timestamp", () => {
        expect(original.cades_signing_certificate_attribute).toBe(true);
        expect(original.timestamp_valid).toBe(true);
    });
    it("rejects PDF content modified after signing", () => {
        const modified = Buffer.from(fixture.signedPdfBytes);
        const index = Math.max(16, Math.floor(original.byte_range[1] / 2));
        modified[index] ^= 0x01;
        expect(verifyPadesPdf({ pdfBuffer: modified }).valid).toBe(false);
    });
    it("rejects modified embedded CMS bytes", () => {
        const extracted = extractPadesContainer(fixture.signedPdfBytes);
        const cmsHex = extracted.cmsDer.toString("hex").toUpperCase();
        const ascii = fixture.signedPdfBytes.toString("ascii");
        const start = ascii.indexOf(cmsHex);
        expect(start).toBeGreaterThan(0);
        const modified = Buffer.from(fixture.signedPdfBytes);
        const position = start + Math.floor(cmsHex.length / 2);
        modified[position] = modified[position] === 0x41 ? 0x42 : 0x41;
        expect(verifyPadesPdf({ pdfBuffer: modified }).valid).toBe(false);
    });
    it("rejects a mismatched expected signer certificate", () => {
        const result = verifyPadesPdf({
            pdfPath: fixture.signedPdfPath,
            expectedFingerprint: "00".repeat(32),
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toBe("PADES_SIGNER_CERTIFICATE_MISMATCH");
    });
    it("rejects a PDF without a digital signature field", () => {
        const result = verifyPadesPdf({ pdfPath: fixture.inputPdfPath });
        expect(result.valid).toBe(false);
        expect(result.reason).toBe("PADES_SIGNATURE_NOT_FOUND");
    });
});
