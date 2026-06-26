import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { extractPadesContainer, getPadesStatus } from "../../src/crypto/pades.service.js";
import { verifyPadesLtEvidence } from "../../src/crypto/pades-lt.service.js";
import { createPadesLtFixture } from "../helpers/pades-fixture.js";

function replaceAscii(buffer, from, to) {
    if (Buffer.byteLength(from, "ascii") !== Buffer.byteLength(to, "ascii")) {
        throw new Error("Replacement must preserve byte length");
    }
    const output = Buffer.from(buffer);
    const index = output.indexOf(Buffer.from(from, "ascii"));
    if (index < 0) throw new Error(`Marker not found: ${from}`);
    Buffer.from(to, "ascii").copy(output, index);
    return output;
}

function flipEmbedded(buffer, needle, offset = 16) {
    const output = Buffer.from(buffer);
    const index = output.indexOf(needle);
    if (index < 0) throw new Error("Embedded evidence was not found");
    const target = index + Math.min(offset, needle.length - 1);
    output[target] ^= 0x01;
    return output;
}

function crlDer() {
    const result = spawnSync(process.env.OPENSSL_BIN || "openssl", [
        "crl", "-in", path.resolve(process.cwd(), "../pki/root-ca/root-ca.crl"), "-outform", "DER",
    ], { encoding: null, windowsHide: true });
    if (result.status !== 0) throw new Error(String(result.stderr || "Unable to convert CRL"));
    return Buffer.from(result.stdout);
}

describe("PAdES-LT DSS/VRI", () => {
    let fixture;

    const previousSigningProvider = process.env.SIGNING_PROVIDER;
    const previousRuntimeProbe = process.env.SOFTHSM_RUNTIME_PROBE;

    beforeAll(async () => {
        // Unit/security fixture uses the local software certificate.
        // Real SoftHSM is covered by the separate remote E2E test.
        process.env.SIGNING_PROVIDER = "file";
        process.env.SOFTHSM_RUNTIME_PROBE = "false";

        fixture = await createPadesLtFixture();
    }, 120000);

    afterAll(() => {
        fixture?.cleanup();

        if (previousSigningProvider === undefined) {
            delete process.env.SIGNING_PROVIDER;
        } else {
            process.env.SIGNING_PROVIDER = previousSigningProvider;
        }

        if (previousRuntimeProbe === undefined) {
            delete process.env.SOFTHSM_RUNTIME_PROBE;
        } else {
            process.env.SOFTHSM_RUNTIME_PROBE = previousRuntimeProbe;
        }
    });

    function verifyLt(buffer, signatureTimestamp = fixture.verification.timestamp) {
        const extracted = extractPadesContainer(buffer);
        return verifyPadesLtEvidence({
            pdfBuffer: buffer,
            cmsDer: extracted.cmsDer,
            signedRevisionLength: extracted.signedRevisionLength,
            expectedFingerprint: fixture.certificateRecord.fingerprint_sha256,
            signatureTimestamp,
        });
    }

    it("creates and verifies a PAdES-LT PDF", () => {
        expect(fixture.verification.valid).toBe(true);
        expect(fixture.verification.reason).toBe("VALID_PADES_LT");
        expect(fixture.verification.baseline_level).toBe("PAdES-LT");
    });

    it("keeps PAdES-LTA outside the claimed PAdES-LT profile", () => {
        const status = getPadesStatus();
        expect(status.supported_levels).toContain("PAdES-LT");
        expect(status.supported_levels).not.toContain("PAdES-LTA");
    });

    it("embeds DSS, VRI, certificate chain, OCSP and CRL evidence", () => {
        expect(fixture.verification.dss_present).toBe(true);
        expect(fixture.verification.vri_present).toBe(true);
        expect(fixture.verification.pades_lt.vri_binding_valid).toBe(true);
        expect(fixture.verification.pades_lt.embedded_certificate_count).toBeGreaterThanOrEqual(4);
        expect(fixture.verification.pades_lt.embedded_ocsp_count).toBe(1);
        expect(fixture.verification.pades_lt.embedded_crl_count).toBe(1);
        expect(fixture.verification.offline_verification_ready).toBe(true);
    });

    it("preserves the original PAdES-B-T signed revision", () => {
        expect(fixture.evidence.verification.valid).toBe(true);
        expect(fixture.evidence.verification.baseline_level).toBe("PAdES-B-T");
        expect(fixture.verification.signed_revision_length).toBe(fs.statSync(fixture.signedBtPdfPath).size);
    });

    it("rejects a PDF whose catalog no longer references DSS", () => {
        const tampered = replaceAscii(fixture.signedPdfBytes, "/DSS", "/DSX");
        const result = verifyLt(tampered);
        expect(result.valid).toBe(false);
        expect(result.reason).toBe("PADES_DSS_MISSING");
    });

    it("rejects a PDF whose DSS no longer contains VRI", () => {
        const tampered = replaceAscii(fixture.signedPdfBytes, "/VRI", "/VRX");
        const result = verifyLt(tampered);
        expect(result.valid).toBe(false);
        expect(["PADES_VRI_BINDING_INVALID", "PADES_VRI_MISSING"]).toContain(result.reason);
    });

    it("rejects a modified embedded signer certificate", () => {
        const certificate = new crypto.X509Certificate(
            fs.readFileSync(path.resolve(process.cwd(), fixture.certificateRecord.certificate_path))
        );
        const tampered = flipEmbedded(fixture.signedPdfBytes, certificate.raw, 24);
        const result = verifyLt(tampered);
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/^PADES_EMBEDDED_/);
    });

    it("rejects a modified embedded OCSP response", () => {
        const ocsp = Buffer.from(fixture.ocspEvidence.response_der_base64, "base64");
        const tampered = flipEmbedded(fixture.signedPdfBytes, ocsp, 32);
        const result = verifyLt(tampered);
        expect(result.valid).toBe(false);
        expect(result.reason).toBe("PADES_EMBEDDED_OCSP_INVALID");
    });

    it("rejects a modified embedded CRL", () => {
        const tampered = flipEmbedded(fixture.signedPdfBytes, crlDer(), 24);
        const result = verifyLt(tampered);
        expect(result.valid).toBe(false);
        expect(result.reason).toBe("PADES_EMBEDDED_CRL_INVALID");
    });

    it("rejects a VRI key that is not bound to the CMS signature", () => {
        const key = fixture.ltEvidence.vri_key_sha1;
        const replacement = `${key[0] === "A" ? "B" : "A"}${key.slice(1)}`;
        const tampered = replaceAscii(fixture.signedPdfBytes, `/${key}`, `/${replacement}`);
        const result = verifyLt(tampered);
        expect(result.valid).toBe(false);
        expect(result.reason).toBe("PADES_VRI_BINDING_INVALID");
    });

    it("rejects arbitrary bytes appended after the final incremental revision", () => {
        const tampered = Buffer.concat([fixture.signedPdfBytes, Buffer.from("UNAUTHORISED", "ascii")]);
        const result = verifyLt(tampered);
        expect(result.valid).toBe(false);
        expect(result.reason).toBe("PADES_LT_INCREMENTAL_UPDATE_INVALID");
    });

    it("rejects validation evidence collected outside the trusted signing-time window", () => {
        const extracted = extractPadesContainer(fixture.signedPdfBytes);
        const result = verifyPadesLtEvidence({
            pdfBuffer: fixture.signedPdfBytes,
            cmsDer: extracted.cmsDer,
            signedRevisionLength: extracted.signedRevisionLength,
            expectedFingerprint: fixture.certificateRecord.fingerprint_sha256,
            signatureTimestamp: "2000-01-01T00:00:00.000Z",
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toBe("PADES_LT_EVIDENCE_TIME_INVALID");
    });
});
