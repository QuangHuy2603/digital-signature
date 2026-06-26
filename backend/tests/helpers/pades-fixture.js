import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PDFDocument, StandardFonts } from "pdf-lib";
import { findCertificateById } from "../../src/services/certificate.repository.js";
import { createPadesBtSignature } from "../../src/crypto/pades.service.js";

export async function createPadesFixture({
    certificateId = "CERT-OFFICER-001-V1",
    text = "NT219 PAdES-B-T security fixture",
} = {}) {
    const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-pades-fixture-"));
    const inputPdfPath = path.join(tempDirectory, "input.pdf");
    const signedPdfPath = path.join(tempDirectory, "signed.pdf");
    const pdf = await PDFDocument.create();
    const page = pdf.addPage([595, 842]);
    const font = await pdf.embedFont(StandardFonts.Helvetica);
    page.drawText(text, { x: 48, y: 780, size: 16, font });
    page.drawText("QR is embedded before the PAdES signature in the application flow.", {
        x: 48, y: 750, size: 10, font,
    });
    fs.writeFileSync(inputPdfPath, await pdf.save());
    const certificateRecord = findCertificateById(certificateId);
    if (!certificateRecord) throw new Error(`Certificate ${certificateId} was not found`);
    const evidence = await createPadesBtSignature({
        inputPdfPath,
        outputPdfPath: signedPdfPath,
        certificateRecord,
        signer: {
            full_name: certificateRecord.full_name || "Can bo Nguyen",
            email: certificateRecord.email || "officer@test.com",
        },
        evidenceDirectory: path.join(tempDirectory, "timestamps"),
    });
    return {
        tempDirectory,
        inputPdfPath,
        signedPdfPath,
        signedPdfBytes: fs.readFileSync(signedPdfPath),
        certificateRecord,
        evidence,
        cleanup() { fs.rmSync(tempDirectory, { recursive: true, force: true }); },
    };
}

export async function createPadesLtFixture({
    certificateId = "CERT-OFFICER-001-V1",
    text = "NT219 PAdES-LT security fixture",
} = {}) {
    const { assertCertificateGoodViaOcsp } = await import("../../src/crypto/ocsp.service.js");
    const { upgradePadesBtToLt } = await import("../../src/crypto/pades-lt.service.js");
    const { verifyPadesPdf } = await import("../../src/crypto/pades.service.js");
    const fixture = await createPadesFixture({ certificateId, text });
    const signedBtPdfPath = fixture.signedPdfPath;
    const signedLtPdfPath = path.join(fixture.tempDirectory, "signed-lt.pdf");
    const ocspResult = assertCertificateGoodViaOcsp(fixture.certificateRecord);
    const ltEvidence = await upgradePadesBtToLt({
        inputPdfPath: signedBtPdfPath,
        outputPdfPath: signedLtPdfPath,
        certificateRecord: fixture.certificateRecord,
        ocspEvidence: ocspResult.ocsp,
    });
    const signedLtPdfBytes = fs.readFileSync(signedLtPdfPath);
    const verification = verifyPadesPdf({
        pdfBuffer: signedLtPdfBytes,
        expectedFingerprint: fixture.certificateRecord.fingerprint_sha256,
    });
    return {
        ...fixture,
        signedBtPdfPath,
        signedLtPdfPath,
        signedPdfPath: signedLtPdfPath,
        signedPdfBytes: signedLtPdfBytes,
        ocspEvidence: ocspResult.ocsp,
        ltEvidence,
        verification,
    };
}
