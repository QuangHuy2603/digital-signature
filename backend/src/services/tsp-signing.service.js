import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createPadesBtSignature } from "../crypto/pades.service.js";
import { findCertificateById } from "./certificate.repository.js";
import { OfficerCertificateError } from "../crypto/x509-pki.service.js";

function sha256(buffer) {
    return crypto.createHash("sha256").update(buffer).digest("hex").toUpperCase();
}

function readOptional(filePath) {
    return filePath && fs.existsSync(filePath) ? fs.readFileSync(filePath).toString("base64") : null;
}

export async function executeTspSigningJob({
    request_id,
    document_id,
    certificate_id,
    signer,
    issued_at,
    input_pdf_base64,
    document_digest_sha256,
} = {}) {
    if (!request_id || !document_id || !certificate_id || !input_pdf_base64) {
        throw new OfficerCertificateError("TSP signing request is incomplete", "TSP_REQUEST_INVALID", 400);
    }
    const input = Buffer.from(input_pdf_base64, "base64");
    const actualDigest = sha256(input);
    if (document_digest_sha256 && actualDigest !== String(document_digest_sha256).toUpperCase()) {
        throw new OfficerCertificateError("TSP document digest mismatch", "TSP_DOCUMENT_DIGEST_MISMATCH", 400);
    }
    const certificateRecord = findCertificateById(certificate_id);
    if (!certificateRecord || certificateRecord.status !== "active") {
        throw new OfficerCertificateError("TSP certificate is unavailable or inactive", "TSP_CERTIFICATE_UNAVAILABLE", 409);
    }

    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-tsp-job-"));
    try {
        const inputPath = path.join(temp, "prepared.pdf");
        const outputPath = path.join(temp, "signed.pdf");
        const evidenceDirectory = path.join(temp, "evidence");
        fs.writeFileSync(inputPath, input);
        const result = await createPadesBtSignature({
            inputPdfPath: inputPath,
            outputPdfPath: outputPath,
            certificateRecord,
            signer,
            issuedAt: issued_at || new Date().toISOString(),
            evidenceDirectory,
        });
        const signed = fs.readFileSync(outputPath);
        return {
            request_id,
            document_id,
            status: "signed",
            certificate_id,
            input_digest_sha256: actualDigest,
            signed_pdf_sha256: sha256(signed),
            signed_pdf_base64: signed.toString("base64"),
            pades: {
                ...result,
                cms_der_path: null,
                cms_bb_der_path: null,
                timestamp_evidence: {
                    ...result.timestamp_evidence,
                    request_path: null,
                    response_path: null,
                },
            },
            evidence_files: {
                pades_bb_cms_der_base64: readOptional(result.cms_bb_der_path),
                pades_bt_cms_der_base64: readOptional(result.cms_der_path),
                timestamp_query_base64: readOptional(result.timestamp_evidence?.request_path),
                timestamp_response_base64: readOptional(result.timestamp_evidence?.response_path),
            },
            key_provider: result.key_provider,
            key_reference: result.key_reference,
            key_exportable: result.key_exportable,
            completed_at: new Date().toISOString(),
        };
    } finally {
        fs.rmSync(temp, { recursive: true, force: true });
    }
}
