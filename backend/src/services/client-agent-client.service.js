import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { OfficerCertificateError } from "../crypto/x509-pki.service.js";
import { verifyPadesPdf } from "../crypto/pades.service.js";

function sha256(buffer) {
    return crypto.createHash("sha256").update(buffer).digest("hex").toUpperCase();
}

function authHeaders(rawBody) {
    const timestamp = String(Date.now());
    const nonce = crypto.randomBytes(24).toString("base64url");
    const secret = process.env.CLIENT_AGENT_SHARED_SECRET || "nt219-demo-client-agent-secret-2026-change-me";
    const signature = crypto.createHmac("sha256", secret)
        .update(`${timestamp}.${nonce}.${rawBody}`)
        .digest("hex");
    return {
        "content-type": "application/json",
        "x-client-agent-client-id": process.env.CLIENT_AGENT_CLIENT_ID || "portal-api",
        "x-client-agent-timestamp": timestamp,
        "x-client-agent-nonce": nonce,
        "x-client-agent-signature": signature,
    };
}

export function getClientAgentClientStatus() {
    return {
        ready: true,
        mode: "software",
        endpoint: process.env.CLIENT_AGENT_URL || "http://127.0.0.1:3500",
        provider: "software",
        authentication: "HMAC-SHA256",
        anti_replay: true,
        idempotency: "request_id",
        browser_health_check: true,
        lab_only: true,
    };
}

async function invokeHttp(payload) {
    const rawBody = JSON.stringify(payload);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Number(process.env.CLIENT_AGENT_REQUEST_TIMEOUT_MS || 120000));
    try {
        const response = await fetch(`${process.env.CLIENT_AGENT_URL || "http://127.0.0.1:3500"}/v1/sign/pades-bt`, {
            method: "POST",
            headers: authHeaders(rawBody),
            body: rawBody,
            signal: controller.signal,
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new OfficerCertificateError(
                body.message || `Client Agent returned HTTP ${response.status}`,
                body.code || "CLIENT_AGENT_HTTP_ERROR",
                response.status
            );
        }
        return body;
    } catch (error) {
        if (error instanceof OfficerCertificateError) throw error;
        throw new OfficerCertificateError(
            `Client Agent unavailable: ${error.message}`,
            "CLIENT_AGENT_UNAVAILABLE",
            503
        );
    } finally {
        clearTimeout(timeout);
    }
}

function persistEvidence(response, outputPdfPath, evidenceDirectory) {
    const signed = Buffer.from(response.signed_pdf_base64, "base64");
    fs.mkdirSync(path.dirname(outputPdfPath), { recursive: true });
    fs.writeFileSync(outputPdfPath, signed);
    fs.mkdirSync(evidenceDirectory, { recursive: true });
    const mappings = [
        ["pades_bb_cms_der_base64", "pades-bb.cms.der"],
        ["pades_bt_cms_der_base64", "pades-bt.cms.der"],
        ["timestamp_query_base64", "pades-signature-timestamp.tsq"],
        ["timestamp_response_base64", "pades-signature-timestamp.tsr"],
    ];
    const paths = {};
    for (const [key, fileName] of mappings) {
        const encoded = response.evidence_files?.[key];
        if (!encoded) continue;
        const target = path.join(evidenceDirectory, fileName);
        fs.writeFileSync(target, Buffer.from(encoded, "base64"));
        paths[key] = target;
    }
    const pades = {
        ...response.pades,
        cms_bb_der_path: paths.pades_bb_cms_der_base64 || null,
        cms_der_path: paths.pades_bt_cms_der_base64 || null,
        timestamp_evidence: {
            ...response.pades.timestamp_evidence,
            request_path: paths.timestamp_query_base64 || null,
            response_path: paths.timestamp_response_base64 || null,
        },
    };
    return { ...response, pades, signed_pdf_sha256: sha256(signed) };
}

export async function signPadesViaClientAgent({
    requestId,
    documentId,
    inputPdfPath,
    outputPdfPath,
    evidenceDirectory,
    certificateRecord,
    signer,
    issuedAt,
} = {}) {
    const input = fs.readFileSync(inputPdfPath);
    const payload = {
        request_id: requestId || crypto.randomUUID(),
        document_id: documentId,
        officer_id: signer?.officer_id || certificateRecord.officer_id,
        certificate_id: certificateRecord.certificate_id,
        signer: {
            id: signer?.id || null,
            officer_id: signer?.officer_id || certificateRecord.officer_id || null,
            full_name: signer?.full_name || certificateRecord.full_name || null,
            email: signer?.email || certificateRecord.email || null,
        },
        issued_at: issuedAt || new Date().toISOString(),
        input_pdf_base64: input.toString("base64"),
        document_digest_sha256: sha256(input),
    };
    const response = await invokeHttp(payload);
    if (String(response.certificate_id || "") !== String(certificateRecord.certificate_id || "")) {
        throw new OfficerCertificateError(
            "Client Agent returned a different certificate identity",
            "CLIENT_AGENT_CERTIFICATE_MISMATCH",
            502
        );
    }
    if (String(response.input_digest_sha256 || "").toUpperCase() !== payload.document_digest_sha256) {
        throw new OfficerCertificateError(
            "Client Agent response is bound to a different PDF digest",
            "CLIENT_AGENT_RESPONSE_DIGEST_MISMATCH",
            502
        );
    }
    const persisted = persistEvidence(response, outputPdfPath, evidenceDirectory);
    const portalVerification = verifyPadesPdf({
        pdfPath: outputPdfPath,
        expectedFingerprint: certificateRecord.fingerprint_sha256 || "",
    });
    if (!portalVerification.valid) {
        throw new OfficerCertificateError(
            `Client Agent returned an invalid PAdES document: ${portalVerification.reason}`,
            "CLIENT_AGENT_SIGNATURE_INVALID",
            502
        );
    }
    return { ...persisted, portal_verification: portalVerification };
}
