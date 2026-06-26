import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { executeTspSigningJob } from "./tsp-signing.service.js";
import { OfficerCertificateError } from "../crypto/x509-pki.service.js";

function sha256(buffer) {
    return crypto.createHash("sha256").update(buffer).digest("hex").toUpperCase();
}

function authHeaders(rawBody) {
    const timestamp = String(Date.now());
    const nonce = crypto.randomBytes(24).toString("base64url");
    const secret = process.env.TSP_SHARED_SECRET || "nt219-demo-tsp-secret-2026-change-me";
    const signature = crypto.createHmac("sha256", secret)
        .update(`${timestamp}.${nonce}.${rawBody}`)
        .digest("hex");
    return {
        "content-type": "application/json",
        "x-tsp-client-id": process.env.TSP_CLIENT_ID || "portal-api",
        "x-tsp-timestamp": timestamp,
        "x-tsp-nonce": nonce,
        "x-tsp-signature": signature,
    };
}

export function getTspClientStatus() {
    const mode = String(process.env.TSP_MODE || "http").toLowerCase();
    return {
        ready: true,
        mode,
        endpoint: process.env.TSP_URL || "http://127.0.0.1:3400",
        local_fallback_enabled: String(process.env.TSP_ALLOW_LOCAL_FALLBACK || "false").toLowerCase() === "true",
        authentication: "HMAC-SHA256",
        anti_replay: true,
        idempotency: "request_id",
    };
}

async function invokeHttp(payload) {
    const rawBody = JSON.stringify(payload);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Number(process.env.TSP_REQUEST_TIMEOUT_MS || 120000));
    try {
        const response = await fetch(`${process.env.TSP_URL || "http://127.0.0.1:3400"}/v1/sign/pades-bt`, {
            method: "POST",
            headers: authHeaders(rawBody),
            body: rawBody,
            signal: controller.signal,
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new OfficerCertificateError(
                body.message || `TSP returned HTTP ${response.status}`,
                body.code || "TSP_HTTP_ERROR",
                response.status
            );
        }
        return body;
    } catch (error) {
        if (error instanceof OfficerCertificateError) throw error;
        throw new OfficerCertificateError(
            `TSP service unavailable: ${error.message}`,
            "TSP_SERVICE_UNAVAILABLE",
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

export async function signPadesViaTsp({
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
    const mode = String(process.env.TSP_MODE || "http").toLowerCase();
    let response;
    if (mode === "local") {
        response = await executeTspSigningJob(payload);
    } else {
        try {
            response = await invokeHttp(payload);
        } catch (error) {
            const fallback = String(process.env.TSP_ALLOW_LOCAL_FALLBACK || "false").toLowerCase() === "true";
            if (!fallback) throw error;
            response = await executeTspSigningJob(payload);
            response.local_fallback_used = true;
        }
    }
    return persistEvidence(response, outputPdfPath, evidenceDirectory);
}
