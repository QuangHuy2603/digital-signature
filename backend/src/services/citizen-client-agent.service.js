import crypto from "node:crypto";
import { CitizenSigningError, verifyCitizenDetachedSignature } from "../crypto/citizen-signature.service.js";

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

async function invoke(pathname, payload) {
    const rawBody = JSON.stringify(payload);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Number(process.env.CLIENT_AGENT_REQUEST_TIMEOUT_MS || 120000));
    try {
        const response = await fetch(`${process.env.CLIENT_AGENT_URL || "http://127.0.0.1:3500"}${pathname}`, {
            method: "POST",
            headers: authHeaders(rawBody),
            body: rawBody,
            signal: controller.signal,
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new CitizenSigningError(
                body.message || `Client Agent returned HTTP ${response.status}`,
                body.code || "CITIZEN_CLIENT_AGENT_HTTP_ERROR",
                response.status
            );
        }
        return body;
    } catch (error) {
        if (error instanceof CitizenSigningError) throw error;
        throw new CitizenSigningError(
            `Client Agent unavailable: ${error.message}`,
            "CLIENT_AGENT_UNAVAILABLE",
            503
        );
    } finally {
        clearTimeout(timeout);
    }
}

export async function requestCitizenDigestSignature({
    request,
    identity,
    canonicalPayload,
    provider,
} = {}) {
    const payload = {
        request_id: request.request_id,
        document_id: request.document_id,
        user_id: identity.user.id,
        citizen_id: identity.user.citizen_id,
        certificate_id: identity.certificateRecord.certificate_id,
        provider,
        created_at: request.created_at,
        document_digest_sha256: request.document_hash,
        canonical_payload: canonicalPayload,
    };
    const response = await invoke("/v1/sign/digest", payload);
    if (String(response.request_id) !== String(request.request_id) ||
        String(response.document_id) !== String(request.document_id)) {
        throw new CitizenSigningError(
            "Client Agent response is bound to another request or document",
            "CITIZEN_CLIENT_AGENT_RESPONSE_BINDING_MISMATCH",
            502
        );
    }
    if (String(response.certificate_id) !== String(identity.certificateRecord.certificate_id)) {
        throw new CitizenSigningError(
            "Client Agent returned a different citizen certificate",
            "CITIZEN_CLIENT_AGENT_CERTIFICATE_MISMATCH",
            502
        );
    }
    if (String(response.document_digest_sha256 || "").toUpperCase() !== String(request.document_hash).toUpperCase()) {
        throw new CitizenSigningError(
            "Client Agent response is bound to another document digest",
            "CITIZEN_DOCUMENT_DIGEST_MISMATCH",
            502
        );
    }
    if (response.canonical_payload !== canonicalPayload) {
        throw new CitizenSigningError(
            "Client Agent returned a modified canonical payload",
            "CITIZEN_CANONICAL_PAYLOAD_MISMATCH",
            502
        );
    }
    const embeddedCertificate = Buffer.from(String(response.certificate_pem_base64 || ""), "base64").toString("utf8");
    if (embeddedCertificate.trim() !== identity.certificatePem.trim()) {
        throw new CitizenSigningError(
            "Client Agent returned a certificate different from the registry",
            "CITIZEN_CLIENT_AGENT_CERTIFICATE_MISMATCH",
            502
        );
    }
    const signatureValid = verifyCitizenDetachedSignature({
        signatureBase64: response.signature_der_base64,
        canonicalPayload,
        certificatePem: identity.certificatePem,
    });
    if (!signatureValid) {
        throw new CitizenSigningError(
            "Citizen signature returned by Client Agent is invalid",
            "CITIZEN_SIGNATURE_INVALID",
            502
        );
    }
    return { ...response, signature_valid: true };
}

export async function listCitizenClientAgentCertificates({ userId = null } = {}) {
    const url = new URL(`${process.env.CLIENT_AGENT_URL || "http://127.0.0.1:3500"}/v1/certificates`);
    url.searchParams.set("signer_type", "citizen");
    if (userId !== null) url.searchParams.set("user_id", String(userId));
    const response = await fetch(url, { method: "GET" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new CitizenSigningError(body.message || "Unable to query Client Agent certificates", body.code || "CLIENT_AGENT_UNAVAILABLE", response.status);
    }
    return Array.isArray(body.certificates) ? body.certificates : [];
}
