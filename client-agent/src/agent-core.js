import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildCitizenSignaturePayload } from "../../backend/src/crypto/citizen-signature-payload.js";
import {
    getPkcs11CertificateStatus,
    signCanonicalPayloadWithPkcs11,
    signCanonicalPayloadWithSoftware,
} from "./providers.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "../..");
const registryPath = path.join(projectRoot, "client-agent/storage/certificates.json");

function sha256(buffer) {
    return crypto.createHash("sha256").update(buffer).digest("hex").toUpperCase();
}

export function readClientAgentRegistry() {
    if (!fs.existsSync(registryPath)) return [];
    const records = JSON.parse(fs.readFileSync(registryPath, "utf8"));
    return Array.isArray(records) ? records : [];
}

function resolveRecord(record) {
    const resolvePath = (value) => value ? (path.isAbsolute(value) ? value : path.resolve(projectRoot, value)) : null;
    return {
        ...record,
        certificate_path: resolvePath(record.certificate_path),
        private_key_path: resolvePath(record.private_key_path),
        certificate_chain_path: resolvePath(record.certificate_chain_path),
        root_ca_certificate_path: resolvePath(record.root_ca_certificate_path),
    };
}

function statusForRecord(record) {
    const resolved = resolveRecord(record);
    const provider = String(record.provider || record.key_provider || "software").toLowerCase();
    const pkcs11 = provider === "pkcs11" ? getPkcs11CertificateStatus(record, projectRoot) : null;
    const certificateAvailable = Boolean(resolved.certificate_path && fs.existsSync(resolved.certificate_path));
    const privateKeyAvailable = provider === "pkcs11"
        ? pkcs11?.ready === true
        : Boolean(resolved.private_key_path && fs.existsSync(resolved.private_key_path));
    return {
        certificate_id: record.certificate_id,
        signer_type: record.signer_type || (record.citizen_id ? "citizen" : "officer"),
        user_id: record.user_id || null,
        citizen_id: record.citizen_id || null,
        officer_id: record.officer_id || null,
        full_name: record.full_name,
        email: record.email,
        status: record.status,
        provider,
        fingerprint_sha256: record.fingerprint_sha256,
        serial_number: record.serial_number,
        certificate_available: certificateAvailable,
        private_key_available: privateKeyAvailable,
        private_key_exportable: provider !== "pkcs11",
        key_reference: provider === "pkcs11" ? pkcs11?.key_reference || null : `client-agent-software:${record.certificate_id}`,
        provider_ready: provider === "pkcs11" ? pkcs11?.ready === true : certificateAvailable && privateKeyAvailable,
        provider_error: provider === "pkcs11" ? pkcs11?.error || null : null,
    };
}

export function listClientAgentCertificates({ signerType = null, userId = null } = {}) {
    return readClientAgentRegistry()
        .filter((record) => !signerType || String(record.signer_type || (record.citizen_id ? "citizen" : "officer")) === String(signerType))
        .filter((record) => userId === null || String(record.user_id) === String(userId))
        .map(statusForRecord);
}

export function getClientAgentStatus() {
    const certificates = listClientAgentCertificates();
    const providers = {
        software: certificates.some((item) => item.provider === "software" && item.provider_ready && item.status === "active"),
        pkcs11: certificates.some((item) => item.provider === "pkcs11" && item.provider_ready && item.status === "active"),
    };
    return {
        ready: certificates.some((item) => item.status === "active" && item.provider_ready),
        service: "nt219-client-agent",
        version: "1.0.0",
        provider: providers.pkcs11 ? "hybrid" : "software",
        providers,
        host: process.env.CLIENT_AGENT_HOST || "127.0.0.1",
        port: Number(process.env.CLIENT_AGENT_PORT || 3500),
        certificates,
        private_keys_exportable: providers.pkcs11 ? "mixed" : true,
        lab_only: true,
        note: "Software provider is lab-only; PKCS#11 provider keeps the citizen private key inside SoftHSM/token.",
    };
}

function readOptional(filePath) {
    return filePath && fs.existsSync(filePath) ? fs.readFileSync(filePath).toString("base64") : null;
}

export async function executeCitizenDigestSigningJob(payload = {}) {
    const {
        request_id,
        document_id,
        user_id,
        citizen_id,
        certificate_id,
        provider,
        created_at,
        document_digest_sha256,
        canonical_payload,
    } = payload;
    if (!request_id || !document_id || !user_id || !citizen_id || !certificate_id || !document_digest_sha256) {
        const error = new Error("Citizen signing request is incomplete");
        error.code = "CITIZEN_CLIENT_AGENT_REQUEST_INVALID";
        error.status = 400;
        throw error;
    }
    const record = readClientAgentRegistry().find((item) => item.certificate_id === certificate_id);
    if (!record || record.status !== "active") {
        const error = new Error("Citizen certificate is unavailable or inactive in Client Agent");
        error.code = "CITIZEN_CLIENT_AGENT_CERTIFICATE_UNAVAILABLE";
        error.status = 409;
        throw error;
    }
    if ((record.signer_type || (record.citizen_id ? "citizen" : "officer")) !== "citizen") {
        const error = new Error("Officer certificate cannot be used for citizen signing");
        error.code = "CERTIFICATE_ROLE_MISMATCH";
        error.status = 403;
        throw error;
    }
    if (String(record.user_id) !== String(user_id) || String(record.citizen_id) !== String(citizen_id)) {
        const error = new Error("Citizen certificate does not belong to the requesting citizen");
        error.code = "CITIZEN_CERTIFICATE_OWNER_MISMATCH";
        error.status = 403;
        throw error;
    }
    const selectedProvider = String(record.provider || record.key_provider || "software").toLowerCase();
    if (provider && selectedProvider !== String(provider).toLowerCase()) {
        const error = new Error("Requested Client Agent provider does not match the selected certificate");
        error.code = "CITIZEN_CERTIFICATE_PROVIDER_MISMATCH";
        error.status = 409;
        throw error;
    }
    const rebuilt = buildCitizenSignaturePayload({
        requestId: request_id,
        documentId: document_id,
        citizenId: citizen_id,
        userId: user_id,
        certificateId: certificate_id,
        documentDigestSha256: document_digest_sha256,
        createdAt: created_at,
    });
    if (canonical_payload && canonical_payload !== rebuilt) {
        const error = new Error("Canonical citizen-signing payload was substituted");
        error.code = "CITIZEN_CANONICAL_PAYLOAD_MISMATCH";
        error.status = 400;
        throw error;
    }
    const signed = selectedProvider === "pkcs11"
        ? signCanonicalPayloadWithPkcs11({ record, projectRoot, canonicalPayload: rebuilt })
        : signCanonicalPayloadWithSoftware({ record, projectRoot, canonicalPayload: rebuilt });
    return {
        request_id,
        document_id,
        user_id,
        citizen_id,
        certificate_id,
        status: "signed",
        signing_purpose: "citizen-submission",
        provider: signed.provider,
        key_reference: signed.keyReference,
        key_exportable: signed.keyExportable,
        digest_algorithm: "SHA-256",
        document_digest_sha256: String(document_digest_sha256).toUpperCase(),
        canonical_payload_sha256: sha256(Buffer.from(rebuilt, "utf8")),
        canonical_payload: rebuilt,
        signature_algorithm: "ECDSA-P256-SHA256",
        signature_der_base64: signed.signature.toString("base64"),
        certificate_pem_base64: Buffer.from(signed.certificatePem, "utf8").toString("base64"),
        client_agent_version: "1.0.0",
        completed_at: new Date().toISOString(),
    };
}

export async function executeClientAgentSigningJob(payload = {}) {
    const {
        request_id,
        document_id,
        officer_id,
        certificate_id,
        signer,
        issued_at,
        input_pdf_base64,
        document_digest_sha256,
    } = payload;
    if (!request_id || !document_id || !officer_id || !certificate_id || !input_pdf_base64) {
        const error = new Error("Client-agent signing request is incomplete");
        error.code = "CLIENT_AGENT_REQUEST_INVALID";
        error.status = 400;
        throw error;
    }
    const record = readClientAgentRegistry().find((item) => item.certificate_id === certificate_id);
    if (!record || record.status !== "active") {
        const error = new Error("Local software certificate is unavailable or inactive");
        error.code = "CLIENT_AGENT_CERTIFICATE_UNAVAILABLE";
        error.status = 409;
        throw error;
    }
    if ((record.signer_type || (record.citizen_id ? "citizen" : "officer")) !== "officer") {
        const error = new Error("Citizen certificate cannot be used for officer PAdES signing");
        error.code = "CERTIFICATE_ROLE_MISMATCH";
        error.status = 403;
        throw error;
    }
    if (String(record.officer_id) !== String(officer_id)) {
        const error = new Error("Local certificate does not belong to the requesting officer");
        error.code = "CLIENT_AGENT_CERTIFICATE_OFFICER_MISMATCH";
        error.status = 403;
        throw error;
    }
    const input = Buffer.from(input_pdf_base64, "base64");
    const actualDigest = sha256(input);
    if (document_digest_sha256 && actualDigest !== String(document_digest_sha256).toUpperCase()) {
        const error = new Error("Client-agent document digest mismatch");
        error.code = "CLIENT_AGENT_DOCUMENT_DIGEST_MISMATCH";
        error.status = 400;
        throw error;
    }

    const originalProvider = process.env.SIGNING_PROVIDER;
    process.env.SIGNING_PROVIDER = "file";
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-client-agent-"));
    try {
        const { createPadesBtSignature } = await import("../../backend/src/crypto/pades.service.js");
        const inputPath = path.join(temp, "prepared.pdf");
        const outputPath = path.join(temp, "signed.pdf");
        const evidenceDirectory = path.join(temp, "evidence");
        fs.writeFileSync(inputPath, input);
        const certificateRecord = resolveRecord(record);
        const result = await createPadesBtSignature({
            inputPdfPath: inputPath,
            outputPdfPath: outputPath,
            certificateRecord,
            signer: signer || record,
            issuedAt: issued_at || new Date().toISOString(),
            evidenceDirectory,
        });
        const signed = fs.readFileSync(outputPath);
        return {
            request_id,
            document_id,
            status: "signed",
            signing_method: "local",
            client_agent_version: "1.0.0",
            certificate_id,
            officer_id,
            provider: "software",
            key_reference: `client-agent-software:${certificate_id}`,
            key_exportable: true,
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
            completed_at: new Date().toISOString(),
        };
    } finally {
        if (originalProvider === undefined) delete process.env.SIGNING_PROVIDER;
        else process.env.SIGNING_PROVIDER = originalProvider;
        fs.rmSync(temp, { recursive: true, force: true });
    }
}
