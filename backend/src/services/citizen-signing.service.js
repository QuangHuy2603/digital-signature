import crypto from "node:crypto";
import path from "node:path";
import { hashFile, hashText } from "../crypto/hash.service.js";
import {
    CitizenSigningError,
    buildCitizenSignaturePayload,
    loadCitizenSigningIdentity,
} from "../crypto/citizen-signature.service.js";
import { findDocumentById, updateDocument } from "./document.repository.js";
import { writeAuditLog } from "./audit.service.js";
import { requestCitizenDigestSignature } from "./citizen-client-agent.service.js";
import {
    createCitizenSigningRequestRecord,
    findCitizenSigningRequestById,
    updateCitizenSigningRequestRecord,
} from "./citizen-signing-request.repository.js";
import { atomicWriteJsonSync } from "../utils/atomic-file.util.js";
import { CITIZEN_SIGNING_REQUEST_TTL_SECONDS } from "../config/env.config.js";

function timingSafeNonceEquals(expectedHash, nonce) {
    const expected = Buffer.from(String(expectedHash || ""), "hex");
    const actual = Buffer.from(hashText(String(nonce || "")), "hex");
    return expected.length > 0 && expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function iso(value) {
    return new Date(value).toISOString();
}

export function createCitizenSigningManager({
    findDocumentFn = findDocumentById,
    updateDocumentFn = updateDocument,
    hashFileFn = hashFile,
    identityLoader = loadCitizenSigningIdentity,
    agentSigner = requestCitizenDigestSignature,
    auditFn = writeAuditLog,
    createRecord = createCitizenSigningRequestRecord,
    findRequest = findCitizenSigningRequestById,
    updateRequest = updateCitizenSigningRequestRecord,
    nowFn = () => new Date(),
    randomUUIDFn = () => crypto.randomUUID(),
    randomBytesFn = (size) => crypto.randomBytes(size),
    ttlSeconds = CITIZEN_SIGNING_REQUEST_TTL_SECONDS,
} = {}) {
    async function create({ documentId, userId, certificateId = null, provider = "software", ipAddress = null }) {
        const document = await findDocumentFn(documentId);
        if (!document) throw new CitizenSigningError("Document not found", "DOCUMENT_NOT_FOUND", 404);
        if (String(document.owner_id) !== String(userId)) {
            throw new CitizenSigningError("Citizen cannot sign another citizen's document", "CITIZEN_DOCUMENT_OWNER_MISMATCH", 403);
        }
        if (document.status !== "awaiting_citizen_signature") {
            throw new CitizenSigningError(
                `Document is not awaiting citizen signature: ${document.status}`,
                "CITIZEN_DOCUMENT_NOT_SIGNABLE",
                409
            );
        }
        const normalizedProvider = String(provider || "software").trim().toLowerCase();
        if (!new Set(["software", "pkcs11"]).has(normalizedProvider)) {
            throw new CitizenSigningError("Unsupported citizen signing provider", "CITIZEN_SIGNING_PROVIDER_UNSUPPORTED", 400);
        }
        const identity = await identityLoader({ userId, certificateId, provider: normalizedProvider });
        const documentHash = await hashFileFn(document.file_path);
        const now = nowFn();
        const nonce = randomBytesFn(32).toString("base64url");
        const record = {
            request_id: randomUUIDFn(),
            document_id: documentId,
            user_id: String(userId),
            citizen_id: identity.user.citizen_id,
            certificate_id: identity.certificateRecord.certificate_id,
            provider: normalizedProvider,
            document_hash: documentHash,
            nonce_hash: hashText(nonce),
            status: "pending",
            created_at: iso(now),
            expires_at: iso(new Date(now.getTime() + ttlSeconds * 1000)),
            used_at: null,
            failed_at: null,
            failure_code: null,
        };
        createRecord(record);
        await auditFn({
            action: "CITIZEN_SIGNING_REQUEST_CREATED",
            requestId: record.request_id,
            documentId,
            userId,
            ipAddress,
            result: "success",
            details: {
                citizen_id: record.citizen_id,
                certificate_id: record.certificate_id,
                provider: record.provider,
                document_hash: record.document_hash,
                expires_at: record.expires_at,
            },
        });
        return {
            request_id: record.request_id,
            nonce,
            document_id: documentId,
            citizen_id: record.citizen_id,
            certificate_id: record.certificate_id,
            provider: record.provider,
            document_digest_sha256: record.document_hash,
            digest_algorithm: "SHA-256",
            created_at: record.created_at,
            expires_at: record.expires_at,
        };
    }

    async function sign({ documentId, userId, requestId, nonce, ipAddress = null }) {
        const request = findRequest(requestId);
        if (!request) throw new CitizenSigningError("Citizen signing request not found", "CITIZEN_SIGNING_REQUEST_NOT_FOUND", 404);
        if (request.status !== "pending") {
            throw new CitizenSigningError("Citizen signing request was already used", "CITIZEN_SIGNING_REPLAY_DETECTED", 409);
        }
        if (String(request.document_id) !== String(documentId) || String(request.user_id) !== String(userId)) {
            throw new CitizenSigningError("Citizen signing request owner mismatch", "CITIZEN_SIGNING_REQUEST_FORBIDDEN", 403);
        }
        const now = nowFn();
        if (new Date(request.expires_at) <= now) {
            updateRequest(requestId, { status: "expired", failed_at: iso(now), failure_code: "CITIZEN_SIGNING_REQUEST_EXPIRED" });
            throw new CitizenSigningError("Citizen signing request has expired", "CITIZEN_SIGNING_REQUEST_EXPIRED", 410);
        }
        if (!timingSafeNonceEquals(request.nonce_hash, nonce)) {
            throw new CitizenSigningError("Citizen signing nonce is invalid", "CITIZEN_SIGNING_NONCE_INVALID", 403);
        }
        const document = await findDocumentFn(documentId);
        if (!document) throw new CitizenSigningError("Document not found", "DOCUMENT_NOT_FOUND", 404);
        if (String(document.owner_id) !== String(userId)) {
            throw new CitizenSigningError("Citizen cannot sign another citizen's document", "CITIZEN_DOCUMENT_OWNER_MISMATCH", 403);
        }
        if (document.status !== "awaiting_citizen_signature") {
            throw new CitizenSigningError("Document is no longer awaiting citizen signature", "CITIZEN_DOCUMENT_NOT_SIGNABLE", 409);
        }
        const currentHash = await hashFileFn(document.file_path);
        if (String(currentHash).toUpperCase() !== String(request.document_hash).toUpperCase()) {
            updateRequest(requestId, { status: "invalidated", failed_at: iso(now), failure_code: "CITIZEN_DOCUMENT_DIGEST_MISMATCH" });
            throw new CitizenSigningError("Document digest changed after the citizen signing request was created", "CITIZEN_DOCUMENT_DIGEST_MISMATCH", 409);
        }
        const identity = await identityLoader({
            userId,
            certificateId: request.certificate_id,
            provider: request.provider,
            now,
        });
        const canonicalPayload = buildCitizenSignaturePayload({
            requestId: request.request_id,
            documentId: request.document_id,
            citizenId: request.citizen_id,
            userId: request.user_id,
            certificateId: request.certificate_id,
            documentDigestSha256: request.document_hash,
            createdAt: request.created_at,
        });
        updateRequest(requestId, { status: "processing", processing_at: iso(now) });
        try {
            const agentResult = await agentSigner({ request, identity, canonicalPayload, provider: request.provider });
            const completedAt = nowFn();
            const evidence = {
                version: 1,
                request_id: request.request_id,
                signed_at: iso(completedAt),
                citizen_id: request.citizen_id,
                user_id: request.user_id,
                certificate_id: request.certificate_id,
                provider: request.provider,
                key_reference: agentResult.key_reference,
                key_exportable: agentResult.key_exportable,
                digest_algorithm: "SHA-256",
                document_digest_sha256: request.document_hash,
                canonical_payload: canonicalPayload,
                canonical_payload_sha256: agentResult.canonical_payload_sha256,
                signature_algorithm: agentResult.signature_algorithm,
                signature_der_base64: agentResult.signature_der_base64,
                certificate_fingerprint_sha256: identity.certificateRecord.fingerprint_sha256,
                certificate_subject: identity.certificate.subject,
                certificate_issuer: identity.certificate.issuer,
                certificate_status_at_signing: identity.certificateRecord.status,
                revocation_source: identity.revocation?.source || null,
                ocsp_evidence: identity.revocation?.ocsp || null,
                signature_valid: agentResult.signature_valid === true,
                client_agent_version: agentResult.client_agent_version,
            };
            const updated = await updateDocumentFn(documentId, {
                status: "submitted",
                citizen_signed_at: evidence.signed_at,
                citizen_signature: evidence,
                citizen_certificate_id: request.certificate_id,
                citizen_signing_provider: request.provider,
                citizen_signature_valid: true,
                citizen_document_digest_sha256: request.document_hash,
            });
            if (updated?.file_path) {
                atomicWriteJsonSync(path.join(path.dirname(updated.file_path), "metadata.json"), updated, { backup: true });
            }
            updateRequest(requestId, { status: "used", used_at: evidence.signed_at });
            await auditFn({
                action: "CITIZEN_DOCUMENT_SIGNED",
                requestId,
                documentId,
                userId,
                ipAddress,
                result: "success",
                details: {
                    citizen_id: request.citizen_id,
                    certificate_id: request.certificate_id,
                    provider: request.provider,
                    document_hash: request.document_hash,
                    key_exportable: agentResult.key_exportable,
                },
            });
            return {
                document_id: documentId,
                status: updated.status,
                citizen_signed_at: updated.citizen_signed_at,
                citizen_id: request.citizen_id,
                certificate_id: request.certificate_id,
                provider: request.provider,
                key_exportable: agentResult.key_exportable,
                signature_valid: true,
                document_digest_sha256: request.document_hash,
                next_step: "OFFICER_REVIEW",
            };
        } catch (error) {
            updateRequest(requestId, {
                status: "failed",
                failed_at: iso(nowFn()),
                failure_code: error.code || "CITIZEN_SIGNING_FAILED",
            });
            await auditFn({
                action: "CITIZEN_SIGNING_REJECTED",
                requestId,
                documentId,
                userId,
                ipAddress,
                result: "blocked",
                details: { code: error.code || "CITIZEN_SIGNING_FAILED", message: error.message },
            });
            throw error;
        }
    }

    return { create, sign };
}

const defaultManager = createCitizenSigningManager();
export const createCitizenSigningRequest = defaultManager.create;
export const signDocumentAsCitizen = defaultManager.sign;
export { CitizenSigningError };
