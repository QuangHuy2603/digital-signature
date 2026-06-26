import crypto from "node:crypto";
import { hashFile, hashText } from "../crypto/hash.service.js";
import { findDocumentById } from "./document.repository.js";
import { writeAuditLog } from "./audit.service.js";
import signingRequestRepository from "./signing-request.repository.js";
import { SIGNING_REQUEST_TTL_SECONDS } from "../config/env.config.js";

export class SigningRequestError extends Error {
    constructor(message, code, status = 400) {
        super(message);
        this.name = "SigningRequestError";
        this.code = code;
        this.status = status;
    }
}

function constantTimeHashEquals(expectedHash, suppliedText) {
    if (typeof expectedHash !== "string" || typeof suppliedText !== "string") {
        return false;
    }

    const suppliedHash = hashText(suppliedText);
    const expected = Buffer.from(expectedHash, "hex");
    const supplied = Buffer.from(suppliedHash, "hex");

    return expected.length === supplied.length &&
        crypto.timingSafeEqual(expected, supplied);
}

const asIso = (date) => new Date(date).toISOString();

/**
 * Dependency-injectable signing request manager.
 * Production uses the file repository; tests can inject an in-memory one.
 */
export function createSigningRequestManager({
    repository = signingRequestRepository,
    findDocumentByIdFn = findDocumentById,
    hashFileFn = hashFile,
    auditFn = writeAuditLog,
    nowFn = () => new Date(),
    randomUUIDFn = () => crypto.randomUUID(),
    randomBytesFn = (size) => crypto.randomBytes(size),
    ttlSeconds = SIGNING_REQUEST_TTL_SECONDS,
} = {}) {
    const audit = async ({
        action,
        requestId,
        documentId,
        officerId,
        ipAddress,
        result,
        details = null,
    }) => auditFn({
        action,
        requestId,
        documentId,
        userId: officerId,
        ipAddress,
        result,
        details,
    });

    async function create({ documentId, officerId, ipAddress = null, signingMethod = "remote" }) {
        const normalizedSigningMethod = String(signingMethod || "remote").trim().toLowerCase();
        if (!new Set(["remote", "local"]).has(normalizedSigningMethod)) {
            throw new SigningRequestError(
                `Unsupported signing method: ${normalizedSigningMethod}`,
                "SIGNING_METHOD_UNSUPPORTED",
                400
            );
        }
        const document = await findDocumentByIdFn(documentId);
        if (!document) {
            throw new SigningRequestError(
                "Document not found",
                "DOCUMENT_NOT_FOUND",
                404
            );
        }
        if (document.status !== "submitted") {
            throw new SigningRequestError(
                `Cannot create signing request for document status "${document.status}"`,
                "DOCUMENT_NOT_SIGNABLE",
                409
            );
        }
        if (!document.file_path) {
            throw new SigningRequestError(
                "Document file path is missing",
                "DOCUMENT_FILE_MISSING",
                409
            );
        }

        const documentHash = await hashFileFn(document.file_path);
        const now = nowFn();
        const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
        const nonce = randomBytesFn(32).toString("base64url");

        const record = {
            request_id: randomUUIDFn(),
            document_id: documentId,
            document_hash: documentHash,
            nonce_hash: hashText(nonce),
            requested_by: String(officerId),
            signing_method: normalizedSigningMethod,
            status: "pending",
            created_at: asIso(now),
            expires_at: asIso(expiresAt),
            processing_at: null,
            used_at: null,
            failed_at: null,
            failure_code: null,
        };

        repository.create(record);

        await audit({
            action: "SIGNING_REQUEST_CREATED",
            requestId: record.request_id,
            documentId,
            officerId,
            ipAddress,
            result: "success",
            details: {
                expires_at: record.expires_at,
                document_hash: record.document_hash,
            },
        });

        return {
            request_id: record.request_id,
            nonce,
            document_id: record.document_id,
            document_hash: record.document_hash,
            expires_at: record.expires_at,
            signing_method: record.signing_method,
            status: record.status,
        };
    }

    async function reserve({
        requestId,
        nonce,
        documentId,
        officerId,
        ipAddress = null,
        signingMethod = "remote",
    }) {
        if (!requestId || !nonce) {
            throw new SigningRequestError(
                "request_id and nonce are required",
                "SIGNING_REQUEST_REQUIRED",
                400
            );
        }

        const request = repository.findById(requestId);
        if (!request) {
            throw new SigningRequestError(
                "Signing request not found",
                "SIGNING_REQUEST_NOT_FOUND",
                404
            );
        }

        if (request.document_id !== documentId ||
            String(request.requested_by) !== String(officerId)) {
            await audit({
                action: "SIGNING_REQUEST_FORBIDDEN",
                requestId,
                documentId,
                officerId,
                ipAddress,
                result: "blocked",
            });
            throw new SigningRequestError(
                "Signing request does not belong to this officer or document",
                "SIGNING_REQUEST_FORBIDDEN",
                403
            );
        }

        const normalizedSigningMethod = String(signingMethod || "remote").trim().toLowerCase();
        if ((request.signing_method || "remote") !== normalizedSigningMethod) {
            await audit({
                action: "SIGNING_METHOD_BINDING_REJECTED",
                requestId,
                documentId,
                officerId,
                ipAddress,
                result: "blocked",
                details: {
                    expected_method: request.signing_method || "remote",
                    supplied_method: normalizedSigningMethod,
                },
            });
            throw new SigningRequestError(
                "Signing request is bound to another signing method",
                "SIGNING_METHOD_BINDING_MISMATCH",
                403
            );
        }

        if (request.status !== "pending") {
            await audit({
                action: "SIGNING_REPLAY_BLOCKED",
                requestId,
                documentId,
                officerId,
                ipAddress,
                result: "blocked",
                details: { previous_status: request.status },
            });
            throw new SigningRequestError(
                "Signing request has already been used or reserved",
                "REPLAY_DETECTED",
                409
            );
        }

        const now = nowFn();
        if (new Date(request.expires_at).getTime() <= now.getTime()) {
            repository.update(requestId, {
                status: "expired",
                failed_at: asIso(now),
                failure_code: "SIGNING_REQUEST_EXPIRED",
            });
            await audit({
                action: "SIGNING_REQUEST_EXPIRED",
                requestId,
                documentId,
                officerId,
                ipAddress,
                result: "blocked",
            });
            throw new SigningRequestError(
                "Signing request has expired",
                "SIGNING_REQUEST_EXPIRED",
                410
            );
        }

        if (!constantTimeHashEquals(request.nonce_hash, nonce)) {
            await audit({
                action: "SIGNING_NONCE_INVALID",
                requestId,
                documentId,
                officerId,
                ipAddress,
                result: "blocked",
            });
            throw new SigningRequestError(
                "Invalid signing nonce",
                "INVALID_SIGNING_NONCE",
                403
            );
        }

        const document = await findDocumentByIdFn(documentId);
        if (!document) {
            throw new SigningRequestError(
                "Document not found",
                "DOCUMENT_NOT_FOUND",
                404
            );
        }
        if (document.status !== "submitted") {
            throw new SigningRequestError(
                `Cannot sign document with status "${document.status}"`,
                "DOCUMENT_NOT_SIGNABLE",
                409
            );
        }

        const currentHash = await hashFileFn(document.file_path);
        if (currentHash !== request.document_hash) {
            repository.update(requestId, {
                status: "invalidated",
                failed_at: asIso(now),
                failure_code: "DOCUMENT_HASH_CHANGED",
            });
            await audit({
                action: "DOCUMENT_HASH_CHANGED",
                requestId,
                documentId,
                officerId,
                ipAddress,
                result: "blocked",
                details: {
                    expected_hash: request.document_hash,
                    current_hash: currentHash,
                },
            });
            throw new SigningRequestError(
                "Document changed after the signing request was created",
                "DOCUMENT_HASH_CHANGED",
                409
            );
        }

        // Synchronous repository update acts as a one-time reservation in the
        // single Node.js process. A replay arriving afterwards sees processing.
        const reserved = repository.update(requestId, {
            status: "processing",
            processing_at: asIso(now),
        });

        return reserved;
    }

    async function complete({
        requestId,
        documentId,
        officerId,
        ipAddress = null,
    }) {
        const request = repository.findById(requestId);
        if (!request || request.status !== "processing") {
            throw new SigningRequestError(
                "Signing request is not reserved for completion",
                "SIGNING_REQUEST_STATE_INVALID",
                409
            );
        }

        const usedAt = asIso(nowFn());
        const completed = repository.update(requestId, {
            status: "used",
            used_at: usedAt,
        });

        await audit({
            action: "SIGNING_REQUEST_USED",
            requestId,
            documentId,
            officerId,
            ipAddress,
            result: "success",
            details: { used_at: usedAt },
        });

        return completed;
    }

    async function fail({
        requestId,
        documentId,
        officerId,
        ipAddress = null,
        failureCode = "SIGNING_OPERATION_FAILED",
    }) {
        if (!requestId) return null;
        const request = repository.findById(requestId);
        if (!request || request.status !== "processing") return request;

        const failed = repository.update(requestId, {
            status: "failed",
            failed_at: asIso(nowFn()),
            failure_code: failureCode,
        });

        await audit({
            action: "SIGNING_REQUEST_FAILED",
            requestId,
            documentId,
            officerId,
            ipAddress,
            result: "failed",
            details: { failure_code: failureCode },
        });

        return failed;
    }

    return { create, reserve, complete, fail };
}

const defaultManager = createSigningRequestManager();

export const createSigningRequest = defaultManager.create;
export const reserveSigningRequest = defaultManager.reserve;
export const completeSigningRequest = defaultManager.complete;
export const failSigningRequest = defaultManager.fail;
