import crypto from "node:crypto";
import { hashFile } from "../crypto/hash.service.js";
import { findDocumentById } from "./document.repository.js";
import { writeAuditLog } from "./audit.service.js";
import remoteAuthorizationRepository from "./remote-signing-authorization.repository.js";
import {
    REMOTE_OTP_AUTHORIZATION_TTL_SECONDS,
    REMOTE_OTP_DEMO_EXPOSE,
    REMOTE_OTP_MAX_ATTEMPTS,
    REMOTE_OTP_SECRET,
    REMOTE_OTP_TTL_SECONDS,
} from "../config/env.config.js";

export class RemoteSigningAuthorizationError extends Error {
    constructor(message, code, status = 400) {
        super(message);
        this.name = "RemoteSigningAuthorizationError";
        this.code = code;
        this.status = status;
    }
}

const asIso = (date) => new Date(date).toISOString();

function normalizeOtp(value) {
    return String(value ?? "").trim();
}

function hmacHex(secret, ...parts) {
    return crypto
        .createHmac("sha256", secret)
        .update(parts.map((part) => String(part ?? "")).join("."))
        .digest("hex");
}

function secureHexEqual(leftHex, rightHex) {
    try {
        const left = Buffer.from(String(leftHex || ""), "hex");
        const right = Buffer.from(String(rightHex || ""), "hex");
        return left.length > 0 && left.length === right.length && crypto.timingSafeEqual(left, right);
    } catch {
        return false;
    }
}

export function createRemoteSigningAuthorizationManager({
    repository = remoteAuthorizationRepository,
    findDocumentByIdFn = findDocumentById,
    hashFileFn = hashFile,
    auditFn = writeAuditLog,
    nowFn = () => new Date(),
    randomUUIDFn = () => crypto.randomUUID(),
    randomBytesFn = (size) => crypto.randomBytes(size),
    otpSecret = REMOTE_OTP_SECRET,
    otpTtlSeconds = REMOTE_OTP_TTL_SECONDS,
    authorizationTtlSeconds = REMOTE_OTP_AUTHORIZATION_TTL_SECONDS,
    maxAttempts = REMOTE_OTP_MAX_ATTEMPTS,
    exposeDemoOtp = REMOTE_OTP_DEMO_EXPOSE,
} = {}) {
    const audit = async ({
        action,
        authorizationId,
        requestId,
        documentId,
        officerId,
        ipAddress,
        result,
        details = null,
    }) => auditFn({
        action,
        requestId: requestId || authorizationId,
        documentId,
        userId: officerId,
        ipAddress,
        result,
        details: {
            authorization_id: authorizationId,
            ...(details || {}),
        },
    });

    const generateOtp = () => {
        const value = randomBytesFn(4).readUInt32BE(0) % 1_000_000;
        return String(value).padStart(6, "0");
    };

    async function assertCurrentDocument(record, failureCode = "OTP_DIGEST_MISMATCH") {
        const document = await findDocumentByIdFn(record.document_id);
        if (!document) {
            throw new RemoteSigningAuthorizationError(
                "Document not found",
                "DOCUMENT_NOT_FOUND",
                404
            );
        }
        if (document.status !== "submitted") {
            throw new RemoteSigningAuthorizationError(
                `Cannot authorize remote signing for document status "${document.status}"`,
                "DOCUMENT_NOT_SIGNABLE",
                409
            );
        }
        const currentHash = await hashFileFn(document.file_path);
        if (currentHash !== record.document_hash) {
            repository.update(record.authorization_id, {
                status: "invalidated",
                failed_at: asIso(nowFn()),
                failure_code: failureCode,
            });
            throw new RemoteSigningAuthorizationError(
                "Document digest changed after OTP authorization was created",
                failureCode,
                409
            );
        }
        return { document, currentHash };
    }

    async function create({
        signingRequest,
        documentId,
        officerId,
        certificateId,
        ipAddress = null,
    }) {
        if (!signingRequest?.request_id || !signingRequest?.nonce || !signingRequest?.document_hash) {
            throw new RemoteSigningAuthorizationError(
                "A valid one-time signing request is required",
                "SIGNING_REQUEST_REQUIRED",
                400
            );
        }
        if (signingRequest.document_id !== documentId) {
            throw new RemoteSigningAuthorizationError(
                "Signing request is bound to another document",
                "OTP_DOCUMENT_BINDING_MISMATCH",
                403
            );
        }
        if (!certificateId) {
            throw new RemoteSigningAuthorizationError(
                "Remote signing certificate is required",
                "OTP_CERTIFICATE_BINDING_REQUIRED",
                409
            );
        }

        const now = nowFn();
        const authorizationId = randomUUIDFn();
        const otp = generateOtp();
        const salt = randomBytesFn(16).toString("hex");
        const expiresAt = new Date(now.getTime() + otpTtlSeconds * 1000);
        const record = {
            authorization_id: authorizationId,
            signing_request_id: signingRequest.request_id,
            signing_nonce_hash: hmacHex(otpSecret, authorizationId, signingRequest.nonce),
            document_id: documentId,
            document_hash: signingRequest.document_hash,
            requested_by: String(officerId),
            certificate_id: certificateId,
            otp_hash: hmacHex(otpSecret, authorizationId, salt, otp),
            otp_salt: salt,
            attempts: 0,
            max_attempts: maxAttempts,
            status: "pending_otp",
            created_at: asIso(now),
            expires_at: asIso(expiresAt),
            verified_at: null,
            authorization_expires_at: null,
            authorization_token_hash: null,
            processing_at: null,
            used_at: null,
            failed_at: null,
            failure_code: null,
        };
        repository.create(record);

        await audit({
            action: "REMOTE_OTP_ISSUED",
            authorizationId,
            requestId: signingRequest.request_id,
            documentId,
            officerId,
            ipAddress,
            result: "success",
            details: {
                certificate_id: certificateId,
                expires_at: record.expires_at,
                max_attempts: maxAttempts,
                document_hash: record.document_hash,
            },
        });

        if (exposeDemoOtp) {
            console.log(`[REMOTE_OTP DEMO OTP] authorization=${authorizationId} otp=${otp}`);
        }

        return {
            authorization_id: authorizationId,
            signing_request_id: signingRequest.request_id,
            document_id: documentId,
            certificate_id: certificateId,
            status: record.status,
            expires_at: record.expires_at,
            attempts_remaining: maxAttempts,
            delivery: {
                channel: exposeDemoOtp ? "demo-console" : "configured-channel",
                lab_only: exposeDemoOtp,
            },
            ...(exposeDemoOtp ? { demo_otp: otp } : {}),
        };
    }

    async function verify({
        authorizationId,
        otp,
        documentId,
        officerId,
        ipAddress = null,
    }) {
        if (!authorizationId || !normalizeOtp(otp)) {
            throw new RemoteSigningAuthorizationError(
                "authorization_id and otp are required",
                "OTP_REQUIRED",
                400
            );
        }
        const record = repository.findById(authorizationId);
        if (!record) {
            throw new RemoteSigningAuthorizationError(
                "Remote signing authorization not found",
                "OTP_AUTHORIZATION_NOT_FOUND",
                404
            );
        }
        if (record.document_id !== documentId || String(record.requested_by) !== String(officerId)) {
            await audit({
                action: "REMOTE_OTP_BINDING_REJECTED",
                authorizationId,
                requestId: record.signing_request_id,
                documentId,
                officerId,
                ipAddress,
                result: "blocked",
            });
            throw new RemoteSigningAuthorizationError(
                "OTP authorization belongs to another officer or document",
                "OTP_DOCUMENT_BINDING_MISMATCH",
                403
            );
        }
        if (record.status === "locked") {
            throw new RemoteSigningAuthorizationError(
                "OTP attempt limit exceeded",
                "OTP_ATTEMPT_LIMIT_EXCEEDED",
                423
            );
        }
        if (record.status !== "pending_otp") {
            throw new RemoteSigningAuthorizationError(
                "OTP authorization has already been verified or used",
                "OTP_REPLAY_DETECTED",
                409
            );
        }

        const now = nowFn();
        if (new Date(record.expires_at).getTime() <= now.getTime()) {
            repository.update(authorizationId, {
                status: "expired",
                failed_at: asIso(now),
                failure_code: "OTP_EXPIRED",
            });
            throw new RemoteSigningAuthorizationError(
                "OTP has expired",
                "OTP_EXPIRED",
                410
            );
        }

        await assertCurrentDocument(record);

        const suppliedHash = hmacHex(
            otpSecret,
            authorizationId,
            record.otp_salt,
            normalizeOtp(otp)
        );
        if (!secureHexEqual(record.otp_hash, suppliedHash)) {
            const attempts = Number(record.attempts || 0) + 1;
            const locked = attempts >= Number(record.max_attempts || maxAttempts);
            repository.update(authorizationId, {
                attempts,
                status: locked ? "locked" : "pending_otp",
                failed_at: locked ? asIso(now) : null,
                failure_code: locked ? "OTP_ATTEMPT_LIMIT_EXCEEDED" : "OTP_INVALID",
            });
            await audit({
                action: locked ? "REMOTE_OTP_LOCKED" : "REMOTE_OTP_INVALID",
                authorizationId,
                requestId: record.signing_request_id,
                documentId,
                officerId,
                ipAddress,
                result: "blocked",
                details: {
                    attempts,
                    max_attempts: record.max_attempts,
                },
            });
            throw new RemoteSigningAuthorizationError(
                locked ? "OTP attempt limit exceeded" : "Invalid OTP",
                locked ? "OTP_ATTEMPT_LIMIT_EXCEEDED" : "OTP_INVALID",
                locked ? 423 : 403
            );
        }

        const authorizationToken = randomBytesFn(32).toString("base64url");
        const authorizationExpiresAt = new Date(
            now.getTime() + authorizationTtlSeconds * 1000
        );
        const updated = repository.update(authorizationId, {
            status: "verified",
            attempts: Number(record.attempts || 0),
            verified_at: asIso(now),
            authorization_expires_at: asIso(authorizationExpiresAt),
            authorization_token_hash: hmacHex(
                otpSecret,
                authorizationId,
                authorizationToken
            ),
            otp_hash: null,
            otp_salt: null,
            failure_code: null,
        });

        await audit({
            action: "REMOTE_OTP_VERIFIED",
            authorizationId,
            requestId: record.signing_request_id,
            documentId,
            officerId,
            ipAddress,
            result: "success",
            details: {
                certificate_id: record.certificate_id,
                authorization_expires_at: updated.authorization_expires_at,
            },
        });

        return {
            authorization_id: authorizationId,
            authorization_token: authorizationToken,
            signing_request_id: record.signing_request_id,
            document_id: record.document_id,
            certificate_id: record.certificate_id,
            status: updated.status,
            expires_at: updated.authorization_expires_at,
        };
    }

    async function reserve({
        authorizationId,
        authorizationToken,
        requestId,
        nonce,
        documentId,
        officerId,
        certificateId,
        ipAddress = null,
    }) {
        if (!authorizationId || !authorizationToken) {
            throw new RemoteSigningAuthorizationError(
                "Verified OTP authorization is required for remote signing",
                "OTP_AUTHORIZATION_REQUIRED",
                401
            );
        }
        const record = repository.findById(authorizationId);
        if (!record) {
            throw new RemoteSigningAuthorizationError(
                "Remote signing authorization not found",
                "OTP_AUTHORIZATION_NOT_FOUND",
                404
            );
        }
        if (record.status !== "verified") {
            const replayStates = new Set(["processing", "used", "failed", "expired", "invalidated"]);
            throw new RemoteSigningAuthorizationError(
                replayStates.has(record.status)
                    ? "OTP authorization has already been consumed"
                    : "OTP authorization has not been verified",
                replayStates.has(record.status)
                    ? "OTP_REPLAY_DETECTED"
                    : "OTP_AUTHORIZATION_NOT_VERIFIED",
                replayStates.has(record.status) ? 409 : 403
            );
        }
        if (record.document_id !== documentId ||
            String(record.requested_by) !== String(officerId) ||
            record.signing_request_id !== requestId) {
            throw new RemoteSigningAuthorizationError(
                "OTP authorization is bound to another officer, document, or request",
                "OTP_DOCUMENT_BINDING_MISMATCH",
                403
            );
        }
        if (record.certificate_id !== certificateId) {
            throw new RemoteSigningAuthorizationError(
                "OTP authorization is bound to another remote certificate",
                "OTP_CERTIFICATE_BINDING_MISMATCH",
                403
            );
        }
        const suppliedNonceHash = hmacHex(otpSecret, authorizationId, nonce);
        if (!secureHexEqual(record.signing_nonce_hash, suppliedNonceHash)) {
            throw new RemoteSigningAuthorizationError(
                "OTP authorization nonce binding is invalid",
                "OTP_SIGNING_NONCE_MISMATCH",
                403
            );
        }

        const now = nowFn();
        if (!record.authorization_expires_at ||
            new Date(record.authorization_expires_at).getTime() <= now.getTime()) {
            repository.update(authorizationId, {
                status: "expired",
                failed_at: asIso(now),
                failure_code: "OTP_EXPIRED",
            });
            throw new RemoteSigningAuthorizationError(
                "Verified OTP authorization has expired",
                "OTP_EXPIRED",
                410
            );
        }
        const suppliedTokenHash = hmacHex(
            otpSecret,
            authorizationId,
            authorizationToken
        );
        if (!secureHexEqual(record.authorization_token_hash, suppliedTokenHash)) {
            throw new RemoteSigningAuthorizationError(
                "Invalid OTP authorization token",
                "OTP_AUTHORIZATION_TOKEN_INVALID",
                403
            );
        }

        await assertCurrentDocument(record);
        const reserved = repository.update(authorizationId, {
            status: "processing",
            processing_at: asIso(now),
            authorization_token_hash: null,
        });
        await audit({
            action: "REMOTE_OTP_AUTHORIZATION_RESERVED",
            authorizationId,
            requestId,
            documentId,
            officerId,
            ipAddress,
            result: "success",
            details: { certificate_id: certificateId },
        });
        return reserved;
    }

    async function complete({
        authorizationId,
        documentId,
        officerId,
        ipAddress = null,
    }) {
        const record = repository.findById(authorizationId);
        if (!record || record.status !== "processing") {
            throw new RemoteSigningAuthorizationError(
                "OTP authorization is not reserved for completion",
                "OTP_AUTHORIZATION_STATE_INVALID",
                409
            );
        }
        const completed = repository.update(authorizationId, {
            status: "used",
            used_at: asIso(nowFn()),
        });
        await audit({
            action: "REMOTE_OTP_AUTHORIZATION_USED",
            authorizationId,
            requestId: record.signing_request_id,
            documentId,
            officerId,
            ipAddress,
            result: "success",
            details: { certificate_id: record.certificate_id },
        });
        return completed;
    }

    async function fail({
        authorizationId,
        documentId,
        officerId,
        ipAddress = null,
        failureCode = "REMOTE_SIGNING_FAILED",
    }) {
        if (!authorizationId) return null;
        const record = repository.findById(authorizationId);
        if (!record || record.status !== "processing") return record;
        const failed = repository.update(authorizationId, {
            status: "failed",
            failed_at: asIso(nowFn()),
            failure_code: failureCode,
        });
        await audit({
            action: "REMOTE_OTP_AUTHORIZATION_FAILED",
            authorizationId,
            requestId: record.signing_request_id,
            documentId,
            officerId,
            ipAddress,
            result: "failed",
            details: { failure_code: failureCode },
        });
        return failed;
    }

    return { create, verify, reserve, complete, fail };
}

const defaultManager = createRemoteSigningAuthorizationManager();

export const createRemoteSigningAuthorization = defaultManager.create;
export const verifyRemoteSigningOtp = defaultManager.verify;
export const reserveRemoteSigningAuthorization = defaultManager.reserve;
export const completeRemoteSigningAuthorization = defaultManager.complete;
export const failRemoteSigningAuthorization = defaultManager.fail;
