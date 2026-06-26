import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createMemoryRemoteSigningAuthorizationRepository } from "../../src/services/remote-signing-authorization.repository.js";
import { createRemoteSigningAuthorizationManager } from "../../src/services/remote-signing-authorization.service.js";

let temporaryDirectory;
let documentPath;
let document;
let documentHash;
let now;
let repository;
let manager;

const documentId = "HS-REMOTE_OTP-OTP-001";
const officerId = "1";
const certificateId = "CERT-OFFICER-001-REMOTE-V2";
const signingRequest = {
    request_id: "signing-request-remote-otp",
    nonce: "remote-otp-signing-nonce",
    document_id: documentId,
    document_hash: "AA".repeat(32),
    signing_method: "remote",
};

beforeEach(() => {
    temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-remote-otp-test-"));
    documentPath = path.join(temporaryDirectory, "original.pdf");
    fs.writeFileSync(documentPath, "%PDF-1.7\nREMOTE_OTP OTP TEST\n%%EOF", "utf8");
    document = {
        document_id: documentId,
        status: "submitted",
        file_path: documentPath,
    };
    documentHash = signingRequest.document_hash;
    now = new Date("2026-06-25T10:00:00.000Z");
    repository = createMemoryRemoteSigningAuthorizationRepository();
    manager = createRemoteSigningAuthorizationManager({
        repository,
        findDocumentByIdFn: async (id) => id === documentId ? document : null,
        hashFileFn: async () => documentHash,
        auditFn: async () => null,
        nowFn: () => new Date(now),
        randomUUIDFn: () => "authorization-remote-otp",
        randomBytesFn: (size) => Buffer.alloc(size),
        otpSecret: "test-otp-secret",
        otpTtlSeconds: 120,
        authorizationTtlSeconds: 120,
        maxAttempts: 3,
        exposeDemoOtp: true,
    });
});

afterEach(() => {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
});

async function createChallenge(overrides = {}) {
    return manager.create({
        signingRequest,
        documentId,
        officerId,
        certificateId,
        ...overrides,
    });
}

async function verifyChallenge(challenge, overrides = {}) {
    return manager.verify({
        authorizationId: challenge.authorization_id,
        otp: challenge.demo_otp,
        documentId,
        officerId,
        ...overrides,
    });
}

describe("Remote-signing OTP authorization", () => {
    it("verifies and consumes a correctly bound OTP authorization exactly once", async () => {
        const challenge = await createChallenge();
        expect(challenge.demo_otp).toBe("000000");
        const verified = await verifyChallenge(challenge);
        const reserved = await manager.reserve({
            authorizationId: verified.authorization_id,
            authorizationToken: verified.authorization_token,
            requestId: signingRequest.request_id,
            nonce: signingRequest.nonce,
            documentId,
            officerId,
            certificateId,
        });
        const used = await manager.complete({ authorizationId: reserved.authorization_id, documentId, officerId });
        expect(used.status).toBe("used");
        expect(used.otp_hash).toBeNull();
        expect(used.authorization_token_hash).toBeNull();
    });

    it("rejects an incorrect OTP without exposing the stored OTP", async () => {
        const challenge = await createChallenge();
        await expect(manager.verify({
            authorizationId: challenge.authorization_id,
            otp: "123456",
            documentId,
            officerId,
        })).rejects.toMatchObject({ code: "OTP_INVALID", status: 403 });
        const record = repository.findById(challenge.authorization_id);
        expect(record.attempts).toBe(1);
        expect(record.otp_hash).toMatch(/^[a-f0-9]{64}$/);
        expect(record).not.toHaveProperty("otp");
        expect(record.otp_hash).not.toBe(challenge.demo_otp);
    });

    it("locks the OTP after the configured attempt limit", async () => {
        const challenge = await createChallenge();
        for (let attempt = 1; attempt <= 2; attempt += 1) {
            await expect(manager.verify({ authorizationId: challenge.authorization_id, otp: "999999", documentId, officerId }))
                .rejects.toMatchObject({ code: "OTP_INVALID" });
        }
        await expect(manager.verify({ authorizationId: challenge.authorization_id, otp: "999999", documentId, officerId }))
            .rejects.toMatchObject({ code: "OTP_ATTEMPT_LIMIT_EXCEEDED", status: 423 });
        expect(repository.findById(challenge.authorization_id).status).toBe("locked");
    });

    it("rejects an expired OTP", async () => {
        const challenge = await createChallenge();
        now = new Date(now.getTime() + 121_000);
        await expect(verifyChallenge(challenge)).rejects.toMatchObject({ code: "OTP_EXPIRED", status: 410 });
        expect(repository.findById(challenge.authorization_id).status).toBe("expired");
    });

    it("rejects cross-document and cross-officer OTP use", async () => {
        const challenge = await createChallenge();
        await expect(verifyChallenge(challenge, { documentId: "HS-OTHER" }))
            .rejects.toMatchObject({ code: "OTP_DOCUMENT_BINDING_MISMATCH", status: 403 });
        await expect(verifyChallenge(challenge, { officerId: "2" }))
            .rejects.toMatchObject({ code: "OTP_DOCUMENT_BINDING_MISMATCH", status: 403 });
    });

    it("invalidates the OTP if the document digest changes", async () => {
        const challenge = await createChallenge();
        documentHash = "BB".repeat(32);
        await expect(verifyChallenge(challenge)).rejects.toMatchObject({ code: "OTP_DIGEST_MISMATCH", status: 409 });
        expect(repository.findById(challenge.authorization_id).status).toBe("invalidated");
    });

    it("rejects a verified token used with another certificate or nonce", async () => {
        const challenge = await createChallenge();
        const verified = await verifyChallenge(challenge);
        await expect(manager.reserve({
            authorizationId: verified.authorization_id,
            authorizationToken: verified.authorization_token,
            requestId: signingRequest.request_id,
            nonce: signingRequest.nonce,
            documentId,
            officerId,
            certificateId: "CERT-ATTACKER",
        })).rejects.toMatchObject({ code: "OTP_CERTIFICATE_BINDING_MISMATCH" });
        await expect(manager.reserve({
            authorizationId: verified.authorization_id,
            authorizationToken: verified.authorization_token,
            requestId: signingRequest.request_id,
            nonce: "changed-nonce",
            documentId,
            officerId,
            certificateId,
        })).rejects.toMatchObject({ code: "OTP_SIGNING_NONCE_MISMATCH" });
    });

    it("rejects replay after the authorization was consumed", async () => {
        const challenge = await createChallenge();
        const verified = await verifyChallenge(challenge);
        const input = {
            authorizationId: verified.authorization_id,
            authorizationToken: verified.authorization_token,
            requestId: signingRequest.request_id,
            nonce: signingRequest.nonce,
            documentId,
            officerId,
            certificateId,
        };
        await manager.reserve(input);
        await manager.complete({ authorizationId: verified.authorization_id, documentId, officerId });
        await expect(manager.reserve(input)).rejects.toMatchObject({ code: "OTP_REPLAY_DETECTED", status: 409 });
    });
});
