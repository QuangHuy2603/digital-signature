import { createMemoryRemoteSigningAuthorizationRepository } from "../src/services/remote-signing-authorization.repository.js";
import { createRemoteSigningAuthorizationManager } from "../src/services/remote-signing-authorization.service.js";

export function createRemoteOtpAttackFixture({ maxAttempts = 3 } = {}) {
    const documentId = "HS-REMOTE_OTP-ATTACK";
    const officerId = "1";
    const certificateId = "CERT-OFFICER-001-REMOTE-V2";
    const signingRequest = {
        request_id: "remote-otp-attack-signing-request",
        nonce: "remote-otp-attack-nonce",
        document_id: documentId,
        document_hash: "AA".repeat(32),
        signing_method: "remote",
    };
    let currentHash = signingRequest.document_hash;
    let now = new Date("2026-06-25T10:00:00.000Z");
    const repository = createMemoryRemoteSigningAuthorizationRepository();
    const manager = createRemoteSigningAuthorizationManager({
        repository,
        findDocumentByIdFn: async (id) => id === documentId ? {
            document_id: documentId,
            status: "submitted",
            file_path: "/tmp/remote-otp-attack.pdf",
        } : null,
        hashFileFn: async () => currentHash,
        auditFn: async () => null,
        nowFn: () => new Date(now),
        randomUUIDFn: () => "remote-otp-attack-authorization",
        randomBytesFn: (size) => Buffer.alloc(size),
        otpSecret: "remote-otp-attack-secret",
        otpTtlSeconds: 120,
        authorizationTtlSeconds: 120,
        maxAttempts,
        exposeDemoOtp: true,
    });

    return {
        manager,
        repository,
        documentId,
        officerId,
        certificateId,
        signingRequest,
        async createChallenge() {
            return manager.create({ signingRequest, documentId, officerId, certificateId });
        },
        async verifyChallenge(challenge) {
            return manager.verify({
                authorizationId: challenge.authorization_id,
                otp: challenge.demo_otp,
                documentId,
                officerId,
            });
        },
        reserveInput(verified, overrides = {}) {
            return {
                authorizationId: verified.authorization_id,
                authorizationToken: verified.authorization_token,
                requestId: signingRequest.request_id,
                nonce: signingRequest.nonce,
                documentId,
                officerId,
                certificateId,
                ...overrides,
            };
        },
        advance(ms) {
            now = new Date(now.getTime() + ms);
        },
        changeDigest() {
            currentHash = "BB".repeat(32);
        },
    };
}
