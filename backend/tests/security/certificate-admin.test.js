import { describe, expect, it, beforeEach } from "vitest";
import { createMemoryCertificateRequestRepository } from "../../src/services/certificate-request.repository.js";
import { createCertificateLifecycleManager, assertCertificateUsableForSigning, assertRevocationConsistency } from "../../src/services/certificate-admin.service.js";

const citizen = { id: 4, citizen_id: "CITIZEN-001", roles: ["citizen"] };
const officer = { id: 1, officer_id: "OFFICER-001", roles: ["officer"] };
const admin = { id: 9, roles: ["admin"] };
let repository;
let certificates;
let manager;
let counter;

beforeEach(() => {
    counter = 0;
    repository = createMemoryCertificateRequestRepository();
    certificates = [];
    manager = createCertificateLifecycleManager({
        repository,
        userLookup: (id) => [citizen, officer, admin].find((u) => String(u.id) === String(id)),
        certificateList: () => certificates,
        issueExecutor: async (request) => {
            const certificate = {
                certificate_id: `CERT-${request.subject_id}-TEST-${++counter}`,
                user_id: request.user_id,
                citizen_id: request.certificate_role === "citizen" ? request.subject_id : null,
                officer_id: request.certificate_role === "officer" ? request.subject_id : null,
                signer_type: request.certificate_role,
                provider: request.provider,
                key_provider: request.provider,
                serial_number: `AA${counter}`,
                status: "active",
            };
            certificates.push(certificate);
            return certificate;
        },
        revokeExecutor: async (request) => {
            const cert = certificates.find((c) => c.certificate_id === request.target_certificate_id);
            cert.status = "revoked";
            cert.revoked_at = "2026-06-25T00:00:00.000Z";
            return cert;
        },
        certificateUpdate: (id, patch) => {
            const cert = certificates.find((c) => c.certificate_id === id);
            Object.assign(cert, patch);
            return cert;
        },
        clientAgentSync: () => null,
        nowFn: () => new Date("2026-06-25T12:00:00.000Z"),
        uuidFn: () => `id-${++counter}`,
        auditFn: async () => null,
    });
});

describe("Single-admin certificate lifecycle", () => {
    it("creates, approves and issues a citizen software certificate request", async () => {
        const request = await manager.create({ user: citizen, requestType: "issue", certificateRole: "citizen", provider: "software" });
        expect(request.status).toBe("PENDING");
        await manager.approve({ admin, requestId: request.request_id });
        const result = await manager.issue({ admin, requestId: request.request_id });
        expect(result.request.status).toBe("ISSUED");
        expect(result.certificate.citizen_id).toBe("CITIZEN-001");
    });

    it("blocks a citizen from requesting an officer certificate", async () => {
        await expect(manager.create({ user: citizen, requestType: "issue", certificateRole: "officer", provider: "software" }))
            .rejects.toMatchObject({ code: "CERTIFICATE_ROLE_NOT_ALLOWED", status: 403 });
    });

    it("requires admin approval before certificate issuance", async () => {
        const request = await manager.create({ user: citizen, requestType: "issue", certificateRole: "citizen", provider: "software" });
        await expect(manager.issue({ admin, requestId: request.request_id }))
            .rejects.toMatchObject({ code: "RA_APPROVAL_REQUIRED", status: 409 });
    });

    it("detects CSR changes after approval", async () => {
        const request = await manager.create({ user: citizen, requestType: "issue", certificateRole: "citizen", provider: "software", csrPem: "CSR-A" });
        await manager.approve({ admin, requestId: request.request_id });
        repository.update(request.request_id, { csr_sha256: "CHANGED" });
        await expect(manager.issue({ admin, requestId: request.request_id }))
            .rejects.toMatchObject({ code: "CSR_DIGEST_MISMATCH" });
    });

    it("detects public-key changes after approval", async () => {
        const request = await manager.create({ user: citizen, requestType: "issue", certificateRole: "citizen", provider: "software", publicKeyPem: "KEY-A" });
        await manager.approve({ admin, requestId: request.request_id });
        repository.update(request.request_id, { public_key_sha256: "CHANGED" });
        await expect(manager.issue({ admin, requestId: request.request_id }))
            .rejects.toMatchObject({ code: "PUBLIC_KEY_BINDING_MISMATCH" });
    });

    it("rejects a duplicate certificate serial", async () => {
        certificates.push({ certificate_id: "EXISTING", citizen_id: "OTHER", serial_number: "DUP", status: "active" });
        manager = createCertificateLifecycleManager({
            repository,
            certificateList: () => certificates,
            issueExecutor: async (request) => {
                const cert = { certificate_id: "NEW", citizen_id: request.subject_id, serial_number: "DUP", status: "active", provider: request.provider };
                certificates.push(cert); return cert;
            },
            certificateUpdate: () => null, clientAgentSync: () => null,
            nowFn: () => new Date("2026-06-25T12:00:00.000Z"), uuidFn: () => `dup-${++counter}`, auditFn: async () => null,
        });
        const request = await manager.create({ user: citizen, requestType: "issue", certificateRole: "citizen", provider: "software" });
        await manager.approve({ admin, requestId: request.request_id });
        await expect(manager.issue({ admin, requestId: request.request_id })).rejects.toMatchObject({ code: "CERTIFICATE_SERIAL_DUPLICATE" });
    });

    it("rejects a certificate issued for another owner", async () => {
        manager = createCertificateLifecycleManager({
            repository, certificateList: () => certificates,
            issueExecutor: async () => ({ certificate_id: "WRONG", citizen_id: "CITIZEN-999", serial_number: "BB", status: "active" }),
            certificateUpdate: () => null, clientAgentSync: () => null,
            nowFn: () => new Date("2026-06-25T12:00:00.000Z"), uuidFn: () => `owner-${++counter}`, auditFn: async () => null,
        });
        const request = await manager.create({ user: citizen, requestType: "issue", certificateRole: "citizen", provider: "software" });
        await manager.approve({ admin, requestId: request.request_id });
        await expect(manager.issue({ admin, requestId: request.request_id })).rejects.toMatchObject({ code: "CERTIFICATE_OWNER_MISMATCH" });
    });

    it("revokes a certificate only through an approved request", async () => {
        certificates.push({ certificate_id: "CERT-CITIZEN-A", user_id: 4, citizen_id: "CITIZEN-001", status: "active", provider: "software" });
        const request = await manager.create({ user: citizen, requestType: "revoke", certificateRole: "citizen", targetCertificateId: "CERT-CITIZEN-A", revocationReason: "keyCompromise" });
        await manager.approve({ admin, requestId: request.request_id });
        const result = await manager.issue({ admin, requestId: request.request_id });
        expect(result.request.status).toBe("REVOKED");
        expect(result.certificate.status).toBe("revoked");
        expect(() => assertCertificateUsableForSigning(result.certificate)).toThrowError(expect.objectContaining({ code: "CERTIFICATE_REVOKED" }));
    });

    it("detects CRL/OCSP disagreement with a revoked registry record", () => {
        const certificate = { status: "revoked", revoked_at: "2026-06-25T00:00:00.000Z" };
        expect(() => assertRevocationConsistency({ certificate, crlResult: { revoked: false }, ocspResult: { status: "good" } }))
            .toThrowError(expect.objectContaining({ code: "CRL_REVOCATION_MISSING" }));
        expect(() => assertRevocationConsistency({ certificate, crlResult: { revoked: true }, ocspResult: { status: "good" } }))
            .toThrowError(expect.objectContaining({ code: "OCSP_REVOCATION_STATUS_MISMATCH" }));
    });

    it("lets ADMIN revoke an active certificate directly without an owner request", async () => {
        certificates.push({
            certificate_id: "CERT-CITIZEN-DIRECT",
            user_id: 4,
            citizen_id: "CITIZEN-001",
            signer_type: "citizen",
            status: "active",
            provider: "software",
        });

        const result = await manager.revokeDirect({
            admin,
            certificateId: "CERT-CITIZEN-DIRECT",
            reason: "keyCompromise",
            confirmation: "CERT-CITIZEN-DIRECT",
        });

        expect(result.certificate.status).toBe("revoked");
        expect(result.request.status).toBe("REVOKED");
        expect(result.request.request_origin).toBe("admin");
        expect(result.request.admin_direct_revocation).toBe(true);
        expect(repository.listEvents().some((event) => event.action === "ADMIN_DIRECT_CERTIFICATE_REVOKED")).toBe(true);
    });

    it("rejects direct revocation by a non-admin user", async () => {
        certificates.push({ certificate_id: "CERT-NON-ADMIN", citizen_id: "CITIZEN-001", status: "active", provider: "software" });
        await expect(manager.revokeDirect({
            admin: citizen,
            certificateId: "CERT-NON-ADMIN",
            reason: "keyCompromise",
            confirmation: "CERT-NON-ADMIN",
        })).rejects.toMatchObject({ code: "ADMIN_ROLE_REQUIRED", status: 403 });
    });

    it("requires exact certificate-ID confirmation for direct revocation", async () => {
        certificates.push({ certificate_id: "CERT-CONFIRM", citizen_id: "CITIZEN-001", status: "active", provider: "software" });
        await expect(manager.revokeDirect({
            admin,
            certificateId: "CERT-CONFIRM",
            reason: "keyCompromise",
            confirmation: "WRONG-ID",
        })).rejects.toMatchObject({ code: "DIRECT_REVOCATION_CONFIRMATION_REQUIRED", status: 400 });
    });

    it("rejects repeated direct revocation of an already revoked certificate", async () => {
        certificates.push({
            certificate_id: "CERT-ALREADY-REVOKED",
            citizen_id: "CITIZEN-001",
            status: "revoked",
            revoked_at: "2026-06-25T00:00:00.000Z",
            provider: "software",
        });
        await expect(manager.revokeDirect({
            admin,
            certificateId: "CERT-ALREADY-REVOKED",
            reason: "keyCompromise",
            confirmation: "CERT-ALREADY-REVOKED",
        })).rejects.toMatchObject({ code: "CERTIFICATE_ALREADY_REVOKED", status: 409 });
    });

});
