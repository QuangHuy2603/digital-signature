import { createMemoryCertificateRequestRepository } from "../src/services/certificate-request.repository.js";
import { createCertificateLifecycleManager } from "../src/services/certificate-admin.service.js";

const repository = createMemoryCertificateRequestRepository();
const citizen = { id: 4, citizen_id: "CITIZEN-001", roles: ["citizen"] };
const admin = { id: 5, roles: ["admin"] };
const certificates = [];
let seq = 0;

const manager = createCertificateLifecycleManager({
    repository,
    certificateList: () => certificates,
    issueExecutor: async (request) => {
        const certificate = {
            certificate_id: `CERT-${request.subject_id}-LIFECYCLE-DEMO-V1`,
            citizen_id: request.subject_id,
            user_id: request.user_id,
            signer_type: request.certificate_role,
            provider: request.provider,
            key_provider: request.provider,
            serial_number: "19AA",
            status: "active",
        };
        certificates.push(certificate);
        return certificate;
    },
    revokeExecutor: async (request) => {
        const certificate = certificates.find((item) => item.certificate_id === request.target_certificate_id);
        certificate.status = "revoked";
        certificate.revoked_at = "2026-06-25T12:05:00.000Z";
        certificate.revocation_reason = request.revocation_reason;
        return certificate;
    },
    certificateUpdate: () => null,
    clientAgentSync: () => null,
    nowFn: () => new Date("2026-06-25T12:00:00.000Z"),
    uuidFn: () => `lifecycle-${++seq}`,
    auditFn: async () => null,
});

const created = await manager.create({
    user: citizen,
    requestType: "issue",
    certificateRole: "citizen",
    provider: "software",
});
const approved = await manager.approve({ admin, requestId: created.request_id });
const issued = await manager.issue({ admin, requestId: created.request_id });
const directlyRevoked = await manager.revokeDirect({
    admin,
    certificateId: issued.certificate.certificate_id,
    reason: "keyCompromise",
    confirmation: issued.certificate.certificate_id,
});

const pass = created.status === "PENDING"
    && approved.status === "APPROVED"
    && issued.request.status === "ISSUED"
    && directlyRevoked.request.status === "REVOKED"
    && directlyRevoked.request.request_origin === "admin"
    && directlyRevoked.certificate.status === "revoked";

console.log(JSON.stringify({
    test: "ADMIN_CERTIFICATE_LIFECYCLE_END_TO_END",
    result: pass ? "PASS" : "FAIL",
    flow: [
        "citizen request",
        "admin approval",
        "CA issuance",
        "certificate registry",
        "admin direct revocation",
        "revoked lifecycle record",
    ],
    issue_request_id: created.request_id,
    direct_revocation_request_id: directlyRevoked.request.request_id,
    certificate_id: issued.certificate.certificate_id,
    certificate_status: directlyRevoked.certificate.status,
    request_origin: directlyRevoked.request.request_origin,
    audit_events: repository.listEvents().length,
}, null, 2));

process.exit(pass ? 0 : 1);
