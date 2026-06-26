import { createMemoryCertificateRequestRepository } from "../src/services/certificate-request.repository.js";
import { createCertificateLifecycleManager, assertCertificateUsableForSigning, assertRevocationConsistency } from "../src/services/certificate-admin.service.js";

const citizen = { id: 4, citizen_id: "CITIZEN-001", roles: ["citizen"] };
const admin = { id: 5, roles: ["admin"] };
let seq = 0;

function makeManager({ certificates = [], issueExecutor, revokeExecutor } = {}) {
    const repository = createMemoryCertificateRequestRepository();
    const manager = createCertificateLifecycleManager({
        repository,
        certificateList: () => certificates,
        issueExecutor: issueExecutor || (async (request) => {
            const certificate = { certificate_id: `CERT-${request.subject_id}-${++seq}`, citizen_id: request.subject_id, user_id: request.user_id, provider: request.provider, serial_number: `S${seq}`, status: "active" };
            certificates.push(certificate); return certificate;
        }),
        revokeExecutor: revokeExecutor || (async (request) => {
            const cert = certificates.find((item) => item.certificate_id === request.target_certificate_id);
            cert.status = "revoked"; cert.revoked_at = "2026-06-25T00:00:00.000Z"; return cert;
        }),
        certificateUpdate: (id, patch) => Object.assign(certificates.find((item) => item.certificate_id === id), patch),
        clientAgentSync: () => null,
        nowFn: () => new Date("2026-06-25T12:00:00.000Z"),
        uuidFn: () => `attack-${++seq}`,
        auditFn: async () => null,
    });
    return { manager, repository, certificates };
}

async function expectCode(name, expectedCode, action) {
    try { await action(); console.log(`${name}: FAIL (not rejected)`); return false; }
    catch (error) { const pass = error.code === expectedCode; console.log(`${name}: ${pass ? "PASS" : "FAIL"}`); console.log(`Reason: ${error.code}`); return pass; }
}

let passed = true;
console.log("\n=== CERTIFICATE ADMINISTRATION ATTACKS 45-54 ===");
{
    const { manager } = makeManager();
    passed &= await expectCode("ATTACK 45 - citizen requests officer certificate", "CERTIFICATE_ROLE_NOT_ALLOWED", () => manager.create({ user: citizen, requestType: "issue", certificateRole: "officer", provider: "software" }));
}
{
    const { manager } = makeManager();
    const request = await manager.create({ user: citizen, requestType: "issue", certificateRole: "citizen", provider: "software" });
    passed &= await expectCode("ATTACK 46 - bypass approval", "RA_APPROVAL_REQUIRED", () => manager.issue({ admin, requestId: request.request_id }));
}
{
    const { manager, repository } = makeManager();
    const request = await manager.create({ user: citizen, requestType: "issue", certificateRole: "citizen", provider: "software", csrPem: "CSR-ORIGINAL" });
    await manager.approve({ admin, requestId: request.request_id }); repository.update(request.request_id, { csr_sha256: "ATTACK" });
    passed &= await expectCode("ATTACK 47 - CSR changed after approval", "CSR_DIGEST_MISMATCH", () => manager.issue({ admin, requestId: request.request_id }));
}
{
    const { manager, repository } = makeManager();
    const request = await manager.create({ user: citizen, requestType: "issue", certificateRole: "citizen", provider: "software", publicKeyPem: "KEY-ORIGINAL" });
    await manager.approve({ admin, requestId: request.request_id }); repository.update(request.request_id, { public_key_sha256: "ATTACK" });
    passed &= await expectCode("ATTACK 48 - public key substitution", "PUBLIC_KEY_BINDING_MISMATCH", () => manager.issue({ admin, requestId: request.request_id }));
}
{
    const certificates = [{ certificate_id: "EXISTING", citizen_id: "OTHER", serial_number: "DUP", status: "active" }];
    const { manager } = makeManager({ certificates, issueExecutor: async (request) => { const cert = { certificate_id: "NEW", citizen_id: request.subject_id, serial_number: "DUP", status: "active" }; certificates.push(cert); return cert; } });
    const request = await manager.create({ user: citizen, requestType: "issue", certificateRole: "citizen", provider: "software" }); await manager.approve({ admin, requestId: request.request_id });
    passed &= await expectCode("ATTACK 49 - duplicate serial", "CERTIFICATE_SERIAL_DUPLICATE", () => manager.issue({ admin, requestId: request.request_id }));
}
{
    const { manager } = makeManager({ issueExecutor: async () => ({ certificate_id: "WRONG", citizen_id: "CITIZEN-999", serial_number: "UNIQUE", status: "active" }) });
    const request = await manager.create({ user: citizen, requestType: "issue", certificateRole: "citizen", provider: "software" }); await manager.approve({ admin, requestId: request.request_id });
    passed &= await expectCode("ATTACK 50 - wrong certificate owner", "CERTIFICATE_OWNER_MISMATCH", () => manager.issue({ admin, requestId: request.request_id }));
}
{
    passed &= await expectCode("ATTACK 51 - signing after revocation", "CERTIFICATE_REVOKED", async () => assertCertificateUsableForSigning({ certificate_id: "REVOKED", status: "revoked", revoked_at: "2026-06-25T00:00:00.000Z" }));
}
{
    passed &= await expectCode("ATTACK 52 - CRL/OCSP inconsistency", "CRL_REVOCATION_MISSING", async () => assertRevocationConsistency({ certificate: { status: "revoked", revoked_at: "2026-06-25T00:00:00.000Z" }, crlResult: { revoked: false }, ocspResult: { status: "good" } }));
}

{
    const certificates = [{ certificate_id: "DIRECT-NON-ADMIN", citizen_id: "CITIZEN-001", status: "active", provider: "software" }];
    const { manager } = makeManager({ certificates });
    passed &= await expectCode("ATTACK 53 - non-admin direct revocation", "ADMIN_ROLE_REQUIRED", () => manager.revokeDirect({ admin: citizen, certificateId: "DIRECT-NON-ADMIN", reason: "keyCompromise", confirmation: "DIRECT-NON-ADMIN" }));
}
{
    const certificates = [{ certificate_id: "DIRECT-REPLAY", citizen_id: "CITIZEN-001", status: "revoked", revoked_at: "2026-06-25T00:00:00.000Z", provider: "software" }];
    const { manager } = makeManager({ certificates });
    passed &= await expectCode("ATTACK 54 - repeated admin direct revocation", "CERTIFICATE_ALREADY_REVOKED", () => manager.revokeDirect({ admin, certificateId: "DIRECT-REPLAY", reason: "keyCompromise", confirmation: "DIRECT-REPLAY" }));
}
console.log(`Certificate administration attack result: ${passed ? "PASS" : "FAIL"}`);
process.exit(passed ? 0 : 1);
