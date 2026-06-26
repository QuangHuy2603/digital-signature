import { createCitizenSigningManager } from "../src/services/citizen-signing.service.js";

export function createAttackFixture({ changingHash = false, expired = false, identityError = null } = {}) {
    let document = { document_id: "HS-ATTACK-CITIZEN", owner_id: 4, file_path: "/tmp/citizen-attack.pdf", status: "awaiting_citizen_signature" };
    const requests = new Map();
    let hashCalls = 0;
    let currentTime = new Date("2026-06-25T10:00:00.000Z");
    const manager = createCitizenSigningManager({
        findDocumentFn: async (id) => id === document.document_id ? document : null,
        updateDocumentFn: async (_id, patch) => (document = { ...document, ...patch }),
        hashFileFn: async () => {
            hashCalls += 1;
            return changingHash && hashCalls > 1 ? "BB".repeat(32) : "AA".repeat(32);
        },
        identityLoader: async () => {
            if (identityError) throw identityError;
            return {
                user: { id: 4, citizen_id: "CITIZEN-001", roles: ["citizen"] },
                certificateRecord: { certificate_id: "CERT-CITIZEN-001-SOFTWARE-V1", fingerprint_sha256: "11".repeat(32), status: "active" },
                certificatePem: "CERTIFICATE",
                certificate: { subject: "UID=CITIZEN-001", issuer: "CN=ROOT" },
                revocation: { source: "OCSP", ocsp: { certificate_status: "good" } },
            };
        },
        agentSigner: async ({ canonicalPayload }) => ({ key_reference: "software:test", key_exportable: true, canonical_payload_sha256: "22".repeat(32), signature_algorithm: "ECDSA-P256-SHA256", signature_der_base64: "MEUCIQ==", signature_valid: true, client_agent_version: "1.0.0", canonical_payload: canonicalPayload }),
        auditFn: async () => {},
        createRecord: (record) => { requests.set(record.request_id, record); return record; },
        findRequest: (id) => requests.get(id) || null,
        updateRequest: (id, patch) => { const updated = { ...requests.get(id), ...patch }; requests.set(id, updated); return updated; },
        nowFn: () => currentTime,
        randomUUIDFn: () => "citizen-attack-request",
        randomBytesFn: () => Buffer.from("attack-nonce"),
        ttlSeconds: expired ? 1 : 300,
    });
    return {
        manager,
        requests,
        getDocument: () => document,
        advanceTime(ms) { currentTime = new Date(currentTime.getTime() + ms); },
    };
}
