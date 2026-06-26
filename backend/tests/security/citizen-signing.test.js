import { describe, expect, it } from "vitest";
import { createCitizenSigningManager } from "../../src/services/citizen-signing.service.js";

function fixture(overrides = {}) {
    const document = {
        document_id: "HS-2026-CITIZEN",
        owner_id: 4,
        file_path: "/tmp/citizen.pdf",
        status: "awaiting_citizen_signature",
        ...overrides.document,
    };
    const requests = new Map();
    let savedDocument = document;
    const identity = {
        user: { id: 4, citizen_id: "CITIZEN-001", roles: ["citizen"] },
        certificateRecord: {
            certificate_id: "CERT-CITIZEN-001-SOFTWARE-V1",
            fingerprint_sha256: "AA".repeat(32),
            status: "active",
        },
        certificatePem: "CERTIFICATE",
        certificate: { subject: "UID=CITIZEN-001", issuer: "CN=ROOT" },
        revocation: { source: "OCSP", ocsp: { certificate_status: "good" } },
    };
    const manager = createCitizenSigningManager({
        findDocumentFn: async () => savedDocument,
        updateDocumentFn: async (_id, patch) => (savedDocument = { ...savedDocument, ...patch }),
        hashFileFn: async () => overrides.hash || "11".repeat(32).toUpperCase(),
        identityLoader: async (input) => {
            if (overrides.identityError) throw overrides.identityError;
            return { ...identity, requested: input };
        },
        agentSigner: async ({ request, canonicalPayload }) => ({
            key_reference: "client-agent-software:test",
            key_exportable: true,
            canonical_payload_sha256: "22".repeat(32),
            signature_algorithm: "ECDSA-P256-SHA256",
            signature_der_base64: "MEUCIQ==",
            signature_valid: true,
            client_agent_version: "1.0.0",
            canonical_payload: canonicalPayload,
            request_id: request.request_id,
        }),
        auditFn: async () => {},
        createRecord: (record) => { requests.set(record.request_id, record); return record; },
        findRequest: (id) => requests.get(id) || null,
        updateRequest: (id, patch) => { const next = { ...requests.get(id), ...patch }; requests.set(id, next); return next; },
        nowFn: () => new Date("2026-06-25T10:00:00.000Z"),
        randomUUIDFn: () => "citizen-request-001",
        randomBytesFn: () => Buffer.from("citizen-nonce"),
        ttlSeconds: 300,
    });
    return { manager, requests, getDocument: () => savedDocument };
}

describe("Citizen signing citizen submission signing", () => {
    it("creates a one-time request bound to citizen, certificate, provider and digest", async () => {
        const { manager } = fixture();
        const result = await manager.create({ documentId: "HS-2026-CITIZEN", userId: 4, provider: "software" });
        expect(result.request_id).toBe("citizen-request-001");
        expect(result.citizen_id).toBe("CITIZEN-001");
        expect(result.certificate_id).toBe("CERT-CITIZEN-001-SOFTWARE-V1");
        expect(result.document_digest_sha256).toBe("11".repeat(32).toUpperCase());
    });

    it("rejects another citizen attempting to sign the document", async () => {
        const { manager } = fixture();
        await expect(manager.create({ documentId: "HS-2026-CITIZEN", userId: 99, provider: "software" }))
            .rejects.toMatchObject({ code: "CITIZEN_DOCUMENT_OWNER_MISMATCH" });
    });

    it("moves a valid citizen-signed document into officer review", async () => {
        const { manager, getDocument } = fixture();
        const created = await manager.create({ documentId: "HS-2026-CITIZEN", userId: 4, provider: "software" });
        const result = await manager.sign({ documentId: "HS-2026-CITIZEN", userId: 4, requestId: created.request_id, nonce: created.nonce });
        expect(result.status).toBe("submitted");
        expect(result.signature_valid).toBe(true);
        expect(getDocument().citizen_signature_valid).toBe(true);
        expect(getDocument().citizen_signature.provider).toBe("software");
    });

    it("blocks replay of a used citizen signing request", async () => {
        const { manager } = fixture();
        const created = await manager.create({ documentId: "HS-2026-CITIZEN", userId: 4, provider: "software" });
        await manager.sign({ documentId: "HS-2026-CITIZEN", userId: 4, requestId: created.request_id, nonce: created.nonce });
        await expect(manager.sign({ documentId: "HS-2026-CITIZEN", userId: 4, requestId: created.request_id, nonce: created.nonce }))
            .rejects.toMatchObject({ code: "CITIZEN_SIGNING_REPLAY_DETECTED" });
    });

    it("rejects digest substitution after the request is created", async () => {
        let calls = 0;
        // Use an isolated manager with a hash that changes between create and sign.
        const requests = new Map();
        let document = { document_id: "HS-DIGEST", owner_id: 4, file_path: "/tmp/a.pdf", status: "awaiting_citizen_signature" };
        const changing = createCitizenSigningManager({
            findDocumentFn: async () => document,
            updateDocumentFn: async (_id, patch) => (document = { ...document, ...patch }),
            hashFileFn: async () => (++calls === 1 ? "AA".repeat(32) : "BB".repeat(32)),
            identityLoader: async () => ({ user: { id: 4, citizen_id: "CITIZEN-001" }, certificateRecord: { certificate_id: "CERT-CITIZEN-001-SOFTWARE-V1" } }),
            agentSigner: async () => ({}),
            auditFn: async () => {},
            createRecord: (record) => { requests.set(record.request_id, record); return record; },
            findRequest: (id) => requests.get(id),
            updateRequest: (id, patch) => { const next = { ...requests.get(id), ...patch }; requests.set(id, next); return next; },
            nowFn: () => new Date("2026-06-25T10:00:00Z"),
            randomUUIDFn: () => "digest-request",
            randomBytesFn: () => Buffer.from("nonce"),
        });
        const created = await changing.create({ documentId: "HS-DIGEST", userId: 4, provider: "software" });
        await expect(changing.sign({ documentId: "HS-DIGEST", userId: 4, requestId: created.request_id, nonce: created.nonce }))
            .rejects.toMatchObject({ code: "CITIZEN_DOCUMENT_DIGEST_MISMATCH" });
    });
});
