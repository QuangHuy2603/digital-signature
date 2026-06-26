import crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import { executeCitizenDigestSigningJob, listClientAgentCertificates } from "../../../client-agent/src/agent-core.js";
import { buildCitizenSignaturePayload } from "../../src/crypto/citizen-signature-payload.js";
import { verifyCitizenDetachedSignature } from "../../src/crypto/citizen-signature.service.js";
import { validateCitizenPkcs11Binding } from "../../../client-agent/src/providers.js";

describe("Citizen PKCS#11 citizen Client Agent providers", () => {
    it("lists the provisioned citizen software certificate", () => {
        const certificates = listClientAgentCertificates({ signerType: "citizen", userId: 4 });
        expect(certificates.some((item) => item.certificate_id === "CERT-CITIZEN-001-SOFTWARE-V1" && item.provider_ready)).toBe(true);
    });

    it("signs a canonical document digest using the citizen software key", async () => {
        const payload = {
            request_id: crypto.randomUUID(),
            document_id: "HS-CITIZEN-AGENT",
            user_id: 4,
            citizen_id: "CITIZEN-001",
            certificate_id: "CERT-CITIZEN-001-SOFTWARE-V1",
            provider: "software",
            created_at: "2026-06-25T10:00:00.000Z",
            document_digest_sha256: crypto.createHash("sha256").update("citizen document").digest("hex").toUpperCase(),
        };
        payload.canonical_payload = buildCitizenSignaturePayload({
            requestId: payload.request_id,
            documentId: payload.document_id,
            citizenId: payload.citizen_id,
            userId: payload.user_id,
            certificateId: payload.certificate_id,
            documentDigestSha256: payload.document_digest_sha256,
            createdAt: payload.created_at,
        });
        const result = await executeCitizenDigestSigningJob(payload);
        const certPem = Buffer.from(result.certificate_pem_base64, "base64").toString("utf8");
        expect(result.provider).toBe("software");
        expect(result.key_exportable).toBe(true);
        expect(verifyCitizenDetachedSignature({ signatureBase64: result.signature_der_base64, canonicalPayload: result.canonical_payload, certificatePem: certPem })).toBe(true);
    });

    it("rejects cross-citizen and certificate-role misuse", async () => {
        const base = {
            request_id: crypto.randomUUID(),
            document_id: "HS-CROSS-CITIZEN",
            user_id: 999,
            citizen_id: "CITIZEN-999",
            certificate_id: "CERT-CITIZEN-001-SOFTWARE-V1",
            provider: "software",
            created_at: "2026-06-25T10:00:00.000Z",
            document_digest_sha256: "AA".repeat(32),
        };
        await expect(executeCitizenDigestSigningJob(base)).rejects.toMatchObject({ code: "CITIZEN_CERTIFICATE_OWNER_MISMATCH" });
        await expect(executeCitizenDigestSigningJob({ ...base, user_id: 1, citizen_id: "OFFICER-001", certificate_id: "CERT-OFFICER-001-V1" }))
            .rejects.toMatchObject({ code: "CERTIFICATE_ROLE_MISMATCH" });
    });

    it("enforces deterministic citizen PKCS#11 key ownership binding", () => {
        const certificateId = "CERT-CITIZEN-001-PKCS11-V2";
        const id = crypto.createHash("sha256").update(certificateId).digest("hex").slice(0, 32);
        expect(validateCitizenPkcs11Binding({
            certificate_id: certificateId,
            version: 2,
            signer_type: "citizen",
            citizen_id: "CITIZEN-001",
            pkcs11_token_label: "NT219-CITIZEN",
            pkcs11_key_label: "NT219-CITIZEN-001-SIGNING-V2",
            pkcs11_key_id: id,
            pkcs11_binding_scheme: "nt219-citizen-deterministic-v1",
        })).toMatchObject({ key_id: id });
        expect(() => validateCitizenPkcs11Binding({
            certificate_id: certificateId,
            version: 2,
            signer_type: "citizen",
            citizen_id: "CITIZEN-001",
            pkcs11_token_label: "NT219-CITIZEN",
            pkcs11_key_label: "NT219-CITIZEN-999-SIGNING-V2",
            pkcs11_key_id: id,
            pkcs11_binding_scheme: "nt219-citizen-deterministic-v1",
        })).toThrowError(expect.objectContaining({ code: "CITIZEN_PKCS11_KEY_OWNER_MISMATCH" }));
    });
});
