import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
    assignSigningCertificate,
    findOfficerByOfficerId,
} from "../../src/services/officer-account.service.js";
import { loadOfficerSigningIdentity } from "../../src/crypto/officer-pki.service.js";
import { validateSoftHsmCertificateBinding } from "../../src/crypto/signing-provider.service.js";

const usersPath = path.resolve("src/data/users.json");
let backup;
let officer;

beforeAll(() => {
    backup = fs.readFileSync(usersPath);
    officer = findOfficerByOfficerId("OFFICER-001");
    if (!officer?.active_certificate_id) {
        throw new Error("OFFICER-001 must have a baseline certificate for this test");
    }
});

afterAll(() => {
    if (backup) fs.writeFileSync(usersPath, backup);
});

describe("SoftHSM remote signing provider-specific certificate binding", () => {
    it("selects the remote certificate independently from the local certificate", async () => {
        assignSigningCertificate({
            officerId: "OFFICER-001",
            certificateId: officer.active_certificate_id,
            signingMethod: "remote",
        });
        const remote = await loadOfficerSigningIdentity(officer.id, { signingMethod: "remote" });
        expect(remote.certificateRecord.certificate_id).toBe(officer.active_certificate_id);

        const local = await loadOfficerSigningIdentity(officer.id, { signingMethod: "local" });
        expect(local.certificateRecord.certificate_id).toBe(
            officer.local_certificate_id || officer.active_certificate_id
        );
    });
});


describe("SoftHSM remote signing SoftHSM key ownership binding", () => {
    it("accepts a complete certificate-to-token binding", () => {
        expect(validateSoftHsmCertificateBinding({
            certificate_id: "CERT-REMOTE-001",
            key_provider: "softhsm",
            pkcs11_token_label: "NT219-TSP",
            pkcs11_key_label: "OFFICER-001-REMOTE",
            pkcs11_key_id: "0101",
        })).toEqual({
            certificate_id: "CERT-REMOTE-001",
            token_label: "NT219-TSP",
            key_label: "OFFICER-001-REMOTE",
            key_id: "0101",
        });
    });

    it("rejects a file-backed certificate in SoftHSM mode", () => {
        expect(() => validateSoftHsmCertificateBinding({
            certificate_id: "CERT-LOCAL-001",
            key_provider: "file",
            pkcs11_token_label: "NT219-TSP",
            pkcs11_key_label: "OFFICER-001-REMOTE",
            pkcs11_key_id: "0101",
        })).toThrowError(expect.objectContaining({
            code: "SOFTHSM_CERTIFICATE_PROVIDER_MISMATCH",
        }));
    });

    it("rejects an incomplete key binding instead of guessing a token key", () => {
        expect(() => validateSoftHsmCertificateBinding({
            certificate_id: "CERT-REMOTE-BROKEN",
            key_provider: "softhsm",
            pkcs11_token_label: "NT219-TSP",
        })).toThrowError(expect.objectContaining({
            code: "SOFTHSM_KEY_BINDING_MISSING",
        }));
    });
    it("rejects a deterministic binding that points at another officer key label", () => {
        const certificateId = "CERT-OFFICER-001-REMOTE-V2";
        const expectedId = crypto.createHash("sha256").update(certificateId).digest("hex").slice(0, 32);
        expect(() => validateSoftHsmCertificateBinding({
            certificate_id: certificateId,
            version: 2,
            officer_id: "OFFICER-001",
            key_provider: "softhsm",
            pkcs11_binding_scheme: "nt219-deterministic-v1",
            pkcs11_token_label: "NT219-TSP",
            pkcs11_key_label: "NT219-OFFICER-002-REMOTE-V2",
            pkcs11_key_id: expectedId,
        })).toThrowError(expect.objectContaining({
            code: "SOFTHSM_KEY_OWNER_MISMATCH",
        }));
    });

    it("rejects a deterministic binding whose key ID was substituted", () => {
        expect(() => validateSoftHsmCertificateBinding({
            certificate_id: "CERT-OFFICER-001-REMOTE-V2",
            version: 2,
            officer_id: "OFFICER-001",
            key_provider: "softhsm",
            pkcs11_binding_scheme: "nt219-deterministic-v1",
            pkcs11_token_label: "NT219-TSP",
            pkcs11_key_label: "NT219-OFFICER-001-REMOTE-V2",
            pkcs11_key_id: "00".repeat(16),
        })).toThrowError(expect.objectContaining({
            code: "SOFTHSM_KEY_ID_MISMATCH",
        }));
    });

});
