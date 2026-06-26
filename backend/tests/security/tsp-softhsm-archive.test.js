import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createPadesLtFixture } from "../helpers/pades-fixture.js";
import { executeTspSigningJob } from "../../src/services/tsp-signing.service.js";
import { buildPkcs11Uri, getSigningProviderStatus } from "../../src/crypto/signing-provider.service.js";
import { createLtvArchive, getArchiveStatus, verifyLtvArchive } from "../../src/services/archive.service.js";

let fixture;
const archiveIds = [];
const previousProvider = process.env.SIGNING_PROVIDER;

beforeAll(async () => {
    process.env.SIGNING_PROVIDER = "file";
    fixture = await createPadesLtFixture({ text: "Authenticated TSP and archive integration fixture" });
}, 120000);

afterAll(() => {
    fixture?.cleanup();
    for (const id of archiveIds) {
        fs.rmSync(path.resolve("storage/archive", id), { recursive: true, force: true });
    }
    process.env.SIGNING_PROVIDER = previousProvider;
});

describe("Authenticated TSP signing core", () => {
    it("creates a valid PAdES-B-T response using the selected provider", async () => {
        const input = fs.readFileSync(fixture.inputPdfPath);
        const result = await executeTspSigningJob({
            request_id: crypto.randomUUID(),
            document_id: "HS-TSP-TEST",
            certificate_id: fixture.certificateRecord.certificate_id,
            signer: { full_name: "Officer Test", email: "officer@test.com" },
            input_pdf_base64: input.toString("base64"),
            document_digest_sha256: crypto.createHash("sha256").update(input).digest("hex").toUpperCase(),
        });
        expect(result.status).toBe("signed");
        expect(result.pades.verification.valid).toBe(true);
        expect(result.key_provider).toBe("file");
        expect(result.signed_pdf_base64.length).toBeGreaterThan(1000);
    }, 120000);

    it("rejects a request whose digest does not match the supplied PDF", async () => {
        await expect(executeTspSigningJob({
            request_id: crypto.randomUUID(),
            document_id: "HS-TSP-DIGEST",
            certificate_id: fixture.certificateRecord.certificate_id,
            input_pdf_base64: fs.readFileSync(fixture.inputPdfPath).toString("base64"),
            document_digest_sha256: "00".repeat(32),
        })).rejects.toMatchObject({ code: "TSP_DOCUMENT_DIGEST_MISMATCH" });
    });
});

describe("Signing-provider abstraction", () => {
    it("reports the file provider as ready for the portable demo", () => {
        const status = getSigningProviderStatus();
        expect(status.selected_provider).toBe("file");
        expect(status.ready).toBe(true);
        expect(status.file_provider.private_keys_exportable).toBe(true);
    });

    it("builds a stable PKCS#11 URI for the SoftHSM provider", () => {
        const uri = buildPkcs11Uri(fixture.certificateRecord);
        expect(uri).toContain("pkcs11:token=");
        expect(uri).toContain("type=private");
        expect(uri).toContain("object=");
    });
});

describe("Sealed PAdES-LT archive", () => {
    it("trusts the dedicated archive-seal certificate", () => {
        const status = getArchiveStatus();
        expect(status.ready).toBe(true);
        expect(status.seal_certificate_trusted).toBe(true);
    });

    it("creates, verifies and detects tampering in an evidence bundle", () => {
        const archive = createLtvArchive({
            documentId: "HS-ARCHIVE-TEST",
            originalPdfPath: fixture.inputPdfPath,
            signedPdfPath: fixture.signedPdfPath,
            metadata: { document_id: "HS-ARCHIVE-TEST", pades_level: "PAdES-LT", key_provider: "file", tsp_mode: "local" },
            certificateRecord: fixture.certificateRecord,
            ocspEvidence: {},
            padesEvidence: { ...fixture.evidence, verification: fixture.verification, lt_evidence: fixture.ltEvidence },
            timestampEvidence: fixture.evidence.timestamp_evidence,
        });
        archiveIds.push(archive.archive_id);
        expect(verifyLtvArchive(archive.archive_id).valid).toBe(true);
        const target = path.join(archive.archive_path, "documents/signed.pdf");
        fs.appendFileSync(target, Buffer.from("tampered"));
        const tampered = verifyLtvArchive(archive.archive_id);
        expect(tampered.valid).toBe(false);
        expect(tampered.reason).toBe("ARCHIVE_FILE_TAMPERED");
    });
});
