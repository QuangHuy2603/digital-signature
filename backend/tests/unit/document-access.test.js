import fs from "node:fs";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
    getDocument,
    getDocuments,
    getDocumentsByOwner
} from "../../src/services/document.service.js";

const dataFilePath = path.resolve("src/data/documents.json");
let originalDocumentsJson = null;

const fixtureDocuments = [
    {
        document_id: "HS-TEST-OWNER-1",
        owner_id: "1",
        original_name: "CT01.pdf",
        file_hash: null,
        original_file_hash: "a".repeat(64),
        file_path: "storage/documents/HS-TEST-OWNER-1/original.pdf",
        signed_pdf_path: null,
        status: "submitted",
        created_at: "2026-05-24T00:00:00.000Z",
        signed_at: null
    },
    {
        document_id: "HS-TEST-OWNER-2",
        owner_id: "2",
        original_name: "CT01.pdf",
        file_hash: "b".repeat(64),
        original_file_hash: "b".repeat(64),
        file_path: "storage/documents/HS-TEST-OWNER-2/original.pdf",
        signed_pdf_path: "storage/documents/HS-TEST-OWNER-2/signed.pdf",
        status: "issued",
        created_at: "2026-05-24T00:00:00.000Z",
        signed_at: "2026-05-24T00:10:00.000Z"
    }
];

beforeAll(() => {
    fs.mkdirSync(path.dirname(dataFilePath), { recursive: true });
    if (fs.existsSync(dataFilePath)) {
        originalDocumentsJson = fs.readFileSync(dataFilePath, "utf8");
    }
    fs.writeFileSync(dataFilePath, JSON.stringify(fixtureDocuments, null, 2));
});

afterAll(() => {
    if (originalDocumentsJson === null) {
        fs.rmSync(dataFilePath, { force: true });
        return;
    }
    fs.writeFileSync(dataFilePath, originalDocumentsJson);
});

describe("document access helpers", () => {
    it("returns only documents owned by the requested citizen", async () => {
        const ownerOneDocuments = await getDocumentsByOwner("1");

        expect(ownerOneDocuments).toHaveLength(1);
        expect(ownerOneDocuments[0].document_id).toBe("HS-TEST-OWNER-1");
    });

    it("keeps all documents available for officer listing paths", async () => {
        expect(await getDocuments()).toHaveLength(2);
    });

    it("returns a sanitized document detail shape", async () => {
        const document = await getDocument("HS-TEST-OWNER-2");

        expect(document.owner_id).toBe("2");
        expect(document.signed_pdf_url).toBe("/api/app/documents/HS-TEST-OWNER-2/signed-pdf");
    });
});
