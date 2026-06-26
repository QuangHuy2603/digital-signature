import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
} from "vitest";
import {
    createMemorySigningRequestRepository,
} from "../../src/services/signing-request.repository.js";
import {
    createSigningRequestManager,
} from "../../src/services/signing-request.service.js";

let temporaryDirectory;
let documentPath;
let repository;
let manager;
let now;

const documentId = "HS-REPLAY-TEST-001";
const officerId = "officer-01";

beforeEach(() => {
    temporaryDirectory = fs.mkdtempSync(
        path.join(os.tmpdir(), "nt219-replay-test-")
    );
    documentPath = path.join(temporaryDirectory, "original.pdf");
    fs.writeFileSync(
        documentPath,
        "%PDF-1.7\nORIGINAL DOCUMENT\n%%EOF",
        "utf8"
    );

    repository = createMemorySigningRequestRepository();
    now = new Date("2026-06-24T10:00:00.000Z");

    manager = createSigningRequestManager({
        repository,
        findDocumentByIdFn: async (requestedId) => requestedId === documentId
            ? {
                document_id: documentId,
                status: "submitted",
                file_path: documentPath,
            }
            : null,
        auditFn: async () => null,
        nowFn: () => new Date(now),
        ttlSeconds: 300,
    });
});

afterEach(() => {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
});

async function createRequest() {
    return manager.create({ documentId, officerId });
}

async function reserveRequest(request, nonce = request.nonce) {
    return manager.reserve({
        requestId: request.request_id,
        nonce,
        documentId,
        officerId,
    });
}

describe("one-time remote-signing request protection", () => {
    it("accepts and consumes a valid signing request exactly once", async () => {
        const request = await createRequest();
        const reserved = await reserveRequest(request);
        const completed = await manager.complete({
            requestId: request.request_id,
            documentId,
            officerId,
        });

        expect(reserved.status).toBe("processing");
        expect(completed.status).toBe("used");
        expect(completed.used_at).toBeTruthy();
    });

    it("rejects a replay of an already used signing request", async () => {
        const request = await createRequest();
        await reserveRequest(request);
        await manager.complete({
            requestId: request.request_id,
            documentId,
            officerId,
        });

        await expect(reserveRequest(request)).rejects.toMatchObject({
            code: "REPLAY_DETECTED",
            status: 409,
        });
    });

    it("rejects an incorrect nonce", async () => {
        const request = await createRequest();

        await expect(
            reserveRequest(request, "incorrect-nonce")
        ).rejects.toMatchObject({
            code: "INVALID_SIGNING_NONCE",
            status: 403,
        });

        expect(repository.findById(request.request_id).status).toBe("pending");
    });

    it("rejects an expired signing request", async () => {
        const request = await createRequest();
        now = new Date(now.getTime() + 301_000);

        await expect(reserveRequest(request)).rejects.toMatchObject({
            code: "SIGNING_REQUEST_EXPIRED",
            status: 410,
        });

        expect(repository.findById(request.request_id).status).toBe("expired");
    });

    it("rejects signing when the PDF changed after request creation", async () => {
        const request = await createRequest();
        fs.appendFileSync(documentPath, "\nATTACKER MODIFICATION", "utf8");

        await expect(reserveRequest(request)).rejects.toMatchObject({
            code: "DOCUMENT_HASH_CHANGED",
            status: 409,
        });

        expect(repository.findById(request.request_id).status)
            .toBe("invalidated");
    });
});
