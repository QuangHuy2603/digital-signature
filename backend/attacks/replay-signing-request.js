import "dotenv/config";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
    createMemorySigningRequestRepository,
} from "../src/services/signing-request.repository.js";
import {
    createSigningRequestManager,
} from "../src/services/signing-request.service.js";

const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "nt219-replay-attack-")
);
const documentPath = path.join(temporaryDirectory, "original.pdf");
const documentId = "HS-ATTACK-REPLAY-001";
const officerId = "demo-officer";

fs.writeFileSync(
    documentPath,
    "%PDF-1.7\nREMOTE SIGNING REPLAY DEMO\n%%EOF",
    "utf8"
);

const repository = createMemorySigningRequestRepository();
const manager = createSigningRequestManager({
    repository,
    findDocumentByIdFn: async () => ({
        document_id: documentId,
        status: "submitted",
        file_path: documentPath,
    }),
    auditFn: async () => null,
});

let firstRequestAccepted = false;
let replayRejected = false;
let replayReason = "NO_ERROR";

try {
    const signingRequest = await manager.create({
        documentId,
        officerId,
    });

    await manager.reserve({
        requestId: signingRequest.request_id,
        nonce: signingRequest.nonce,
        documentId,
        officerId,
    });

    await manager.complete({
        requestId: signingRequest.request_id,
        documentId,
        officerId,
    });

    firstRequestAccepted = true;

    try {
        await manager.reserve({
            requestId: signingRequest.request_id,
            nonce: signingRequest.nonce,
            documentId,
            officerId,
        });
    } catch (error) {
        replayReason = error.code || error.message;
        replayRejected = error.code === "REPLAY_DETECTED";
    }
} finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
}

const passed = firstRequestAccepted && replayRejected;

console.log("\n=== ATTACK 6 - REPLAY SIGNING REQUEST ===");
console.log("First request:", firstRequestAccepted ? "ACCEPTED" : "REJECTED");
console.log("Replayed request:", replayRejected ? "REJECTED" : "ACCEPTED");
console.log("Reason:", replayReason);
console.log("Expected reason: REPLAY_DETECTED");
console.log("Test result:", passed ? "PASS" : "FAIL");

if (!passed) {
    process.exitCode = 1;
}
