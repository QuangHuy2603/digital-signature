import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PDFDocument } from "pdf-lib";
import {
    executeClientAgentSigningJob,
    getClientAgentStatus,
    listClientAgentCertificates,
} from "../../../client-agent/src/agent-core.js";
import {
    createClientAgentSignature,
    verifyClientAgentAuthentication,
} from "../../../client-agent/src/security.js";

const tempFiles = [];
let pdfBuffer;

beforeAll(async () => {
    const pdf = await PDFDocument.create();
    const page = pdf.addPage([420, 260]);
    page.drawText("NT219 Local Client Agent local Client Agent software signing test", { x: 30, y: 180, size: 12 });
    pdfBuffer = Buffer.from(await pdf.save({ useObjectStreams: false }));
});

afterAll(() => {
    for (const file of tempFiles) fs.rmSync(file, { force: true });
});

describe("Local Client Agent local software Client Agent", () => {
    it("reports a ready localhost software provider and active certificate", () => {
        const status = getClientAgentStatus();
        const certificates = listClientAgentCertificates();
        expect(status.ready).toBe(true);
        expect(status.providers?.software).toBe(true);
        expect(["software", "hybrid"]).toContain(status.provider);
        if (status.providers?.pkcs11) {
            expect(status.provider).toBe("hybrid");
        } else {
            expect(status.provider).toBe("software");
        }
        expect(certificates.some((item) => item.certificate_id === "CERT-OFFICER-001-V1")).toBe(true);
    });

    it("authenticates a portal request and blocks replayed nonces", () => {
        const rawBody = JSON.stringify({ request_id: "client-agent-local-auth" });
        const timestamp = String(Date.now());
        const nonce = "client-agent-local-nonce";
        const secret = "client-agent-local-test-secret";
        const signature = createClientAgentSignature({ timestamp, nonce, rawBody, secret });
        const headers = {
            "x-client-agent-client-id": "portal-api",
            "x-client-agent-timestamp": timestamp,
            "x-client-agent-nonce": nonce,
            "x-client-agent-signature": signature,
        };
        const first = verifyClientAgentAuthentication({ headers, rawBody, secret, usedNonces: [] });
        expect(first.ok).toBe(true);
        const replay = verifyClientAgentAuthentication({
            headers,
            rawBody,
            secret,
            usedNonces: [{ nonce, used_at_ms: Date.now() }],
        });
        expect(replay.ok).toBe(false);
        expect(replay.code).toBe("CLIENT_AGENT_REPLAY_DETECTED");
    });

    it("creates a valid PAdES-B-T document using the local software certificate", async () => {
        const digest = crypto.createHash("sha256").update(pdfBuffer).digest("hex").toUpperCase();
        const result = await executeClientAgentSigningJob({
            request_id: crypto.randomUUID(),
            document_id: "HS-CLIENT_AGENT_LOCAL-LOCAL",
            officer_id: "OFFICER-001",
            certificate_id: "CERT-OFFICER-001-V1",
            signer: { officer_id: "OFFICER-001", full_name: "Can bo Nguyen", email: "officer@test.com" },
            input_pdf_base64: pdfBuffer.toString("base64"),
            document_digest_sha256: digest,
        });
        expect(result.status).toBe("signed");
        expect(result.signing_method).toBe("local");
        expect(result.provider).toBe("software");
        expect(result.pades.verification.valid).toBe(true);
        expect(result.pades.verification.baseline_level).toBe("PAdES-B-T");
    }, 120000);

    it("rejects changed PDF bytes and cross-officer certificate use", async () => {
        await expect(executeClientAgentSigningJob({
            request_id: crypto.randomUUID(),
            document_id: "HS-CLIENT_AGENT_LOCAL-DIGEST",
            officer_id: "OFFICER-001",
            certificate_id: "CERT-OFFICER-001-V1",
            input_pdf_base64: pdfBuffer.toString("base64"),
            document_digest_sha256: "00".repeat(32),
        })).rejects.toMatchObject({ code: "CLIENT_AGENT_DOCUMENT_DIGEST_MISMATCH" });

        await expect(executeClientAgentSigningJob({
            request_id: crypto.randomUUID(),
            document_id: "HS-CLIENT_AGENT_LOCAL-OWNER",
            officer_id: "OFFICER-999",
            certificate_id: "CERT-OFFICER-001-V1",
            input_pdf_base64: pdfBuffer.toString("base64"),
        })).rejects.toMatchObject({ code: "CLIENT_AGENT_CERTIFICATE_OFFICER_MISMATCH" });
    });
});
