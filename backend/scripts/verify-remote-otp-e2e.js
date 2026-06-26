import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { PDFDocument, StandardFonts } from "pdf-lib";
import "../src/config/env.config.js";
import { hashFile } from "../src/crypto/hash.service.js";
import { verifyPadesPdf } from "../src/crypto/pades.service.js";
import { getSigningProviderStatus } from "../src/crypto/signing-provider.service.js";
import { findOfficerByOfficerId } from "../src/services/officer-account.service.js";
import { findCertificateById } from "../src/services/certificate.repository.js";
import { signPadesViaTsp } from "../src/services/tsp-client.service.js";
import { createMemoryRemoteSigningAuthorizationRepository } from "../src/services/remote-signing-authorization.repository.js";
import { createRemoteSigningAuthorizationManager } from "../src/services/remote-signing-authorization.service.js";
import { atomicWriteJsonSync } from "../src/utils/atomic-file.util.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(__dirname, "..");
const projectRoot = path.resolve(backendRoot, "..");
const endpoint = process.env.TSP_URL || "http://127.0.0.1:3400";

async function createPdf(target) {
    const pdf = await PDFDocument.create();
    const page = pdf.addPage([595, 842]);
    const font = await pdf.embedFont(StandardFonts.Helvetica);
    page.drawText("Remote Signing OTP End-to-End Test", { x: 55, y: 760, size: 18, font });
    page.drawText(`Generated: ${new Date().toISOString()}`, { x: 55, y: 725, size: 10, font });
    page.drawText("OTP -> one-time authorization -> TSP -> SoftHSM -> PAdES-B-T", { x: 55, y: 695, size: 10, font });
    fs.writeFileSync(target, await pdf.save({ useObjectStreams: false }));
}

async function readHealth() {
    try {
        const response = await fetch(`${endpoint}/health`, { signal: AbortSignal.timeout(1500) });
        if (!response.ok) return null;
        return response.json();
    } catch {
        return null;
    }
}

async function waitForHealth(timeoutMs = 15000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const health = await readHealth();
        if (health) return health;
        await new Promise((resolve) => setTimeout(resolve, 300));
    }
    return null;
}

let child = null;
let temp = null;
try {
    process.env.SIGNING_PROVIDER = "softhsm";
    process.env.TSP_MODE = "http";
    const officer = findOfficerByOfficerId("OFFICER-001");
    if (!officer?.remote_certificate_id) throw new Error("OFFICER-001 remote certificate is not configured");
    const certificateRecord = findCertificateById(officer.remote_certificate_id);
    if (!certificateRecord) throw new Error(`Certificate ${officer.remote_certificate_id} was not found`);
    if (certificateRecord.key_provider !== "softhsm") throw new Error("Remote certificate is not bound to SoftHSM");
    const providerStatus = getSigningProviderStatus({ certificateRecord });
    if (!providerStatus.softhsm_provider.ready) {
        throw new Error(`SoftHSM provider is not ready: ${JSON.stringify(providerStatus.softhsm_provider.runtime_key_probe)}`);
    }

    const existingHealth = await readHealth();
    if (!existingHealth) {
        child = spawn(process.execPath, [path.join(projectRoot, "tsp-service", "src", "server.js")], {
            cwd: backendRoot,
            env: { ...process.env, SIGNING_PROVIDER: "softhsm", TSP_MODE: "http" },
            stdio: ["ignore", "pipe", "pipe"],
            windowsHide: true,
        });
        child.stdout?.on("data", (chunk) => process.stdout.write(`[tsp] ${chunk}`));
        child.stderr?.on("data", (chunk) => process.stderr.write(`[tsp] ${chunk}`));
        if (!await waitForHealth()) throw new Error("TSP service did not become ready");
    } else if (existingHealth.provider?.selected_provider !== "softhsm") {
        throw new Error("The running TSP is not using the SoftHSM provider");
    }

    temp = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-remote-otp-e2e-"));
    const inputPdfPath = path.join(temp, "input.pdf");
    const outputPdfPath = path.join(temp, "signed.pdf");
    const evidenceDirectory = path.join(temp, "timestamps");
    await createPdf(inputPdfPath);
    const documentId = `REMOTE_OTP-OTP-E2E-${Date.now()}`;
    const officerUserId = String(officer.id);
    const digest = await hashFile(inputPdfPath);
    const signingRequest = {
        request_id: crypto.randomUUID(),
        nonce: crypto.randomBytes(32).toString("base64url"),
        document_id: documentId,
        document_hash: digest,
        signing_method: "remote",
    };
    const authorizationManager = createRemoteSigningAuthorizationManager({
        repository: createMemoryRemoteSigningAuthorizationRepository(),
        findDocumentByIdFn: async (id) => id === documentId ? {
            document_id: documentId,
            status: "submitted",
            file_path: inputPdfPath,
        } : null,
        hashFileFn: hashFile,
        auditFn: async () => null,
        exposeDemoOtp: true,
    });

    const challenge = await authorizationManager.create({
        signingRequest,
        documentId,
        officerId: officerUserId,
        certificateId: certificateRecord.certificate_id,
    });
    const verified = await authorizationManager.verify({
        authorizationId: challenge.authorization_id,
        otp: challenge.demo_otp,
        documentId,
        officerId: officerUserId,
    });
    const reserved = await authorizationManager.reserve({
        authorizationId: verified.authorization_id,
        authorizationToken: verified.authorization_token,
        requestId: signingRequest.request_id,
        nonce: signingRequest.nonce,
        documentId,
        officerId: officerUserId,
        certificateId: certificateRecord.certificate_id,
    });

    const started = performance.now();
    const signingResult = await signPadesViaTsp({
        requestId: signingRequest.request_id,
        documentId,
        inputPdfPath,
        outputPdfPath,
        evidenceDirectory,
        certificateRecord,
        signer: officer,
        issuedAt: new Date().toISOString(),
    });
    const completed = await authorizationManager.complete({
        authorizationId: reserved.authorization_id,
        documentId,
        officerId: officerUserId,
    });
    const verification = verifyPadesPdf({
        pdfPath: outputPdfPath,
        expectedFingerprint: certificateRecord.fingerprint_sha256,
    });
    if (completed.status !== "used") throw new Error("OTP authorization was not consumed");
    if (!verification.valid) throw new Error(`PAdES verification failed: ${verification.reason}`);
    if (signingResult.key_provider !== "softhsm" || signingResult.key_exportable !== false) {
        throw new Error("Remote signing did not use a non-exportable SoftHSM key");
    }

    const evidenceRoot = path.join(projectRoot, "evidence", "remote-otp-otp-e2e");
    fs.rmSync(evidenceRoot, { recursive: true, force: true });
    fs.mkdirSync(evidenceRoot, { recursive: true });
    fs.copyFileSync(inputPdfPath, path.join(evidenceRoot, "input.pdf"));
    fs.copyFileSync(outputPdfPath, path.join(evidenceRoot, "signed-pades-bt.pdf"));
    for (const name of fs.readdirSync(evidenceDirectory)) {
        fs.copyFileSync(path.join(evidenceDirectory, name), path.join(evidenceRoot, name));
    }
    const report = {
        test: "REMOTE_OTP_SOFTHSM_PADES_BT_END_TO_END",
        result: "PASS",
        generated_at: new Date().toISOString(),
        duration_ms: Number((performance.now() - started).toFixed(3)),
        flow: [
            "Officer remote signing request",
            "6-digit OTP challenge",
            "OTP HMAC-SHA256 verification",
            "one-time authorization token",
            "authenticated TSP HTTP",
            "SoftHSM PKCS#11 non-exportable key",
            "CMS/CAdES + RFC3161",
            "PAdES-B-T",
        ],
        authorization_status: completed.status,
        otp_plaintext_stored: false,
        otp_attempts: completed.attempts,
        document_id: documentId,
        certificate_id: certificateRecord.certificate_id,
        key_provider: signingResult.key_provider,
        key_exportable: signingResult.key_exportable,
        pades_valid: verification.valid,
        timestamp_valid: verification.timestamp_valid,
        evidence_directory: "evidence/remote-otp-otp-e2e",
    };
    atomicWriteJsonSync(path.join(evidenceRoot, "result.json"), report, { backup: false });
    console.log(JSON.stringify(report, null, 2));
} catch (error) {
    console.error(JSON.stringify({
        test: "REMOTE_OTP_SOFTHSM_PADES_BT_END_TO_END",
        result: "FAIL",
        error: error.message,
    }, null, 2));
    process.exitCode = 2;
} finally {
    if (child && !child.killed) child.kill();
    if (temp) fs.rmSync(temp, { recursive: true, force: true });
}
