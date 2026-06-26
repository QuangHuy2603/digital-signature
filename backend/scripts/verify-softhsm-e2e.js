import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { PDFDocument, StandardFonts } from "pdf-lib";
import "../src/config/env.config.js";
import { parseCliArgs } from "./cli-args.js";
import { findOfficerByOfficerId, normalizeOfficerId } from "../src/services/officer-account.service.js";
import { findCertificateById } from "../src/services/certificate.repository.js";
import { signPadesViaTsp } from "../src/services/tsp-client.service.js";
import { verifyPadesPdf } from "../src/crypto/pades.service.js";
import { getSigningProviderStatus } from "../src/crypto/signing-provider.service.js";
import { atomicWriteJsonSync } from "../src/utils/atomic-file.util.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(__dirname, "..");
const projectRoot = path.resolve(backendRoot, "..");
const args = parseCliArgs();
const officerId = normalizeOfficerId(args["officer-id"] || "OFFICER-001");
const endpoint = process.env.TSP_URL || "http://127.0.0.1:3400";

async function createPdf(target) {
    const pdf = await PDFDocument.create();
    const page = pdf.addPage([595, 842]);
    const font = await pdf.embedFont(StandardFonts.Helvetica);
    page.drawText("NT219 SoftHSM End-to-End Remote Signing Test", { x: 60, y: 760, size: 18, font });
    page.drawText(`Officer: ${officerId}`, { x: 60, y: 720, size: 12, font });
    page.drawText(`Generated: ${new Date().toISOString()}`, { x: 60, y: 700, size: 10, font });
    page.drawText("Expected flow: Portal API -> TSP -> PKCS#11 -> SoftHSM -> PAdES-B-T", { x: 60, y: 670, size: 10, font });
    fs.writeFileSync(target, await pdf.save({ useObjectStreams: false }));
}

async function readHealth() {
    try {
        const response = await fetch(`${endpoint}/health`, { signal: AbortSignal.timeout(1500) });
        if (!response.ok) return null;
        return await response.json();
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
    const officer = findOfficerByOfficerId(officerId);
    if (!officer) throw new Error(`Officer ${officerId} was not found`);
    if (!officer.remote_certificate_id) {
        throw new Error(`Officer ${officerId} has no remote_certificate_id. Run npm run softhsm:provision first.`);
    }
    const certificateRecord = findCertificateById(officer.remote_certificate_id);
    if (!certificateRecord) throw new Error(`Remote certificate ${officer.remote_certificate_id} was not found`);
    if (certificateRecord.key_provider !== "softhsm") {
        throw new Error(`Remote certificate is not bound to SoftHSM (provider=${certificateRecord.key_provider || "missing"})`);
    }
    if (certificateRecord.private_key_path) {
        throw new Error("SoftHSM remote certificate unexpectedly references a private key file");
    }

    const providerStatus = getSigningProviderStatus({ certificateRecord });
    if (!providerStatus.softhsm_provider.ready) {
        throw new Error(`SoftHSM provider is not ready: ${JSON.stringify(providerStatus.softhsm_provider.runtime_key_probe)}`);
    }

    const existingHealth = await readHealth();
    if (existingHealth) {
        if (existingHealth.provider?.selected_provider !== "softhsm") {
            throw new Error(
                `A TSP service is already running at ${endpoint} with provider=${existingHealth.provider?.selected_provider || "unknown"}. ` +
                "Stop it and rerun the SoftHSM remote signing E2E check."
            );
        }
    } else {
        child = spawn(process.execPath, [path.join(projectRoot, "tsp-service", "src", "server.js")], {
            cwd: backendRoot,
            env: {
                ...process.env,
                SIGNING_PROVIDER: "softhsm",
                TSP_MODE: "http",
            },
            stdio: ["ignore", "pipe", "pipe"],
            windowsHide: true,
        });
        child.stdout?.on("data", (chunk) => process.stdout.write(`[tsp] ${chunk}`));
        child.stderr?.on("data", (chunk) => process.stderr.write(`[tsp] ${chunk}`));
        const startedHealth = await waitForHealth();
        if (!startedHealth) throw new Error("TSP service did not become ready");
        if (startedHealth.provider?.selected_provider !== "softhsm") {
            throw new Error(`Spawned TSP selected unexpected provider: ${startedHealth.provider?.selected_provider || "unknown"}`);
        }
    }

    temp = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-softhsm-e2e-"));
    const inputPdfPath = path.join(temp, "input.pdf");
    const outputPdfPath = path.join(temp, "signed.pdf");
    const evidenceDirectory = path.join(temp, "timestamps");
    await createPdf(inputPdfPath);

    const requestId = crypto.randomUUID();
    const started = performance.now();
    const result = await signPadesViaTsp({
        requestId,
        documentId: `SOFTHSM-E2E-${Date.now()}`,
        inputPdfPath,
        outputPdfPath,
        evidenceDirectory,
        certificateRecord,
        signer: officer,
        issuedAt: new Date().toISOString(),
    });
    const durationMs = Number((performance.now() - started).toFixed(3));
    const verification = verifyPadesPdf({
        pdfPath: outputPdfPath,
        expectedFingerprint: certificateRecord.fingerprint_sha256,
    });

    if (result.key_provider !== "softhsm") throw new Error(`Unexpected key provider: ${result.key_provider}`);
    if (result.key_exportable !== false) throw new Error("SoftHSM key was not reported as non-exportable");
    if (!verification.valid) throw new Error(`PAdES verification failed: ${verification.reason}`);
    if (result.pades?.baseline_level !== "PAdES-B-T") throw new Error(`Unexpected PAdES level: ${result.pades?.baseline_level}`);

    const evidenceRoot = path.join(projectRoot, "evidence", "softhsm-e2e");
    fs.rmSync(evidenceRoot, { recursive: true, force: true });
    fs.mkdirSync(evidenceRoot, { recursive: true });
    fs.copyFileSync(inputPdfPath, path.join(evidenceRoot, "input.pdf"));
    fs.copyFileSync(outputPdfPath, path.join(evidenceRoot, "signed-pades-bt.pdf"));
    for (const file of fs.readdirSync(evidenceDirectory)) {
        fs.copyFileSync(path.join(evidenceDirectory, file), path.join(evidenceRoot, file));
    }

    const report = {
        test: "SOFTHSM_REMOTE_PADES_BT_END_TO_END",
        result: "PASS",
        generated_at: new Date().toISOString(),
        duration_ms: durationMs,
        request_id: requestId,
        officer_id: officerId,
        certificate_id: certificateRecord.certificate_id,
        flow: ["Portal API client", "Authenticated TSP HTTP", "OpenSSL PKCS#11 provider", "SoftHSM", "CMS/CAdES", "RFC3161 TSA", "PAdES-B-T"],
        key_provider: result.key_provider,
        key_reference: result.key_reference,
        key_exportable: result.key_exportable,
        private_key_file_referenced: Boolean(certificateRecord.private_key_path),
        pades_level: result.pades.baseline_level,
        pades_valid: verification.valid,
        pades_reason: verification.reason,
        cms_signature_valid: verification.cms_signature_valid,
        timestamp_valid: verification.timestamp_valid,
        signed_pdf_sha256: result.signed_pdf_sha256,
        evidence_directory: "evidence/softhsm-e2e",
    };
    atomicWriteJsonSync(path.join(evidenceRoot, "result.json"), report, { backup: false });
    console.log(JSON.stringify(report, null, 2));
} catch (error) {
    console.error(JSON.stringify({
        test: "SOFTHSM_REMOTE_PADES_BT_END_TO_END",
        result: "FAIL",
        error: error.message,
    }, null, 2));
    process.exitCode = 2;
} finally {
    if (child && !child.killed) child.kill();
    if (temp) fs.rmSync(temp, { recursive: true, force: true });
}
