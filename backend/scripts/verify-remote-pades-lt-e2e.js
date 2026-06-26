import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { PDFDocument, StandardFonts } from "pdf-lib";

process.env.SIGNING_PROVIDER = "softhsm";
process.env.TSP_MODE = "http";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(__dirname, "..");
const projectRoot = path.resolve(backendRoot, "..");
const endpoint = process.env.TSP_URL || "http://127.0.0.1:3400";

async function createPdf(target) {
    const pdf = await PDFDocument.create();
    const page = pdf.addPage([595, 842]);
    const font = await pdf.embedFont(StandardFonts.Helvetica);
    page.drawText("Digital Signature Capstone Remote SoftHSM PAdES-LT Test", { x: 55, y: 760, size: 18, font });
    page.drawText(`Generated: ${new Date().toISOString()}`, { x: 55, y: 725, size: 10, font });
    page.drawText("TSP -> SoftHSM -> PAdES-B-T -> Portal DSS/VRI -> PAdES-LT", { x: 55, y: 700, size: 10, font });
    fs.writeFileSync(target, await pdf.save({ useObjectStreams: false }));
}

async function readHealth() {
    try {
        const response = await fetch(`${endpoint}/health`, { signal: AbortSignal.timeout(1500) });
        return response.ok ? await response.json() : null;
    } catch { return null; }
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
    await import("../src/config/env.config.js");
    const { findOfficerByOfficerId } = await import("../src/services/officer-account.service.js");
    const { findCertificateById } = await import("../src/services/certificate.repository.js");
    const { signPadesViaTsp } = await import("../src/services/tsp-client.service.js");
    const { getSigningProviderStatus } = await import("../src/crypto/signing-provider.service.js");
    const { assertCertificateGoodViaOcsp } = await import("../src/crypto/ocsp.service.js");
    const { upgradePadesBtToLt } = await import("../src/crypto/pades-lt.service.js");
    const { verifyPadesPdf } = await import("../src/crypto/pades.service.js");
    const { atomicWriteJsonSync } = await import("../src/utils/atomic-file.util.js");

    const officer = findOfficerByOfficerId("OFFICER-001");
    if (!officer?.remote_certificate_id) throw new Error("Remote officer certificate is not provisioned");
    const certificateRecord = findCertificateById(officer.remote_certificate_id);
    if (!certificateRecord) throw new Error(`Certificate ${officer.remote_certificate_id} was not found`);
    const provider = getSigningProviderStatus({ certificateRecord });
    if (!provider.softhsm_provider?.ready) {
        throw new Error(`SoftHSM provider is not ready: ${JSON.stringify(provider.softhsm_provider?.runtime_key_probe)}`);
    }

    const existing = await readHealth();
    if (!existing) {
        child = spawn(process.execPath, [path.join(projectRoot, "tsp-service", "src", "server.js")], {
            cwd: backendRoot,
            env: { ...process.env, SIGNING_PROVIDER: "softhsm", TSP_MODE: "http" },
            stdio: ["ignore", "pipe", "pipe"],
            windowsHide: true,
        });
        child.stdout?.on("data", (chunk) => process.stdout.write(`[tsp] ${chunk}`));
        child.stderr?.on("data", (chunk) => process.stderr.write(`[tsp] ${chunk}`));
        const health = await waitForHealth();
        if (!health) throw new Error("TSP service did not become ready");
    } else if (existing.provider?.selected_provider !== "softhsm") {
        throw new Error(`Existing TSP uses ${existing.provider?.selected_provider || "unknown"}; stop it and rerun`);
    }

    temp = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-pades-lt-remote-"));
    const inputPdfPath = path.join(temp, "input.pdf");
    const btPdfPath = path.join(temp, "signed-bt.pdf");
    const ltPdfPath = path.join(temp, "signed-lt.pdf");
    const timestampDirectory = path.join(temp, "timestamps");
    await createPdf(inputPdfPath);
    const started = performance.now();
    const tspResult = await signPadesViaTsp({
        requestId: crypto.randomUUID(),
        documentId: `PADES_LT-REMOTE-${Date.now()}`,
        inputPdfPath,
        outputPdfPath: btPdfPath,
        evidenceDirectory: timestampDirectory,
        certificateRecord,
        signer: officer,
        issuedAt: new Date().toISOString(),
    });
    const ocsp = assertCertificateGoodViaOcsp(certificateRecord).ocsp;
    const ltEvidence = await upgradePadesBtToLt({
        inputPdfPath: btPdfPath,
        outputPdfPath: ltPdfPath,
        certificateRecord,
        ocspEvidence: ocsp,
    });
    const verification = verifyPadesPdf({
        pdfPath: ltPdfPath,
        expectedFingerprint: certificateRecord.fingerprint_sha256,
    });
    const durationMs = Number((performance.now() - started).toFixed(3));
    if (tspResult.key_provider !== "softhsm" || tspResult.key_exportable !== false) {
        throw new Error("Remote key was not used as non-exportable SoftHSM key");
    }
    if (!verification.valid || verification.baseline_level !== "PAdES-LT") {
        throw new Error(`PAdES-LT verification failed: ${verification.reason}`);
    }

    const evidenceRoot = path.join(projectRoot, "evidence", "pades-lt-remote");
    fs.rmSync(evidenceRoot, { recursive: true, force: true });
    fs.mkdirSync(evidenceRoot, { recursive: true });
    fs.copyFileSync(inputPdfPath, path.join(evidenceRoot, "input.pdf"));
    fs.copyFileSync(btPdfPath, path.join(evidenceRoot, "signed-pades-bt.pdf"));
    fs.copyFileSync(ltPdfPath, path.join(evidenceRoot, "signed-pades-lt.pdf"));
    const report = {
        test: "REMOTE_SOFTHSM_PADES_LT_END_TO_END",
        result: "PASS",
        generated_at: new Date().toISOString(),
        duration_ms: durationMs,
        flow: ["TSP HMAC", "PKCS#11", "SoftHSM", "PAdES-B-T", "Portal DSS/VRI", "PAdES-LT"],
        certificate_id: certificateRecord.certificate_id,
        key_provider: tspResult.key_provider,
        key_exportable: tspResult.key_exportable,
        pades_level: verification.baseline_level,
        pades_reason: verification.reason,
        dss_present: verification.dss_present,
        vri_present: verification.vri_present,
        offline_verification_ready: verification.offline_verification_ready,
        embedded_certificate_count: ltEvidence.embedded_certificate_count,
        embedded_ocsp_count: ltEvidence.embedded_ocsp_count,
        embedded_crl_count: ltEvidence.embedded_crl_count,
        evidence_directory: "evidence/pades-lt-remote",
        otp_note: "Remote OTP separately proves OTP authorization before the same remote TSP signing path.",
    };
    atomicWriteJsonSync(path.join(evidenceRoot, "result.json"), report, { backup: false });
    console.log(JSON.stringify(report, null, 2));
} catch (error) {
    console.error(JSON.stringify({
        test: "REMOTE_SOFTHSM_PADES_LT_END_TO_END",
        result: "FAIL",
        error: error.message,
    }, null, 2));
    process.exitCode = 2;
} finally {
    if (child && !child.killed) child.kill();
    if (temp) fs.rmSync(temp, { recursive: true, force: true });
}
