import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { PDFDocument, StandardFonts } from "pdf-lib";
import "../src/config/env.config.js";
import { parseCliArgs } from "./cli-args.js";
import { executeCitizenDigestSigningJob, executeClientAgentSigningJob } from "../../client-agent/src/agent-core.js";
import { buildCitizenSignaturePayload } from "../src/crypto/citizen-signature-payload.js";
import { findCertificateById, findActiveCitizenCertificate } from "../src/services/certificate.repository.js";
import { findCitizenByCitizenId } from "../src/services/auth.service.js";
import { findOfficerByOfficerId } from "../src/services/officer-account.service.js";
import { signPadesViaTsp } from "../src/services/tsp-client.service.js";
import { verifyPadesPdf } from "../src/crypto/pades.service.js";
import { upgradePadesBtToLt } from "../src/crypto/pades-lt.service.js";
import { assertCertificateGoodViaOcsp } from "../src/crypto/ocsp.service.js";
import { getSigningProviderStatus } from "../src/crypto/signing-provider.service.js";
import { createLtvArchive, getArchiveStatus } from "../src/services/archive.service.js";
import { getPkcs11CertificateStatus } from "../../client-agent/src/providers.js";
import { atomicWriteJsonSync } from "../src/utils/atomic-file.util.js";
import { rowsToCsv, summarizeBenchmarkRows } from "./benchmark-utils.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(__dirname, "..");
const projectRoot = path.resolve(backendRoot, "..");
const args = parseCliArgs();
const runs = Math.max(1, Math.min(30, Number.parseInt(args.runs || process.env.BENCHMARK_DEFAULT_RUNS || "3", 10)));
const citizenId = String(args["citizen-id"] || "CITIZEN-001");
const officerId = String(args["officer-id"] || "OFFICER-001");
const endpoint = process.env.TSP_URL || "http://127.0.0.1:3400";
const rows = [];
let tspChild = null;

function elapsed(start) { return Number((performance.now() - start).toFixed(3)); }
function addRow(row) { rows.push({ reason: "", ...row }); }
function directorySize(directory) {
    if (!directory || !fs.existsSync(directory)) return 0;
    return fs.readdirSync(directory, { withFileTypes: true }).reduce((total, entry) => {
        const full = path.join(directory, entry.name);
        return total + (entry.isDirectory() ? directorySize(full) : fs.statSync(full).size);
    }, 0);
}
function writeBase64Evidence(encoded, target) {
    if (!encoded) return null;
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, Buffer.from(encoded, "base64"));
    return target;
}
async function makePdf() {
    const pdf = await PDFDocument.create();
    const page = pdf.addPage([595, 842]);
    const font = await pdf.embedFont(StandardFonts.Helvetica);
    page.drawText("Digital Signature Signing Benchmark", { x: 50, y: 770, size: 18, font });
    page.drawText(`Generated ${new Date().toISOString()}`, { x: 50, y: 740, size: 10, font });
    return Buffer.from(await pdf.save({ useObjectStreams: false }));
}
async function health() {
    try { const response = await fetch(`${endpoint}/health`, { signal: AbortSignal.timeout(1000) }); return response.ok ? response.json() : null; } catch { return null; }
}
async function ensureTsp() {
    const existing = await health();
    if (existing) return existing;
    tspChild = spawn(process.execPath, [path.join(projectRoot, "tsp-service/src/server.js")], { cwd: backendRoot, env: { ...process.env, SIGNING_PROVIDER: "softhsm", TSP_MODE: "http" }, stdio: ["ignore", "ignore", "pipe"], windowsHide: true });
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
        const current = await health();
        if (current) return current;
        await new Promise((resolve) => setTimeout(resolve, 250));
    }
    return null;
}

const temp = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-signing-benchmark-"));
try {
    const pdfBuffer = await makePdf();
    const citizen = findCitizenByCitizenId(citizenId);
    if (!citizen) throw new Error(`Citizen ${citizenId} not found`);
    const citizenSoftware = findActiveCitizenCertificate(citizenId, "software");
    const citizenPkcs11 = findActiveCitizenCertificate(citizenId, "pkcs11");
    const officer = findOfficerByOfficerId(officerId);
    if (!officer) throw new Error(`Officer ${officerId} not found`);
    const localCertificate = findCertificateById(officer.local_certificate_id || officer.active_certificate_id);
    const remoteCertificate = findCertificateById(officer.remote_certificate_id);

    console.error(`[signing-benchmark] Benchmark started: ${runs} run(s)`);
    for (let run = 1; run <= runs; run += 1) {
        console.error(`[signing-benchmark] Local run ${run}/${runs}`);
        if (citizenSoftware) {
            const digest = crypto.createHash("sha256").update(pdfBuffer).digest("hex").toUpperCase();
            const requestId = crypto.randomUUID();
            const createdAt = new Date().toISOString();
            const canonical = buildCitizenSignaturePayload({ requestId, documentId: `BENCH-CIT-SW-${run}`, citizenId, userId: citizen.id, certificateId: citizenSoftware.certificate_id, documentDigestSha256: digest, createdAt });
            const start = performance.now();
            const result = await executeCitizenDigestSigningJob({ request_id: requestId, document_id: `BENCH-CIT-SW-${run}`, user_id: citizen.id, citizen_id: citizenId, certificate_id: citizenSoftware.certificate_id, provider: "software", created_at: createdAt, document_digest_sha256: digest, canonical_payload: canonical });
            addRow({ operation: "citizen_detached_sign", signer_type: "citizen", provider: "software", run, duration_ms: elapsed(start), input_bytes: pdfBuffer.length, output_bytes: Buffer.from(result.signature_der_base64, "base64").length, certificate_id: citizenSoftware.certificate_id, key_exportable: true, result: "PASS" });
        }

        if (citizenPkcs11) {
            const pkcs11Status = getPkcs11CertificateStatus(citizenPkcs11, projectRoot);
            if (pkcs11Status.ready) {
                const digest = crypto.createHash("sha256").update(pdfBuffer).digest("hex").toUpperCase();
                const requestId = crypto.randomUUID();
                const createdAt = new Date().toISOString();
                const canonical = buildCitizenSignaturePayload({ requestId, documentId: `BENCH-CIT-P11-${run}`, citizenId, userId: citizen.id, certificateId: citizenPkcs11.certificate_id, documentDigestSha256: digest, createdAt });
                const start = performance.now();
                const result = await executeCitizenDigestSigningJob({ request_id: requestId, document_id: `BENCH-CIT-P11-${run}`, user_id: citizen.id, citizen_id: citizenId, certificate_id: citizenPkcs11.certificate_id, provider: "pkcs11", created_at: createdAt, document_digest_sha256: digest, canonical_payload: canonical });
                addRow({ operation: "citizen_detached_sign", signer_type: "citizen", provider: "pkcs11", run, duration_ms: elapsed(start), input_bytes: pdfBuffer.length, output_bytes: Buffer.from(result.signature_der_base64, "base64").length, certificate_id: citizenPkcs11.certificate_id, key_exportable: false, result: "PASS" });
            }
        }

        if (localCertificate) {
            const start = performance.now();
            const result = await executeClientAgentSigningJob({ request_id: crypto.randomUUID(), document_id: `BENCH-OFFICER-LOCAL-${run}`, officer_id: officerId, certificate_id: localCertificate.certificate_id, signer: officer, input_pdf_base64: pdfBuffer.toString("base64"), document_digest_sha256: crypto.createHash("sha256").update(pdfBuffer).digest("hex").toUpperCase() });
            const signedBt = Buffer.from(result.signed_pdf_base64, "base64");
            const btPath = path.join(temp, `local-bt-${run}.pdf`); fs.writeFileSync(btPath, signedBt);
            const ltPath = path.join(temp, `local-lt-${run}.pdf`);
            const ocsp = assertCertificateGoodViaOcsp(localCertificate).ocsp;
            const ltEvidence = await upgradePadesBtToLt({ inputPdfPath: btPath, outputPdfPath: ltPath, certificateRecord: localCertificate, ocspEvidence: ocsp });
            const signedLt = fs.readFileSync(ltPath);
            addRow({ operation: "officer_pades_lt_sign", signer_type: "officer", provider: "client-agent-software", run, duration_ms: elapsed(start), input_bytes: pdfBuffer.length, output_bytes: signedLt.length, certificate_id: localCertificate.certificate_id, key_exportable: true, result: "PASS" });
            const originalPath = path.join(temp, `local-original-${run}.pdf`); fs.writeFileSync(originalPath, pdfBuffer);
            const verifyStart = performance.now(); const verification = verifyPadesPdf({ pdfPath: ltPath, expectedFingerprint: localCertificate.fingerprint_sha256 });
            addRow({ operation: "pades_lt_verify", signer_type: "verifier", provider: "local-pades-lt", run, duration_ms: elapsed(verifyStart), input_bytes: signedLt.length, output_bytes: 0, certificate_id: localCertificate.certificate_id, key_exportable: "", result: verification.valid && verification.baseline_level === "PAdES-LT" ? "PASS" : "FAIL", reason: verification.reason });

            const archiveStatus = getArchiveStatus();
            if (archiveStatus.ready) {
                const evidenceDirectory = path.join(temp, `local-archive-evidence-${run}`);
                const cmsBbPath = writeBase64Evidence(result.evidence_files?.pades_bb_cms_der_base64, path.join(evidenceDirectory, "pades-bb.cms.der"));
                const cmsBtPath = writeBase64Evidence(result.evidence_files?.pades_bt_cms_der_base64, path.join(evidenceDirectory, "pades-bt.cms.der"));
                const tsqPath = writeBase64Evidence(result.evidence_files?.timestamp_query_base64, path.join(evidenceDirectory, "timestamp.tsq"));
                const tsrPath = writeBase64Evidence(result.evidence_files?.timestamp_response_base64, path.join(evidenceDirectory, "timestamp.tsr"));
                const archiveStart = performance.now();
                const archive = createLtvArchive({
                    documentId: `BENCH-ARCHIVE-${run}-${crypto.randomUUID().slice(0, 8)}`,
                    originalPdfPath: originalPath,
                    signedPdfPath: ltPath,
                    metadata: { pades_level: "PAdES-LT", key_provider: "client-agent-software", tsp_mode: "local", benchmark: true },
                    certificateRecord: localCertificate,
                    ocspEvidence: ocsp,
                    padesEvidence: { cms_bb_der_path: cmsBbPath, cms_der_path: cmsBtPath, lt_evidence: ltEvidence, verification },
                    timestampEvidence: { request_path: tsqPath, response_path: tsrPath },
                });
                const archiveBytes = directorySize(archive.archive_path);
                addRow({ operation: "pades_lt_archive_create", signer_type: "archive", provider: "external-sealed-evidence", run, duration_ms: elapsed(archiveStart), input_bytes: signedLt.length, output_bytes: archiveBytes, certificate_id: localCertificate.certificate_id, key_exportable: "", result: archive.valid ? "PASS" : "FAIL", reason: archive.verification?.reason || "" });
                fs.rmSync(archive.archive_path, { recursive: true, force: true });
            }
        }
    }

    if (remoteCertificate) {
        const providerStatus = getSigningProviderStatus({ certificateRecord: remoteCertificate });
        if (providerStatus.softhsm_provider.ready) {
            const tspHealth = await ensureTsp();
            if (tspHealth?.provider?.selected_provider === "softhsm") {
                for (let run = 1; run <= runs; run += 1) {
                    console.error(`[signing-benchmark] Remote SoftHSM run ${run}/${runs}`);
                    const inputPath = path.join(temp, `remote-input-${run}.pdf`);
                    const btPath = path.join(temp, `remote-bt-${run}.pdf`);
                    const ltPath = path.join(temp, `remote-lt-${run}.pdf`);
                    const evidence = path.join(temp, `remote-evidence-${run}`);
                    fs.writeFileSync(inputPath, pdfBuffer);
                    const start = performance.now();
                    const result = await signPadesViaTsp({ requestId: crypto.randomUUID(), documentId: `BENCH-OFFICER-REMOTE-${run}`, inputPdfPath: inputPath, outputPdfPath: btPath, evidenceDirectory: evidence, certificateRecord: remoteCertificate, signer: officer, issuedAt: new Date().toISOString() });
                    const ocsp = assertCertificateGoodViaOcsp(remoteCertificate).ocsp;
                    await upgradePadesBtToLt({ inputPdfPath: btPath, outputPdfPath: ltPath, certificateRecord: remoteCertificate, ocspEvidence: ocsp });
                    const ltSize = fs.statSync(ltPath).size;
                    addRow({ operation: "officer_pades_lt_sign", signer_type: "officer", provider: "tsp-softhsm", run, duration_ms: elapsed(start), input_bytes: pdfBuffer.length, output_bytes: ltSize, certificate_id: remoteCertificate.certificate_id, key_exportable: result.key_exportable, result: "PASS" });
                    const verifyStart = performance.now(); const verification = verifyPadesPdf({ pdfPath: ltPath, expectedFingerprint: remoteCertificate.fingerprint_sha256 });
                    addRow({ operation: "pades_lt_verify", signer_type: "verifier", provider: "remote-softhsm-pades-lt", run, duration_ms: elapsed(verifyStart), input_bytes: ltSize, output_bytes: 0, certificate_id: remoteCertificate.certificate_id, key_exportable: "", result: verification.valid && verification.baseline_level === "PAdES-LT" ? "PASS" : "FAIL", reason: verification.reason });
                }
            }
        }
    }

    const resultsDirectory = path.join(projectRoot, "results");
    fs.mkdirSync(resultsDirectory, { recursive: true });
    const report = {
        version: "1.0.0",
        generated_at: new Date().toISOString(),
        requested_runs: runs,
        environment: { node: process.version, platform: process.platform, arch: process.arch },
        summary: summarizeBenchmarkRows(rows),
        rows,
        skipped: {
            citizen_pkcs11: citizenPkcs11 ? !getPkcs11CertificateStatus(citizenPkcs11, projectRoot).ready : true,
            officer_remote_softhsm: remoteCertificate ? !getSigningProviderStatus({ certificateRecord: remoteCertificate }).softhsm_provider.ready : true,
        },
    };
    fs.writeFileSync(path.join(resultsDirectory, "benchmark-signing.csv"), rowsToCsv(rows), "utf8");
    atomicWriteJsonSync(path.join(resultsDirectory, "benchmark-signing-summary.json"), report, { backup: false });
    console.log(JSON.stringify(report, null, 2));
    if (!rows.length || rows.some((row) => row.result !== "PASS")) process.exitCode = 2;
} catch (error) {
    console.error(JSON.stringify({ version: "1.0.0", result: "FAIL", error: error.message }, null, 2));
    process.exitCode = 2;
} finally {
    if (tspChild && !tspChild.killed) tspChild.kill();
    fs.rmSync(temp, { recursive: true, force: true });
}
