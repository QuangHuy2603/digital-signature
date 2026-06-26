import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { PDFDocument, StandardFonts } from "pdf-lib";
import "../src/config/env.config.js";
import { parseCliArgs } from "./cli-args.js";
import { findCitizenByCitizenId } from "../src/services/auth.service.js";
import { findActiveCitizenCertificate } from "../src/services/certificate.repository.js";
import { createCitizenSigningManager } from "../src/services/citizen-signing.service.js";
import { loadCitizenSigningIdentity } from "../src/crypto/citizen-signature.service.js";
import { requestCitizenDigestSignature } from "../src/services/citizen-client-agent.service.js";
import { hashFile } from "../src/crypto/hash.service.js";
import { atomicWriteJsonSync } from "../src/utils/atomic-file.util.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(__dirname, "..");
const projectRoot = path.resolve(backendRoot, "..");
const args = parseCliArgs();
const citizenId = String(args["citizen-id"] || "CITIZEN-001");
const provider = String(args.provider || "software").toLowerCase();
const endpoint = process.env.CLIENT_AGENT_URL || "http://127.0.0.1:3500";
let child = null;
let temp = null;

async function health() {
    try {
        const response = await fetch(`${endpoint}/health`, { signal: AbortSignal.timeout(1500) });
        return response.ok ? response.json() : null;
    } catch { return null; }
}
async function ensureAgent() {
    const existing = await health();
    if (existing) return existing;
    child = spawn(process.execPath, [path.join(projectRoot, "client-agent", "src", "server.js")], {
        cwd: backendRoot,
        env: process.env,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
    });
    child.stdout?.on("data", (chunk) => process.stdout.write(`[client-agent] ${chunk}`));
    child.stderr?.on("data", (chunk) => process.stderr.write(`[client-agent] ${chunk}`));
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
        const current = await health();
        if (current) return current;
        await new Promise((resolve) => setTimeout(resolve, 250));
    }
    return null;
}
async function createPdf(target) {
    const pdf = await PDFDocument.create();
    const page = pdf.addPage([595, 842]);
    const font = await pdf.embedFont(StandardFonts.Helvetica);
    page.drawText("NT219 Citizen Signing End-to-End Test", { x: 50, y: 770, size: 18, font });
    page.drawText(`Citizen: ${citizenId}`, { x: 50, y: 740, size: 12, font });
    page.drawText(`Provider: ${provider}`, { x: 50, y: 720, size: 12, font });
    fs.writeFileSync(target, await pdf.save({ useObjectStreams: false }));
}

try {
    if (!new Set(["software", "pkcs11"]).has(provider)) throw new Error("--provider must be software or pkcs11");
    const citizen = findCitizenByCitizenId(citizenId);
    if (!citizen) throw new Error(`Citizen ${citizenId} was not found`);
    const certificate = findActiveCitizenCertificate(citizenId, provider);
    if (!certificate) throw new Error(`No active ${provider} citizen certificate. Run the corresponding provisioning command first.`);
    const agentHealth = await ensureAgent();
    if (!agentHealth?.ready) throw new Error("Client Agent did not become ready");

    temp = fs.mkdtempSync(path.join(os.tmpdir(), `nt219-citizen-${provider}-e2e-`));
    const pdfPath = path.join(temp, "citizen-document.pdf");
    await createPdf(pdfPath);
    let document = {
        document_id: `CITIZEN-E2E-${provider.toUpperCase()}-${Date.now()}`,
        owner_id: citizen.id,
        file_path: pdfPath,
        original_file_hash: await hashFile(pdfPath),
        status: "awaiting_citizen_signature",
        created_at: new Date().toISOString(),
    };
    const requests = new Map();
    const manager = createCitizenSigningManager({
        findDocumentFn: async (id) => id === document.document_id ? document : null,
        updateDocumentFn: async (_id, patch) => (document = { ...document, ...patch }),
        identityLoader: loadCitizenSigningIdentity,
        agentSigner: requestCitizenDigestSignature,
        auditFn: async () => {},
        createRecord: (record) => { requests.set(record.request_id, record); return record; },
        findRequest: (id) => requests.get(id) || null,
        updateRequest: (id, patch) => { const updated = { ...requests.get(id), ...patch }; requests.set(id, updated); return updated; },
    });
    const started = performance.now();
    const created = await manager.create({ documentId: document.document_id, userId: citizen.id, certificateId: certificate.certificate_id, provider });
    const result = await manager.sign({ documentId: document.document_id, userId: citizen.id, requestId: created.request_id, nonce: created.nonce });
    const durationMs = Number((performance.now() - started).toFixed(3));
    if (result.status !== "submitted" || !result.signature_valid || document.citizen_signature_valid !== true) {
        throw new Error("Citizen signing flow did not reach submitted with a valid signature");
    }
    if (provider === "pkcs11" && (result.key_exportable !== false || !String(document.citizen_signature.key_reference).startsWith("pkcs11:"))) {
        throw new Error("Citizen PKCS#11 result did not report a non-exportable token key");
    }
    const evidenceDir = path.join(projectRoot, "evidence", `citizen-${provider}-e2e`);
    fs.rmSync(evidenceDir, { recursive: true, force: true });
    fs.mkdirSync(evidenceDir, { recursive: true });
    fs.copyFileSync(pdfPath, path.join(evidenceDir, "citizen-document.pdf"));
    const report = {
        test: `CITIZEN_${provider.toUpperCase()}_CLIENT_AGENT_END_TO_END`,
        result: "PASS",
        generated_at: new Date().toISOString(),
        duration_ms: durationMs,
        flow: ["Citizen Portal service", "one-time request + nonce", "Client Agent HTTP/HMAC", provider === "pkcs11" ? "PKCS#11 SoftHSM/token" : "software key (lab)", "ECDSA detached signature", "Portal certificate/OCSP/signature verification", "submitted for officer review"],
        document_id: document.document_id,
        citizen_id: citizenId,
        user_id: citizen.id,
        certificate_id: certificate.certificate_id,
        provider,
        key_reference: document.citizen_signature.key_reference,
        key_exportable: document.citizen_signature.key_exportable,
        document_digest_sha256: document.citizen_document_digest_sha256,
        signature_valid: document.citizen_signature_valid,
        certificate_status_at_signing: document.citizen_signature.certificate_status_at_signing,
        revocation_source: document.citizen_signature.revocation_source,
        final_document_status: document.status,
        client_agent_version: document.citizen_signature.client_agent_version,
    };
    atomicWriteJsonSync(path.join(evidenceDir, "result.json"), report, { backup: false });
    console.log(JSON.stringify(report, null, 2));
} catch (error) {
    console.error(JSON.stringify({ test: `CITIZEN_${provider.toUpperCase()}_CLIENT_AGENT_END_TO_END`, result: "FAIL", error: error.message }, null, 2));
    process.exitCode = 2;
} finally {
    if (child && !child.killed) child.kill();
    if (temp) fs.rmSync(temp, { recursive: true, force: true });
}
