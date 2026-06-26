import crypto from "node:crypto";
import { PDFDocument } from "pdf-lib";
import { executeClientAgentSigningJob } from "../../client-agent/src/agent-core.js";
const pdf = await PDFDocument.create();
pdf.addPage([300, 200]);
const bytes = Buffer.from(await pdf.save({ useObjectStreams: false }));
let code = null;
try {
    await executeClientAgentSigningJob({
        request_id: crypto.randomUUID(),
        document_id: "HS-ATTACK-CLIENT-DIGEST",
        officer_id: "OFFICER-001",
        certificate_id: "CERT-OFFICER-001-V1",
        input_pdf_base64: bytes.toString("base64"),
        document_digest_sha256: "FF".repeat(32),
    });
} catch (error) { code = error.code; }
const passed = code === "CLIENT_AGENT_DOCUMENT_DIGEST_MISMATCH";
console.log("=== ATTACK 21 - CLIENT AGENT DIGEST SUBSTITUTION ===");
console.log(`Reason: ${code}`);
console.log(`Test result: ${passed ? "PASS" : "FAIL"}`);
process.exitCode = passed ? 0 : 1;
