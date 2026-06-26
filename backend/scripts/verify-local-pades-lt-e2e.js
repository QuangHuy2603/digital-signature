import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

process.env.SIGNING_PROVIDER = "file";
process.env.SOFTHSM_RUNTIME_PROBE = "false";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(__dirname, "..");
const projectRoot = path.resolve(backendRoot, "..");

let fixture;
try {
    const { createPadesLtFixture } = await import("../tests/helpers/pades-fixture.js");
    const { atomicWriteJsonSync } = await import("../src/utils/atomic-file.util.js");
    fixture = await createPadesLtFixture({
        text: "Local Client Agent PAdES-LT flow",
    });
    const verification = fixture.verification;
    if (!verification.valid || verification.reason !== "VALID_PADES_LT") {
        throw new Error(`PAdES-LT verification failed: ${verification.reason}`);
    }
    const evidenceRoot = path.join(projectRoot, "evidence", "pades-lt-local");
    fs.rmSync(evidenceRoot, { recursive: true, force: true });
    fs.mkdirSync(evidenceRoot, { recursive: true });
    fs.copyFileSync(fixture.inputPdfPath, path.join(evidenceRoot, "input.pdf"));
    fs.copyFileSync(fixture.signedBtPdfPath, path.join(evidenceRoot, "signed-pades-bt.pdf"));
    fs.copyFileSync(fixture.signedLtPdfPath, path.join(evidenceRoot, "signed-pades-lt.pdf"));
    const report = {
        test: "LOCAL_PADES_LT_END_TO_END",
        result: "PASS",
        generated_at: new Date().toISOString(),
        flow: [
            "PDF",
            "CMS/CAdES ECDSA P-256",
            "RFC3161 signature timestamp",
            "PAdES-B-T signed revision",
            "incremental DSS/VRI update",
            "embedded certificates + OCSP + CRL",
            "PAdES-LT offline evidence verification",
        ],
        certificate_id: fixture.certificateRecord.certificate_id,
        pades_level: verification.baseline_level,
        pades_reason: verification.reason,
        cms_signature_valid: verification.cms_signature_valid,
        timestamp_valid: verification.timestamp_valid,
        dss_present: verification.dss_present,
        vri_present: verification.vri_present,
        vri_binding_valid: verification.pades_lt?.vri_binding_valid === true,
        embedded_certificate_count: verification.pades_lt?.embedded_certificate_count || 0,
        embedded_ocsp_count: verification.pades_lt?.embedded_ocsp_count || 0,
        embedded_crl_count: verification.pades_lt?.embedded_crl_count || 0,
        offline_verification_ready: verification.offline_verification_ready === true,
        signed_revision_length: verification.signed_revision_length,
        final_pdf_length: verification.pades_lt?.final_pdf_length || fixture.signedPdfBytes.length,
        evidence_directory: "evidence/pades-lt-local",
    };
    atomicWriteJsonSync(path.join(evidenceRoot, "result.json"), report, { backup: false });
    console.log(JSON.stringify(report, null, 2));
} catch (error) {
    console.error(JSON.stringify({
        test: "LOCAL_PADES_LT_END_TO_END",
        result: "FAIL",
        error: error.message,
    }, null, 2));
    process.exitCode = 2;
} finally {
    fixture?.cleanup();
}
