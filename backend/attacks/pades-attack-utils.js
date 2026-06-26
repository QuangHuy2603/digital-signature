import fs from "node:fs";
import path from "node:path";

const fixturesDirectory = path.resolve("tests/fixtures");
const signedPdfPath = path.join(fixturesDirectory, "pades-valid.pdf");
const inputPdfPath = path.join(fixturesDirectory, "pades-unsigned.pdf");
const manifestPath = path.join(fixturesDirectory, "pades-valid.json");

export async function createPadesFixture() {
    if (!fs.existsSync(signedPdfPath) || !fs.existsSync(inputPdfPath) || !fs.existsSync(manifestPath)) {
        throw new Error("PAdES fixtures are missing. Run the automated tests or restore tests/fixtures.");
    }
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const fingerprint = manifest.fingerprint_sha256 || manifest.verification?.signer_fingerprint_sha256;
    return {
        inputPdfPath,
        signedPdfPath,
        signedPdfBytes: fs.readFileSync(signedPdfPath),
        certificateRecord: {
            certificate_id: manifest.certificate_id,
            fingerprint_sha256: fingerprint,
        },
        evidence: manifest.verification,
        cleanup() {},
    };
}

export function printResult({ title, originalValid, attackedValid, reason, expectedReason }) {
    const passed = originalValid === true && attackedValid === false &&
        (!expectedReason || reason === expectedReason);
    console.log(`\n=== ${title} ===`);
    console.log("Original PAdES:", originalValid ? "VALID" : "INVALID");
    console.log("After attack:", attackedValid ? "VALID" : "REJECTED");
    console.log("Reason:", reason || "NONE");
    if (expectedReason) console.log("Expected reason:", expectedReason);
    console.log("Test result:", passed ? "PASS" : "FAIL");
    if (!passed) process.exitCode = 1;
    return passed;
}
