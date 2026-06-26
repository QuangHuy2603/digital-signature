import { verifyPadesPdf } from "../src/crypto/pades.service.js";
import { createPadesFixture, printResult } from "./pades-attack-utils.js";
const fixture = await createPadesFixture();
const original = verifyPadesPdf({ pdfPath: fixture.signedPdfPath, expectedFingerprint: fixture.certificateRecord.fingerprint_sha256 });
const attacked = verifyPadesPdf({ pdfPath: fixture.inputPdfPath });
printResult({ title: "ATTACK 5 - PDF WITH NO DIGITAL SIGNATURE FIELD", originalValid: original.valid, attackedValid: attacked.valid, reason: attacked.reason, expectedReason: "PADES_SIGNATURE_NOT_FOUND" });
