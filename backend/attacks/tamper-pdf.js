import { verifyPadesPdf } from "../src/crypto/pades.service.js";
import { createPadesFixture, printResult } from "./pades-attack-utils.js";
const fixture = await createPadesFixture();
const original = verifyPadesPdf({ pdfPath: fixture.signedPdfPath, expectedFingerprint: fixture.certificateRecord.fingerprint_sha256 });
const tampered = Buffer.from(fixture.signedPdfBytes);
const index = Math.max(16, Math.floor(original.byte_range[1] / 2));
tampered[index] ^= 0x01;
const attacked = verifyPadesPdf({ pdfBuffer: tampered, expectedFingerprint: fixture.certificateRecord.fingerprint_sha256 });
printResult({ title: "ATTACK 2 - PDF CONTENT MODIFIED AFTER PADES SIGNING", originalValid: original.valid, attackedValid: attacked.valid, reason: attacked.reason });
