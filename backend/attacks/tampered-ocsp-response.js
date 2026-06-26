import "dotenv/config";
import { findActiveCertificateByOfficerId } from "../src/services/certificate.repository.js";
import { generateOcspResponse, verifyOcspResponse } from "../src/crypto/ocsp.service.js";

const record = findActiveCertificateByOfficerId("OFFICER-001");
const response = generateOcspResponse({ serialNumber: record.serial_number, certificateId: record.certificate_id });
const original = verifyOcspResponse({ requestDerBase64: response.request_der_base64, responseDerBase64: response.response_der_base64 });
const bytes = Buffer.from(response.response_der_base64, "base64");
const tampered = bytes.subarray(0, Math.max(1, bytes.length - 17));
const attacked = verifyOcspResponse({ requestDerBase64: response.request_der_base64, responseDerBase64: tampered.toString("base64") });
const passed = original.valid === true && attacked.valid === false;
console.log("\n=== ATTACK 12 - TAMPERED OCSP RESPONSE ===");
console.log("Original response:", original.valid ? "VALID" : "INVALID");
console.log("Tampered response:", attacked.valid ? "VALID" : "REJECTED");
console.log("Reason:", attacked.reason);
console.log("Test result:", passed ? "PASS" : "FAIL");
if (!passed) process.exitCode = 1;
