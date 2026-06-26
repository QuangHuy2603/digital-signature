import "dotenv/config";
import { parseCliArgs } from "./cli-args.js";
import { findCertificateById, findActiveCertificateByOfficerId } from "../src/services/certificate.repository.js";
import { generateOcspResponse, verifyOcspResponse } from "../src/crypto/ocsp.service.js";

const args = parseCliArgs();
const record = args["certificate-id"]
    ? findCertificateById(String(args["certificate-id"]))
    : findActiveCertificateByOfficerId(String(args["officer-id"] || "OFFICER-001").toUpperCase());
if (!record) throw new Error("CERTIFICATE_NOT_FOUND");
const response = generateOcspResponse({ serialNumber: record.serial_number, certificateId: record.certificate_id });
const verified = verifyOcspResponse({
    requestDerBase64: response.request_der_base64,
    responseDerBase64: response.response_der_base64,
});
console.log(JSON.stringify({ certificate_id: record.certificate_id, response, verified }, null, 2));
if (!verified.valid) process.exitCode = 1;
else console.log("OCSP VERIFICATION: PASS");
