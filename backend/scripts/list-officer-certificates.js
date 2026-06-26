import "dotenv/config";
import { listCertificates } from "../src/services/certificate.repository.js";

const certificates = listCertificates();
console.log(`Certificates: ${certificates.length}`);
for (const certificate of certificates) {
    console.log(
        `${certificate.certificate_id} | officer=${certificate.officer_id} | ` +
        `status=${certificate.status} | valid_to=${certificate.valid_to}`
    );
}
