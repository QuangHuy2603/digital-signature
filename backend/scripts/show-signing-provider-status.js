import "../src/config/env.config.js";
import { findOfficerByOfficerId } from "../src/services/officer-account.service.js";
import { findCertificateById } from "../src/services/certificate.repository.js";
import { getSigningProviderStatus } from "../src/crypto/signing-provider.service.js";

const officerIdIndex = process.argv.indexOf("--officer-id");
const officerId = String(officerIdIndex >= 0 ? process.argv[officerIdIndex + 1] : "OFFICER-001").toUpperCase();
const officer = findOfficerByOfficerId(officerId);
const certificateId = officer?.remote_certificate_id || officer?.active_certificate_id || null;
const certificateRecord = certificateId ? findCertificateById(certificateId) : null;
console.log(JSON.stringify({
    officer_id: officerId,
    certificate_id: certificateId,
    ...getSigningProviderStatus({ certificateRecord }),
}, null, 2));
