import { listUsers } from "../src/services/auth.service.js";
import { listCertificates } from "../src/services/certificate.repository.js";
import { listCertificateRequests, listCertificateEvents } from "../src/services/certificate-request.repository.js";

const admin = listUsers().find((item) => item.roles?.includes("admin"));
const requests = listCertificateRequests();
const certificates = listCertificates();

console.log(JSON.stringify({
    version: "1.0.0",
    ready: Boolean(admin),
    roles: ["citizen", "officer", "admin"],
    admin_combines_ra_and_ca: true,
    admin_direct_revocation: true,
    direct_revocation_safety: {
        certificate_id_confirmation_required: true,
        revocation_reason_required: true,
        audit_event: "ADMIN_DIRECT_CERTIFICATE_REVOKED",
        synchronizes: ["certificate-registry", "client-agent", "CRL", "OCSP", "user-binding"],
    },
    admin_account: admin ? { id: admin.id, email: admin.email, roles: admin.roles } : null,
    workflow: ["PENDING", "APPROVED", "REJECTED", "ISSUED", "REVOKED"],
    request_origins: ["user", "admin"],
    providers: { citizen: ["software", "pkcs11"], officer: ["software", "softhsm"] },
    requests_total: requests.length,
    admin_direct_revocations: requests.filter((item) => item.admin_direct_revocation === true).length,
    events_total: listCertificateEvents().length,
    active_certificates: certificates.filter((item) => item.status === "active").length,
    revoked_certificates: certificates.filter((item) => item.status === "revoked").length,
    storage: "atomic JSON, no database",
}, null, 2));
