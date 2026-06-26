import "../src/config/env.config.js";
import { parseCliArgs } from "./cli-args.js";
import { findCitizenByCitizenId } from "../src/services/auth.service.js";
import { findCertificatesByCitizenId } from "../src/services/certificate.repository.js";
import { listClientAgentCertificates, getClientAgentStatus } from "../../client-agent/src/agent-core.js";

const args = parseCliArgs();
const citizenId = String(args["citizen-id"] || "CITIZEN-001");
const citizen = findCitizenByCitizenId(citizenId);
const records = findCertificatesByCitizenId(citizenId);
const agentCertificates = citizen ? listClientAgentCertificates({ signerType: "citizen", userId: citizen.id }) : [];
const status = {
    version: "1.0.0",
    citizen_id: citizenId,
    citizen_found: Boolean(citizen),
    user_id: citizen?.id || null,
    software_certificate_id: citizen?.citizen_software_certificate_id || null,
    pkcs11_certificate_id: citizen?.citizen_pkcs11_certificate_id || null,
    active_citizen_certificate_id: citizen?.active_citizen_certificate_id || null,
    registry_certificates: records.map((item) => ({
        certificate_id: item.certificate_id,
        provider: item.key_provider || item.provider,
        status: item.status,
        private_key_exportable: item.private_key_exportable,
        pkcs11_token_label: item.pkcs11_token_label || null,
        pkcs11_key_label: item.pkcs11_key_label || null,
        pkcs11_key_id: item.pkcs11_key_id || null,
    })),
    client_agent: getClientAgentStatus(),
    citizen_certificates: agentCertificates,
};
status.ready_software = agentCertificates.some((item) => item.provider === "software" && item.provider_ready && item.status === "active");
status.ready_pkcs11 = agentCertificates.some((item) => item.provider === "pkcs11" && item.provider_ready && item.status === "active" && item.private_key_exportable === false);
status.ready = status.ready_software;
console.log(JSON.stringify(status, null, 2));
if (!status.ready) process.exitCode = 2;
