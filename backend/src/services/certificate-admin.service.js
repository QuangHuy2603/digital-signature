import crypto from "node:crypto";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
    fileCertificateRequestRepository,
} from "./certificate-request.repository.js";
import {
    findCertificateById,
    findCertificatesByCitizenId,
    findCertificatesByOfficerId,
    listCertificates,
    updateCertificate,
} from "./certificate.repository.js";
import { listUsers, updateUser } from "./auth.service.js";
import { generateCertificateRevocationList, checkCertificateRevocation, normalizeRevocationReason } from "../crypto/crl.service.js";
import { checkCertificateStatusWithOcsp } from "../crypto/ocsp.service.js";
import { atomicWriteJsonSync, readJsonFileSync } from "../utils/atomic-file.util.js";
import { writeAuditLog } from "./audit.service.js";

export class CertificateLifecycleError extends Error {
    constructor(message, code = "CERTIFICATE_LIFECYCLE_ERROR", status = 400) {
        super(message);
        this.name = "CertificateLifecycleError";
        this.code = code;
        this.status = status;
    }
}

const ROLE_PROVIDERS = {
    citizen: new Set(["software", "pkcs11"]),
    officer: new Set(["software", "softhsm"]),
};

function normalizeRole(user) {
    const roles = Array.isArray(user?.roles) ? user.roles : [];
    if (roles.includes("citizen")) return "citizen";
    if (roles.includes("officer")) return "officer";
    if (roles.includes("admin")) return "admin";
    return null;
}

function normalizeRequestType(value) {
    const type = String(value || "issue").trim().toLowerCase();
    if (!new Set(["issue", "renew", "revoke"]).has(type)) {
        throw new CertificateLifecycleError("Unsupported certificate request type", "CERTIFICATE_REQUEST_TYPE_INVALID", 400);
    }
    return type;
}

function normalizeProvider(value) {
    return String(value || "software").trim().toLowerCase();
}

function sha256(value) {
    return crypto.createHash("sha256").update(String(value || ""), "utf8").digest("hex").toUpperCase();
}

function immutablePayload(record) {
    return JSON.stringify({
        request_id: record.request_id,
        request_type: record.request_type,
        user_id: record.user_id,
        certificate_role: record.certificate_role,
        subject_id: record.subject_id,
        provider: record.provider,
        target_certificate_id: record.target_certificate_id || null,
        csr_sha256: record.csr_sha256 || null,
        public_key_sha256: record.public_key_sha256 || null,
    });
}

function immutableDigest(record) {
    return sha256(immutablePayload(record));
}

function subjectIdForUser(user, role) {
    if (role === "citizen") return user.citizen_id || `CITIZEN-${String(user.id).padStart(3, "0")}`;
    if (role === "officer") return user.officer_id || `OFFICER-${String(user.id).padStart(3, "0")}`;
    return null;
}

function recordsForSubject(certificates, role, subjectId) {
    return certificates.filter((certificate) => role === "citizen"
        ? String(certificate.citizen_id || "") === String(subjectId)
        : String(certificate.officer_id || "") === String(subjectId));
}

function providerOf(certificate) {
    return String(certificate?.key_provider || certificate?.provider || "software").toLowerCase();
}

function normalizeCertificateRevocationReason(value = "unspecified") {
    try {
        return normalizeRevocationReason(value || "unspecified");
    } catch (error) {
        throw new CertificateLifecycleError(
            error.message || "Invalid revocation reason",
            error.code || "INVALID_REVOCATION_REASON",
            error.status || 400,
        );
    }
}

function certificateRoleOf(certificate) {
    if (certificate?.citizen_id || certificate?.signer_type === "citizen") return "citizen";
    if (certificate?.officer_id || certificate?.signer_type === "officer") return "officer";
    return null;
}

function assertOwner(certificate, request) {
    const actual = request.certificate_role === "citizen" ? certificate?.citizen_id : certificate?.officer_id;
    if (!certificate || String(actual || "") !== String(request.subject_id || "")) {
        throw new CertificateLifecycleError("Certificate owner does not match request subject", "CERTIFICATE_OWNER_MISMATCH", 409);
    }
}

export function assertCertificateUsableForSigning(certificate) {
    if (!certificate || certificate.status !== "active" || certificate.revoked_at) {
        throw new CertificateLifecycleError("Certificate is revoked or inactive", "CERTIFICATE_REVOKED", 403);
    }
    return true;
}

export function assertRevocationConsistency({ certificate, crlResult, ocspResult }) {
    const revoked = certificate?.status === "revoked" || Boolean(certificate?.revoked_at);
    if (revoked && !crlResult?.revoked) {
        throw new CertificateLifecycleError("CRL does not contain revoked certificate", "CRL_REVOCATION_MISSING", 409);
    }
    if (revoked && ocspResult?.status !== "revoked") {
        throw new CertificateLifecycleError("OCSP status does not match revoked registry status", "OCSP_REVOCATION_STATUS_MISMATCH", 409);
    }
    return true;
}

function syncClientAgentCertificateStatus(certificateId, status) {
    const registryPath = path.resolve("../client-agent/storage/certificates.json");
    const registry = readJsonFileSync(registryPath, []);
    if (!Array.isArray(registry)) return;
    const next = registry.map((item) => item.certificate_id === certificateId ? { ...item, status } : item);
    atomicWriteJsonSync(registryPath, next, { backup: true });
}

function clearUserCertificateBinding(certificate) {
    const user = listUsers().find((item) => String(item.id) === String(certificate.user_id));
    if (!user) return;
    const patch = {};
    if (certificate.signer_type === "citizen" || certificate.citizen_id) {
        if (user.active_citizen_certificate_id === certificate.certificate_id) patch.active_citizen_certificate_id = null;
        if (user.citizen_software_certificate_id === certificate.certificate_id) patch.citizen_software_certificate_id = null;
        if (user.citizen_pkcs11_certificate_id === certificate.certificate_id) patch.citizen_pkcs11_certificate_id = null;
        patch.citizen_certificate_status = "revoked";
    } else {
        if (user.active_certificate_id === certificate.certificate_id) patch.active_certificate_id = null;
        if (user.local_certificate_id === certificate.certificate_id) patch.local_certificate_id = null;
        if (user.remote_certificate_id === certificate.certificate_id) patch.remote_certificate_id = null;
        patch.certificate_status = "revoked";
    }
    updateUser(user.id, patch);
}

export async function revokeCertificateAndSynchronize({ certificateId, reason = "unspecified", actorId = "admin", now = new Date() }) {
    const certificate = findCertificateById(certificateId);
    if (!certificate) throw new CertificateLifecycleError("Certificate not found", "CERTIFICATE_NOT_FOUND", 404);
    if (certificate.status === "revoked" || certificate.revoked_at) {
        throw new CertificateLifecycleError("Certificate is already revoked", "CERTIFICATE_ALREADY_REVOKED", 409);
    }
    const revokedAt = new Date(now).toISOString();
    const updated = updateCertificate(certificateId, {
        status: "revoked",
        previous_status: certificate.status,
        revoked_at: revokedAt,
        revocation_reason: normalizeCertificateRevocationReason(reason),
        status_updated_at: revokedAt,
    });
    clearUserCertificateBinding(updated);
    syncClientAgentCertificateStatus(certificateId, "revoked");
    const crl = generateCertificateRevocationList();
    const crlResult = checkCertificateRevocation({ certificateRecord: updated });
    const ocspResult = checkCertificateStatusWithOcsp({ certificateRecord: updated });
    assertRevocationConsistency({ certificate: updated, crlResult, ocspResult });
    await writeAuditLog({
        action: "CERTIFICATE_REVOKED",
        userId: actorId,
        result: "success",
        details: { certificate_id: certificateId, reason: updated.revocation_reason, crl_number: crl.crl_number },
    });
    return { certificate: updated, crl, crl_status: crlResult, ocsp_status: ocspResult };
}

function executeNodeScript(scriptName, args = []) {
    const result = spawnSync(process.execPath, [path.resolve("scripts", scriptName), ...args], {
        cwd: process.cwd(),
        env: process.env,
        encoding: "utf8",
        windowsHide: true,
        shell: false,
    });
    if (result.error || result.status !== 0) {
        const message = result.error?.message || String(result.stderr || result.stdout || `exit ${result.status}`).trim();
        throw new CertificateLifecycleError(message, "CERTIFICATE_ISSUANCE_FAILED", 500);
    }
    return { stdout: result.stdout, stderr: result.stderr };
}

function defaultIssueExecutor(request) {
    const before = new Set(listCertificates().map((item) => item.certificate_id));
    const args = [];
    let script;
    if (request.certificate_role === "citizen" && request.provider === "software") {
        script = "issue-citizen-software-certificate.js";
        args.push("--user-id", String(request.user_id));
        if (request.request_type === "renew") args.push("--force");
    } else if (request.certificate_role === "citizen" && request.provider === "pkcs11") {
        script = "provision-citizen-pkcs11.js";
        args.push("--user-id", String(request.user_id));
        if (request.request_type === "renew") args.push("--force");
    } else if (request.certificate_role === "officer" && request.provider === "software") {
        script = "issue-officer-certificate.js";
        args.push("--officer-id", request.subject_id);
        if (request.request_type === "renew") args.push("--renew");
    } else if (request.certificate_role === "officer" && request.provider === "softhsm") {
        script = "provision-softhsm-officer.js";
        args.push("--officer-id", request.subject_id);
        if (request.request_type === "renew") args.push("--force");
    } else {
        throw new CertificateLifecycleError("Provider is not allowed for this certificate role", "CERTIFICATE_PROVIDER_NOT_ALLOWED", 400);
    }
    executeNodeScript(script, args);
    const candidates = listCertificates().filter((item) => !before.has(item.certificate_id));
    const issued = candidates.sort((a, b) => Number(b.version || 0) - Number(a.version || 0))[0];
    if (!issued) throw new CertificateLifecycleError("Issuance script did not register a new certificate", "CERTIFICATE_ISSUANCE_RESULT_MISSING", 500);
    return issued;
}

function defaultRevokeExecutor(request, adminUserId) {
    return revokeCertificateAndSynchronize({
        certificateId: request.target_certificate_id,
        reason: request.revocation_reason || "unspecified",
        actorId: adminUserId,
    }).then((result) => result.certificate);
}

function defaultUserLookup(userId) {
    return listUsers().find((item) => String(item.id) === String(userId)) || null;
}

function defaultCertificateList() {
    return listCertificates();
}

export function createCertificateLifecycleManager({
    repository = fileCertificateRequestRepository,
    userLookup = defaultUserLookup,
    certificateList = defaultCertificateList,
    issueExecutor = defaultIssueExecutor,
    revokeExecutor = defaultRevokeExecutor,
    nowFn = () => new Date(),
    uuidFn = () => crypto.randomUUID(),
    auditFn = writeAuditLog,
    certificateUpdate = updateCertificate,
    clientAgentSync = syncClientAgentCertificateStatus,
} = {}) {
    async function event(action, request, actorId, details = {}) {
        const item = {
            event_id: uuidFn(),
            action,
            request_id: request?.request_id || null,
            actor_id: actorId == null ? null : String(actorId),
            created_at: nowFn().toISOString(),
            details,
        };
        repository.appendEvent(item);
        await auditFn({ action, userId: actorId, result: "success", details: { request_id: request?.request_id, ...details } });
        return item;
    }

    function getRequest(requestId) {
        const request = repository.findById(requestId);
        if (!request) throw new CertificateLifecycleError("Certificate request not found", "CERTIFICATE_REQUEST_NOT_FOUND", 404);
        return request;
    }

    function assertAdmin(user) {
        if (!Array.isArray(user?.roles) || !user.roles.includes("admin")) {
            throw new CertificateLifecycleError("Admin role is required", "ADMIN_ROLE_REQUIRED", 403);
        }
    }

    return {
        listForUser(user) {
            return repository.list().filter((item) => String(item.user_id) === String(user.id));
        },
        listAll(admin) { assertAdmin(admin); return repository.list(); },
        listEvents(admin) { assertAdmin(admin); return repository.listEvents(); },
        async create({ user, requestType, certificateRole, provider, targetCertificateId = null, csrPem = null, publicKeyPem = null, revocationReason = null }) {
            const role = normalizeRole(user);
            const type = normalizeRequestType(requestType);
            const requestedRole = String(certificateRole || role || "").toLowerCase();
            if (!new Set(["citizen", "officer"]).has(role) || requestedRole !== role) {
                throw new CertificateLifecycleError("A user may request only a certificate for their own role", "CERTIFICATE_ROLE_NOT_ALLOWED", 403);
            }
            const subjectId = subjectIdForUser(user, role);
            const certs = recordsForSubject(certificateList(), role, subjectId);
            let selectedProvider = normalizeProvider(provider);
            let target = null;
            if (type === "renew" || type === "revoke") {
                target = certificateList().find((item) => item.certificate_id === targetCertificateId) || null;
                assertOwner(target, { certificate_role: role, subject_id: subjectId });
                selectedProvider = providerOf(target);
                if (target.status !== "active") throw new CertificateLifecycleError("Target certificate is not active", "CERTIFICATE_NOT_ACTIVE", 409);
            }
            if (!ROLE_PROVIDERS[role].has(selectedProvider)) {
                throw new CertificateLifecycleError("Provider is not allowed for this certificate role", "CERTIFICATE_PROVIDER_NOT_ALLOWED", 400);
            }
            if (type === "issue" && certs.some((item) => item.status === "active" && providerOf(item) === selectedProvider)) {
                throw new CertificateLifecycleError("An active certificate already exists; use renewal", "ACTIVE_CERTIFICATE_ALREADY_EXISTS", 409);
            }
            const now = nowFn().toISOString();
            const record = {
                request_id: `CERTREQ-${uuidFn()}`,
                request_type: type,
                user_id: user.id,
                certificate_role: role,
                subject_id: subjectId,
                provider: selectedProvider,
                target_certificate_id: target?.certificate_id || null,
                revocation_reason: type === "revoke" ? normalizeCertificateRevocationReason(revocationReason || "unspecified") : null,
                csr_mode: csrPem ? "provided" : "managed",
                csr_sha256: csrPem ? sha256(csrPem) : null,
                public_key_sha256: publicKeyPem ? sha256(publicKeyPem) : null,
                status: "PENDING",
                created_at: now,
                updated_at: now,
            };
            record.immutable_digest_sha256 = immutableDigest(record);
            repository.save(record);
            await event("CERTIFICATE_REQUEST_CREATED", record, user.id, { request_type: type, provider: selectedProvider });
            return record;
        },
        async approve({ admin, requestId }) {
            assertAdmin(admin);
            const request = getRequest(requestId);
            if (request.status !== "PENDING") throw new CertificateLifecycleError("Only pending requests can be approved", "CERTIFICATE_REQUEST_STATE_INVALID", 409);
            const approvedAt = nowFn().toISOString();
            const updated = repository.update(requestId, {
                status: "APPROVED",
                approved_by: admin.id,
                approved_at: approvedAt,
                approved_csr_sha256: request.csr_sha256 || null,
                approved_public_key_sha256: request.public_key_sha256 || null,
                approved_immutable_digest_sha256: immutableDigest(request),
                updated_at: approvedAt,
            });
            await event("CERTIFICATE_REQUEST_APPROVED", updated, admin.id);
            return updated;
        },
        async reject({ admin, requestId, reason }) {
            assertAdmin(admin);
            const request = getRequest(requestId);
            if (!new Set(["PENDING", "APPROVED"]).has(request.status)) throw new CertificateLifecycleError("Request cannot be rejected in its current state", "CERTIFICATE_REQUEST_STATE_INVALID", 409);
            const updated = repository.update(requestId, {
                status: "REJECTED",
                rejected_by: admin.id,
                rejected_at: nowFn().toISOString(),
                rejection_reason: String(reason || "Rejected by administrator").trim(),
                updated_at: nowFn().toISOString(),
            });
            await event("CERTIFICATE_REQUEST_REJECTED", updated, admin.id, { reason: updated.rejection_reason });
            return updated;
        },
        async issue({ admin, requestId }) {
            assertAdmin(admin);
            const request = getRequest(requestId);
            if (request.status !== "APPROVED") throw new CertificateLifecycleError("Request must be approved before processing", "RA_APPROVAL_REQUIRED", 409);
            if (request.csr_sha256 !== request.approved_csr_sha256) throw new CertificateLifecycleError("CSR changed after approval", "CSR_DIGEST_MISMATCH", 409);
            if (request.public_key_sha256 !== request.approved_public_key_sha256) throw new CertificateLifecycleError("Public key changed after approval", "PUBLIC_KEY_BINDING_MISMATCH", 409);
            if (immutableDigest(request) !== request.approved_immutable_digest_sha256) throw new CertificateLifecycleError("Certificate request changed after approval", "CERTIFICATE_REQUEST_INTEGRITY_MISMATCH", 409);
            let certificate;
            if (request.request_type === "revoke") {
                certificate = await revokeExecutor(request, admin.id);
            } else {
                certificate = await issueExecutor(request, admin.id);
                assertOwner(certificate, request);
                const all = certificateList();
                if (all.some((item) => item.certificate_id !== certificate.certificate_id && String(item.serial_number || "").toUpperCase() === String(certificate.serial_number || "").toUpperCase())) {
                    throw new CertificateLifecycleError("Certificate serial number is duplicated", "CERTIFICATE_SERIAL_DUPLICATE", 409);
                }
                if (request.request_type === "renew" && request.target_certificate_id) {
                    certificateUpdate(request.target_certificate_id, {
                        status: "superseded",
                        superseded_at: nowFn().toISOString(),
                        superseded_by_certificate_id: certificate.certificate_id,
                    });
                    clientAgentSync(request.target_certificate_id, "superseded");
                }
            }
            const finalStatus = request.request_type === "revoke" ? "REVOKED" : "ISSUED";
            const updated = repository.update(requestId, {
                status: finalStatus,
                processed_by: admin.id,
                processed_at: nowFn().toISOString(),
                issued_certificate_id: request.request_type === "revoke" ? null : certificate.certificate_id,
                revoked_certificate_id: request.request_type === "revoke" ? certificate.certificate_id : null,
                updated_at: nowFn().toISOString(),
            });
            await event(request.request_type === "revoke" ? "CERTIFICATE_REQUEST_REVOKED" : "CERTIFICATE_ISSUED", updated, admin.id, { certificate_id: certificate.certificate_id });
            return { request: updated, certificate };
        },
        async revokeDirect({ admin, certificateId, reason = "unspecified", confirmation = null }) {
            assertAdmin(admin);
            const normalizedId = String(certificateId || "").trim();
            if (!normalizedId) {
                throw new CertificateLifecycleError("certificate_id is required", "CERTIFICATE_ID_REQUIRED", 400);
            }
            if (String(confirmation || "").trim() !== normalizedId) {
                throw new CertificateLifecycleError(
                    "Direct revocation requires confirmation with the certificate ID",
                    "DIRECT_REVOCATION_CONFIRMATION_REQUIRED",
                    400,
                );
            }

            const certificate = certificateList().find((item) => item.certificate_id === normalizedId) || null;
            if (!certificate) {
                throw new CertificateLifecycleError("Certificate not found", "CERTIFICATE_NOT_FOUND", 404);
            }
            if (certificate.status === "revoked" || certificate.revoked_at) {
                throw new CertificateLifecycleError("Certificate is already revoked", "CERTIFICATE_ALREADY_REVOKED", 409);
            }
            if (certificate.status !== "active") {
                throw new CertificateLifecycleError("Only active certificates can be revoked", "CERTIFICATE_NOT_ACTIVE", 409);
            }

            const certificateRole = certificateRoleOf(certificate);
            const subjectId = certificateRole === "citizen" ? certificate.citizen_id : certificate.officer_id;
            if (!certificateRole || !subjectId) {
                throw new CertificateLifecycleError(
                    "Certificate owner binding is incomplete",
                    "CERTIFICATE_OWNER_BINDING_MISSING",
                    409,
                );
            }

            const now = nowFn().toISOString();
            const normalizedReason = normalizeCertificateRevocationReason(reason);
            const request = {
                request_id: `CERTREQ-ADMIN-${uuidFn()}`,
                request_type: "revoke",
                request_origin: "admin",
                admin_direct_revocation: true,
                user_id: certificate.user_id ?? null,
                certificate_role: certificateRole,
                subject_id: subjectId,
                provider: providerOf(certificate),
                target_certificate_id: normalizedId,
                revocation_reason: normalizedReason,
                csr_mode: "not_applicable",
                csr_sha256: null,
                public_key_sha256: null,
                status: "APPROVED",
                created_by: admin.id,
                created_at: now,
                approved_by: admin.id,
                approved_at: now,
                processed_by: admin.id,
                processed_at: now,
                updated_at: now,
            };
            request.immutable_digest_sha256 = immutableDigest(request);
            request.approved_immutable_digest_sha256 = request.immutable_digest_sha256;

            const revokedCertificate = await revokeExecutor(request, admin.id);
            const finalRequest = {
                ...request,
                status: "REVOKED",
                revoked_certificate_id: revokedCertificate.certificate_id,
            };
            repository.save(finalRequest);
            await event("ADMIN_DIRECT_CERTIFICATE_REVOKED", finalRequest, admin.id, {
                certificate_id: revokedCertificate.certificate_id,
                subject_id: subjectId,
                provider: providerOf(revokedCertificate),
                reason: normalizedReason,
                request_origin: "admin",
            });

            return { request: finalRequest, certificate: revokedCertificate };
        },
        getOverview(admin) {
            assertAdmin(admin);
            const requests = repository.list();
            const certificates = certificateList();
            return {
                version: "1.0.0",
                role_model: ["citizen", "officer", "admin"],
                admin_combines_ra_and_ca: true,
                requests_total: requests.length,
                pending_requests: requests.filter((item) => item.status === "PENDING").length,
                approved_requests: requests.filter((item) => item.status === "APPROVED").length,
                issued_requests: requests.filter((item) => item.status === "ISSUED").length,
                revoked_requests: requests.filter((item) => item.status === "REVOKED").length,
                admin_direct_revocations: requests.filter((item) => item.admin_direct_revocation === true).length,
                active_certificates: certificates.filter((item) => item.status === "active").length,
                revoked_certificates: certificates.filter((item) => item.status === "revoked").length,
            };
        },
    };
}

export const certificateLifecycleManager = createCertificateLifecycleManager();
