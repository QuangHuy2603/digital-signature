import {
    findCertificateById,
    listCertificates,
    updateCertificate,
} from "./certificate.repository.js";
import {
    assignActiveCertificate,
    assignSigningCertificate,
    findOfficerByOfficerId,
} from "./officer-account.service.js";
import {
    generateCertificateRevocationList,
    normalizeRevocationReason,
    checkCertificateRevocation,
} from "../crypto/crl.service.js";
import { writeAuditLog } from "./audit.service.js";
import { OfficerCertificateError } from "../crypto/x509-pki.service.js";

export async function revokeOfficerCertificate({
    certificateId,
    reason = "unspecified",
    actorId = "pki-cli",
    now = new Date(),
} = {}) {
    const normalizedId = String(certificateId || "").trim();
    if (!normalizedId) {
        throw new OfficerCertificateError(
            "certificate_id is required",
            "CERTIFICATE_ID_REQUIRED",
            400
        );
    }

    const revocationReason = normalizeRevocationReason(reason);
    const record = findCertificateById(normalizedId);
    if (!record) {
        throw new OfficerCertificateError(
            `Certificate not found: ${normalizedId}`,
            "CERTIFICATE_NOT_FOUND",
            404
        );
    }
    if (record.status === "revoked" || record.revoked_at) {
        throw new OfficerCertificateError(
            `Certificate is already revoked: ${normalizedId}`,
            "CERTIFICATE_ALREADY_REVOKED",
            409
        );
    }

    const revokedAt = new Date(now).toISOString();
    const previousStatus = record.status;
    const updated = updateCertificate(normalizedId, {
        status: "revoked",
        previous_status: previousStatus,
        revoked_at: revokedAt,
        revocation_reason: revocationReason,
        status_updated_at: revokedAt,
    });

    const officer = findOfficerByOfficerId(record.officer_id);
    if (officer?.remote_certificate_id === normalizedId) {
        assignSigningCertificate({
            officerId: record.officer_id,
            certificateId: null,
            signingMethod: "remote",
        });
    }
    if (officer?.local_certificate_id === normalizedId || officer?.active_certificate_id === normalizedId) {
        assignActiveCertificate({
            officerId: record.officer_id,
            certificateId: null,
            certificateStatus: "revoked",
        });
    }

    const crl = generateCertificateRevocationList();

    await writeAuditLog({
        action: "CERTIFICATE_REVOKED",
        userId: actorId,
        result: "success",
        details: {
            certificate_id: normalizedId,
            officer_id: record.officer_id,
            reason: revocationReason,
            revoked_at: revokedAt,
            previous_status: previousStatus,
            crl_number: crl.crl_number,
        },
    });
    await writeAuditLog({
        action: "CRL_GENERATED",
        userId: actorId,
        result: "success",
        details: {
            crl_number: crl.crl_number,
            revoked_count: crl.revoked_count,
            fingerprint_sha256: crl.fingerprint_sha256,
        },
    });

    return {
        certificate: updated,
        officer: findOfficerByOfficerId(record.officer_id),
        crl,
    };
}

export function getCertificateLifecycleStatus(certificateId) {
    const record = findCertificateById(certificateId);
    if (!record) return null;
    return {
        certificate: record,
        revocation: checkCertificateRevocation({ certificateRecord: record }),
    };
}

export function listCertificateLifecycle() {
    return listCertificates().map((record) => ({
        ...record,
        revocation: checkCertificateRevocation({ certificateRecord: record }),
    }));
}

export function markExpiredCertificates({ now = new Date() } = {}) {
    const current = new Date(now);
    const changed = [];

    for (const record of listCertificates()) {
        if (record.status !== "active") continue;
        if (!record.valid_to || new Date(record.valid_to) >= current) continue;

        const updated = updateCertificate(record.certificate_id, {
            status: "expired",
            expired_at: current.toISOString(),
            status_updated_at: current.toISOString(),
        });
        const officer = findOfficerByOfficerId(record.officer_id);
        if (officer?.remote_certificate_id === record.certificate_id) {
            assignSigningCertificate({
                officerId: record.officer_id,
                certificateId: null,
                signingMethod: "remote",
            });
        }
        if (officer?.local_certificate_id === record.certificate_id || officer?.active_certificate_id === record.certificate_id) {
            assignActiveCertificate({
                officerId: record.officer_id,
                certificateId: null,
                certificateStatus: "expired",
            });
        }
        changed.push(updated);
    }

    if (changed.length > 0) {
        generateCertificateRevocationList();
    }
    return changed;
}
