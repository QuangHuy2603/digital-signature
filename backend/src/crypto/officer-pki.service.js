import {
    loadOfficerCertificateIdentity,
    signPayloadWithOfficerCertificate,
    OfficerCertificateError,
} from "./x509-pki.service.js";
import { getUserById } from "../services/auth.service.js";
import {
    findCertificateById,
    listCertificates,
} from "../services/certificate.repository.js";
import { PKI_ROOT_CA_CERT_PATH } from "../config/env.config.js";
import {
    assertCertificateNotRevoked,
    verifyCertificateRevocationList,
} from "./crl.service.js";

function hasOfficerRole(user) {
    return Array.isArray(user?.roles) && user.roles.includes("officer");
}

export function ensureCertificateRecordActive(record, now = new Date()) {
    if (!record) {
        throw new OfficerCertificateError(
            "No certificate is assigned to this officer",
            "OFFICER_CERTIFICATE_NOT_ASSIGNED",
            409
        );
    }

    if (record.status !== "active") {
        const code = record.status === "revoked"
            ? "OFFICER_CERTIFICATE_REVOKED"
            : record.status === "expired"
                ? "OFFICER_CERTIFICATE_EXPIRED"
                : "OFFICER_CERTIFICATE_NOT_ACTIVE";
        throw new OfficerCertificateError(
            `Officer certificate is not active (status=${record.status})`,
            code,
            409
        );
    }

    if (record.revoked_at) {
        throw new OfficerCertificateError(
            "Officer certificate has been revoked in the local registry",
            "OFFICER_CERTIFICATE_REVOKED",
            409
        );
    }

    if (record.valid_from && new Date(now) < new Date(record.valid_from)) {
        throw new OfficerCertificateError(
            "Officer certificate is not valid yet",
            "OFFICER_CERTIFICATE_NOT_YET_VALID",
            409
        );
    }

    if (record.valid_to && new Date(now) > new Date(record.valid_to)) {
        throw new OfficerCertificateError(
            "Officer certificate has expired",
            "OFFICER_CERTIFICATE_EXPIRED",
            409
        );
    }
}

export async function loadOfficerSigningIdentity(userId, { now = new Date(), signingMethod = null } = {}) {
    const user = await getUserById(userId);

    if (!user) {
        throw new OfficerCertificateError(
            "Authenticated officer account was not found",
            "OFFICER_NOT_FOUND",
            404
        );
    }
    if (!hasOfficerRole(user)) {
        throw new OfficerCertificateError(
            "Authenticated account does not have the officer role",
            "USER_IS_NOT_OFFICER",
            403
        );
    }
    if (!user.officer_id) {
        throw new OfficerCertificateError(
            "Officer account does not have an officer_id",
            "OFFICER_ID_NOT_ASSIGNED",
            409
        );
    }
    const normalizedMethod = String(signingMethod || "").trim().toLowerCase();
    const selectedCertificateId = normalizedMethod === "remote"
        ? (user.remote_certificate_id || user.active_certificate_id)
        : normalizedMethod === "local"
            ? (user.local_certificate_id || user.active_certificate_id)
            : user.active_certificate_id;

    if (!selectedCertificateId) {
        if (user.certificate_status === "revoked") {
            throw new OfficerCertificateError(
                "Officer certificate has been revoked",
                "OFFICER_CERTIFICATE_REVOKED",
                403
            );
        }
        if (user.certificate_status === "expired") {
            throw new OfficerCertificateError(
                "Officer certificate has expired",
                "OFFICER_CERTIFICATE_EXPIRED",
                409
            );
        }
        throw new OfficerCertificateError(
            "Officer account does not have an active certificate",
            "OFFICER_CERTIFICATE_NOT_ASSIGNED",
            409
        );
    }

    const record = findCertificateById(selectedCertificateId);
    ensureCertificateRecordActive(record, now);
    const revocation = assertCertificateNotRevoked(record);

    if (String(record.user_id) !== String(user.id) ||
        String(record.officer_id) !== String(user.officer_id)) {
        throw new OfficerCertificateError(
            "Certificate registry owner does not match the authenticated officer",
            "OFFICER_CERTIFICATE_OWNER_MISMATCH",
            403
        );
    }

    const identity = loadOfficerCertificateIdentity({
        officerCertPath: record.certificate_path,
        rootCertPath: record.root_ca_certificate_path || PKI_ROOT_CA_CERT_PATH,
        expectedFingerprint: record.fingerprint_sha256,
        expectedOfficerId: user.officer_id,
        expectedEmail: user.email,
        now,
    });

    return {
        user,
        certificateRecord: record,
        identity,
        revocation,
    };
}

export async function signPayloadForOfficer(payload, userId, options = {}) {
    const loaded = await loadOfficerSigningIdentity(userId, options);
    const { user, certificateRecord } = loaded;

    const signed = signPayloadWithOfficerCertificate(payload, {
        officerCertPath: certificateRecord.certificate_path,
        rootCertPath: certificateRecord.root_ca_certificate_path || PKI_ROOT_CA_CERT_PATH,
        officerPrivateKeyPath: certificateRecord.private_key_path,
        expectedFingerprint: certificateRecord.fingerprint_sha256,
        expectedOfficerId: user.officer_id,
        expectedEmail: user.email,
        now: options.now || new Date(),
    });

    return {
        ...signed,
        user,
        certificate_record: certificateRecord,
    };
}

export function getMultiOfficerPkiStatus() {
    const certificates = listCertificates();
    const activeCertificates = certificates.filter(
        (certificate) => certificate.status === "active"
    );
    const revokedCertificates = certificates.filter(
        (certificate) => certificate.status === "revoked" || certificate.revoked_at
    );
    const crl = verifyCertificateRevocationList();

    return {
        status: activeCertificates.length > 0 && crl.signature_valid
            ? "ready"
            : "not_ready",
        total_certificates: certificates.length,
        active_certificates: activeCertificates.length,
        revoked_certificates: revokedCertificates.length,
        crl: {
            available: crl.available,
            signature_valid: crl.signature_valid,
            reason: crl.reason,
            crl_number: crl.crl_number ?? null,
            revoked_count: crl.revoked_count ?? 0,
            last_update: crl.last_update ?? null,
            next_update: crl.next_update ?? null,
            fingerprint_sha256: crl.fingerprint_sha256 ?? null,
        },
        certificates: certificates.map((certificate) => ({
            certificate_id: certificate.certificate_id,
            officer_id: certificate.officer_id,
            user_id: certificate.user_id,
            subject: certificate.subject,
            issuer: certificate.issuer,
            serial_number: certificate.serial_number,
            fingerprint_sha256: certificate.fingerprint_sha256,
            valid_from: certificate.valid_from,
            valid_to: certificate.valid_to,
            status: certificate.status,
            purpose: certificate.purpose || "local-signing",
            key_provider: certificate.key_provider || (certificate.private_key_path ? "file" : null),
            private_key_exportable: certificate.private_key_exportable ?? Boolean(certificate.private_key_path),
            pkcs11_token_label: certificate.pkcs11_token_label || null,
            pkcs11_key_label: certificate.pkcs11_key_label || null,
            pkcs11_key_id: certificate.pkcs11_key_id || null,
            revoked_at: certificate.revoked_at || null,
            revocation_reason: certificate.revocation_reason || null,
            superseded_at: certificate.superseded_at || certificate.replaced_at || null,
            superseded_by_certificate_id:
                certificate.superseded_by_certificate_id ||
                certificate.replaced_by_certificate_id ||
                null,
        })),
    };
}
