import crypto, { X509Certificate } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { PKI_ROOT_CA_CERT_PATH } from "../config/env.config.js";
export { buildCitizenSignaturePayload } from "./citizen-signature-payload.js";
import { findCertificateById } from "../services/certificate.repository.js";
import { getUserById } from "../services/auth.service.js";
import { checkCertificateStatusWithOcsp } from "./ocsp.service.js";
import { normalizeFingerprint } from "./x509-pki.service.js";

export class CitizenSigningError extends Error {
    constructor(message, code, status = 400) {
        super(message);
        this.name = "CitizenSigningError";
        this.code = code;
        this.status = status;
    }
}

export function verifyCitizenDetachedSignature({
    signatureBase64,
    canonicalPayload,
    certificatePem,
} = {}) {
    try {
        const certificate = new X509Certificate(certificatePem);
        return crypto.verify(
            "sha256",
            Buffer.from(String(canonicalPayload || ""), "utf8"),
            certificate.publicKey,
            Buffer.from(String(signatureBase64 || ""), "base64")
        );
    } catch {
        return false;
    }
}

function parseUid(subject = "") {
    return String(subject).match(/(?:^|\n|,)\s*UID\s*=\s*([^,\n]+)/i)?.[1]?.trim() || null;
}

function resolveBackendPath(value) {
    return path.resolve(process.cwd(), value);
}

export async function loadCitizenSigningIdentity({
    userId,
    certificateId,
    provider = null,
    now = new Date(),
    requireRevocationGood = true,
} = {}) {
    const user = await getUserById(userId);
    if (!user || !(user.roles || []).includes("citizen")) {
        throw new CitizenSigningError(
            "Authenticated user is not a citizen",
            "CITIZEN_ROLE_REQUIRED",
            403
        );
    }
    if (!user.citizen_id) {
        throw new CitizenSigningError(
            "Citizen account does not have a citizen_id",
            "CITIZEN_ID_NOT_ASSIGNED",
            409
        );
    }

    const selectedId = certificateId ||
        (String(provider || "").toLowerCase() === "pkcs11"
            ? user.citizen_pkcs11_certificate_id
            : user.citizen_software_certificate_id) ||
        user.active_citizen_certificate_id;
    if (!selectedId) {
        throw new CitizenSigningError(
            "Citizen account does not have a signing certificate",
            "CITIZEN_CERTIFICATE_NOT_ASSIGNED",
            409
        );
    }

    const record = findCertificateById(selectedId);
    if (!record) {
        throw new CitizenSigningError(
            "Citizen certificate record was not found",
            "CITIZEN_CERTIFICATE_NOT_FOUND",
            404
        );
    }
    if (record.status === "revoked" || record.revoked_at) {
        throw new CitizenSigningError(
            "Citizen certificate has been revoked",
            "CITIZEN_CERTIFICATE_REVOKED",
            403
        );
    }
    if (record.status !== "active") {
        throw new CitizenSigningError(
            `Citizen certificate is not active: ${record.status}`,
            "CITIZEN_CERTIFICATE_INACTIVE",
            409
        );
    }
    if (new Date(record.valid_from) > now || new Date(record.valid_to) < now) {
        throw new CitizenSigningError(
            "Citizen certificate is outside its validity period",
            "CITIZEN_CERTIFICATE_EXPIRED",
            409
        );
    }
    if (record.signer_type !== "citizen" && record.purpose !== "citizen-signing") {
        throw new CitizenSigningError(
            "Selected certificate is not a citizen-signing certificate",
            "CERTIFICATE_ROLE_MISMATCH",
            403
        );
    }
    if (String(record.user_id) !== String(user.id) ||
        String(record.citizen_id) !== String(user.citizen_id)) {
        throw new CitizenSigningError(
            "Citizen certificate owner does not match the authenticated user",
            "CITIZEN_CERTIFICATE_OWNER_MISMATCH",
            403
        );
    }
    if (provider && String(record.key_provider || record.provider || "software").toLowerCase() !== String(provider).toLowerCase()) {
        throw new CitizenSigningError(
            "Citizen certificate provider does not match the requested provider",
            "CITIZEN_CERTIFICATE_PROVIDER_MISMATCH",
            409
        );
    }

    const certificatePath = resolveBackendPath(record.certificate_path);
    const rootPath = resolveBackendPath(record.root_ca_certificate_path || PKI_ROOT_CA_CERT_PATH);
    if (!fs.existsSync(certificatePath) || !fs.existsSync(rootPath)) {
        throw new CitizenSigningError(
            "Citizen certificate material is missing",
            "CITIZEN_CERTIFICATE_FILE_MISSING",
            500
        );
    }
    const certificatePem = fs.readFileSync(certificatePath, "utf8");
    const rootPem = fs.readFileSync(rootPath, "utf8");
    const certificate = new X509Certificate(certificatePem);
    const root = new X509Certificate(rootPem);
    const fingerprint = normalizeFingerprint(certificate.fingerprint256);
    if (fingerprint !== normalizeFingerprint(record.fingerprint_sha256)) {
        throw new CitizenSigningError(
            "Citizen certificate fingerprint does not match the registry",
            "CITIZEN_CERTIFICATE_TAMPERED",
            403
        );
    }
    if (!certificate.verify(root.publicKey) || certificate.issuer !== root.subject) {
        throw new CitizenSigningError(
            "Citizen certificate is not trusted by the NT219 Test Root CA",
            "UNTRUSTED_CERTIFICATE_ISSUER",
            403
        );
    }
    if (parseUid(certificate.subject) !== String(user.citizen_id)) {
        throw new CitizenSigningError(
            "Citizen certificate UID does not match the citizen account",
            "CITIZEN_CERTIFICATE_OWNER_MISMATCH",
            403
        );
    }

    const revocation = requireRevocationGood
        ? checkCertificateStatusWithOcsp({ certificateRecord: record, includeDer: true, now })
        : null;
    if (requireRevocationGood && (!revocation.trusted || revocation.revoked || revocation.status !== "good")) {
        throw new CitizenSigningError(
            "Citizen certificate revocation status is not good",
            revocation.revoked ? "CITIZEN_CERTIFICATE_REVOKED" : "CITIZEN_REVOCATION_STATUS_UNTRUSTED",
            403
        );
    }

    return {
        user,
        certificateRecord: record,
        certificatePem,
        certificate,
        rootPem,
        revocation,
    };
}
