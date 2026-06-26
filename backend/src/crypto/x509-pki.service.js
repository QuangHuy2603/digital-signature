import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import {
    X509Certificate,
    createPrivateKey,
    sign as cryptoSign,
    verify as cryptoVerify,
} from "node:crypto";
import {
    PKI_ROOT_CA_CERT_PATH,
    PKI_OFFICER_CERT_PATH,
    PKI_OFFICER_PRIVATE_KEY_PATH,
    PKI_OFFICER_CERT_FINGERPRINT_SHA256,
} from "../config/env.config.js";

export class OfficerCertificateError extends Error {
    constructor(message, code, status = 500) {
        super(message);
        this.name = "OfficerCertificateError";
        this.code = code;
        this.status = status;
    }
}

export const normalizeFingerprint = (value = "") => String(value)
    .replace(/:/g, "")
    .replace(/\s/g, "")
    .toUpperCase();

export const resolveFromBackend = (value) => path.resolve(process.cwd(), value);

export function readRequiredPkiFile(filePath, code) {
    const resolved = resolveFromBackend(filePath);
    if (!fs.existsSync(resolved)) {
        throw new OfficerCertificateError(
            `Required PKI file was not found: ${resolved}`,
            code,
            500
        );
    }
    return {
        resolved,
        content: fs.readFileSync(resolved, "utf8"),
    };
}

export function parseCertificate(pem, code = "CERTIFICATE_VERIFICATION_FAILED") {
    try {
        return new X509Certificate(pem);
    } catch (error) {
        throw new OfficerCertificateError(
            `Unable to parse X.509 certificate: ${error.message}`,
            code,
            409
        );
    }
}

function ensureValidAt(certificate, now = new Date()) {
    const validFrom = new Date(certificate.validFrom);
    const validTo = new Date(certificate.validTo);
    const current = new Date(now);

    if (current < validFrom) {
        throw new OfficerCertificateError(
            "Officer certificate is not valid yet",
            "OFFICER_CERTIFICATE_NOT_YET_VALID",
            409
        );
    }

    if (current > validTo) {
        throw new OfficerCertificateError(
            "Officer certificate has expired",
            "OFFICER_CERTIFICATE_EXPIRED",
            409
        );
    }
}

function extractOfficerIdFromSan(subjectAltName = "") {
    const match = String(subjectAltName).match(
        /URI:urn:nt219:officer:([A-Z0-9-]+)/i
    );
    return match ? match[1].toUpperCase() : null;
}

function extractEmailFromSan(subjectAltName = "") {
    const match = String(subjectAltName).match(/email:([^,\s]+)/i);
    return match ? match[1].trim().toLowerCase() : null;
}

export function certificateMetadata(certificate, rootCertificate) {
    const publicKey = certificate.publicKey;
    const publicKeyDetails = publicKey.asymmetricKeyDetails || {};
    const subjectAltName = certificate.subjectAltName || "";

    return {
        subject: certificate.subject,
        issuer: certificate.issuer,
        serial_number: certificate.serialNumber,
        valid_from: new Date(certificate.validFrom).toISOString(),
        valid_to: new Date(certificate.validTo).toISOString(),
        fingerprint_sha256: normalizeFingerprint(certificate.fingerprint256),
        root_ca_subject: rootCertificate.subject,
        root_ca_fingerprint_sha256: normalizeFingerprint(rootCertificate.fingerprint256),
        public_key_type: publicKey.asymmetricKeyType || null,
        named_curve: publicKeyDetails.namedCurve || null,
        subject_alt_name: subjectAltName,
        officer_id: extractOfficerIdFromSan(subjectAltName),
        email: extractEmailFromSan(subjectAltName),
        chain_valid: true,
    };
}

/**
 * Validate one officer leaf certificate against the trusted lab Root CA.
 * multi-officer PKI accepts a different expected fingerprint for every officer.
 */
export function verifyOfficerCertificate({
    officerCertificatePem,
    rootCertificatePem,
    expectedFingerprint = "",
    expectedOfficerId = "",
    expectedEmail = "",
    now = new Date(),
} = {}) {
    const officerCertificate = parseCertificate(officerCertificatePem);
    const rootCertificate = parseCertificate(rootCertificatePem);

    ensureValidAt(rootCertificate, now);
    ensureValidAt(officerCertificate, now);

    if (!rootCertificate.ca) {
        throw new OfficerCertificateError(
            "Configured trust anchor is not a CA certificate",
            "UNTRUSTED_CERTIFICATE_ISSUER",
            409
        );
    }

    const rootSelfSignatureValid = rootCertificate.verify(rootCertificate.publicKey);
    const leafSignatureValid = officerCertificate.verify(rootCertificate.publicKey);
    const issuerMatches = officerCertificate.issuer === rootCertificate.subject;

    if (!rootSelfSignatureValid || !leafSignatureValid || !issuerMatches) {
        throw new OfficerCertificateError(
            "Officer certificate was not issued by the configured NT219 Test Root CA",
            "UNTRUSTED_CERTIFICATE_ISSUER",
            409
        );
    }

    if (officerCertificate.ca) {
        throw new OfficerCertificateError(
            "Officer certificate must be an end-entity certificate",
            "CERTIFICATE_VERIFICATION_FAILED",
            409
        );
    }

    const metadata = certificateMetadata(officerCertificate, rootCertificate);
    const actualFingerprint = metadata.fingerprint_sha256;
    const normalizedExpected = normalizeFingerprint(expectedFingerprint);

    if (normalizedExpected && actualFingerprint !== normalizedExpected) {
        throw new OfficerCertificateError(
            "Officer certificate fingerprint does not match the certificate registry",
            "OFFICER_CERTIFICATE_FINGERPRINT_MISMATCH",
            409
        );
    }

    if (expectedOfficerId &&
        metadata.officer_id !== String(expectedOfficerId).trim().toUpperCase()) {
        throw new OfficerCertificateError(
            "Officer certificate does not belong to the authenticated officer",
            "OFFICER_CERTIFICATE_OWNER_MISMATCH",
            403
        );
    }

    if (expectedEmail &&
        metadata.email !== String(expectedEmail).trim().toLowerCase()) {
        throw new OfficerCertificateError(
            "Officer certificate email does not match the authenticated account",
            "OFFICER_CERTIFICATE_EMAIL_MISMATCH",
            403
        );
    }

    return {
        officerCertificate,
        rootCertificate,
        metadata,
    };
}

export function loadOfficerCertificateIdentity({
    officerCertPath = PKI_OFFICER_CERT_PATH,
    rootCertPath = PKI_ROOT_CA_CERT_PATH,
    expectedFingerprint = PKI_OFFICER_CERT_FINGERPRINT_SHA256,
    expectedOfficerId = "",
    expectedEmail = "",
    now = new Date(),
} = {}) {
    const officer = readRequiredPkiFile(
        officerCertPath,
        "OFFICER_CERTIFICATE_NOT_FOUND"
    );
    const root = readRequiredPkiFile(
        rootCertPath,
        "ROOT_CA_CERTIFICATE_NOT_FOUND"
    );

    const verified = verifyOfficerCertificate({
        officerCertificatePem: officer.content,
        rootCertificatePem: root.content,
        expectedFingerprint,
        expectedOfficerId,
        expectedEmail,
        now,
    });

    return {
        ...verified,
        officerCertificatePem: officer.content,
        rootCertificatePem: root.content,
        officerCertificatePath: officer.resolved,
        rootCertificatePath: root.resolved,
    };
}

export function signPayloadWithOfficerCertificate(payload, {
    officerCertPath = PKI_OFFICER_CERT_PATH,
    rootCertPath = PKI_ROOT_CA_CERT_PATH,
    officerPrivateKeyPath = PKI_OFFICER_PRIVATE_KEY_PATH,
    expectedFingerprint = PKI_OFFICER_CERT_FINGERPRINT_SHA256,
    expectedOfficerId = "",
    expectedEmail = "",
    now = new Date(),
} = {}) {
    const identity = loadOfficerCertificateIdentity({
        officerCertPath,
        rootCertPath,
        expectedFingerprint,
        expectedOfficerId,
        expectedEmail,
        now,
    });
    const privateKeyFile = readRequiredPkiFile(
        officerPrivateKeyPath,
        "OFFICER_PRIVATE_KEY_NOT_FOUND"
    );

    let privateKey;
    try {
        privateKey = createPrivateKey(privateKeyFile.content);
    } catch (error) {
        throw new OfficerCertificateError(
            `Unable to load officer private key: ${error.message}`,
            "OFFICER_PRIVATE_KEY_INVALID",
            500
        );
    }

    const payloadBuffer = Buffer.from(String(payload), "utf8");
    const signature = cryptoSign("sha256", payloadBuffer, privateKey);
    const keyMatchesCertificate = cryptoVerify(
        "sha256",
        payloadBuffer,
        identity.officerCertificate.publicKey,
        signature
    );

    if (!keyMatchesCertificate) {
        throw new OfficerCertificateError(
            "Officer private key does not match the configured X.509 certificate",
            "OFFICER_CERTIFICATE_KEY_MISMATCH",
            409
        );
    }

    return {
        signature: signature.toString("base64"),
        algorithm: "ECDSA-P256-SHA256",
        certificate_pem: identity.officerCertificatePem,
        certificate_metadata: identity.metadata,
    };
}

export function verifyCertificateBackedSignature({
    payload,
    signatureBase64,
    officerCertificatePem,
    rootCertificatePem = null,
    rootCertPath = PKI_ROOT_CA_CERT_PATH,
    expectedFingerprint = "",
    expectedOfficerId = "",
    expectedEmail = "",
    now = new Date(),
} = {}) {
    try {
        let trustedRootPem = rootCertificatePem;
        if (!trustedRootPem) {
            trustedRootPem = readRequiredPkiFile(
                rootCertPath,
                "ROOT_CA_CERTIFICATE_NOT_FOUND"
            ).content;
        }

        const verified = verifyOfficerCertificate({
            officerCertificatePem,
            rootCertificatePem: trustedRootPem,
            expectedFingerprint,
            expectedOfficerId,
            expectedEmail,
            now,
        });

        const signatureValid = cryptoVerify(
            "sha256",
            Buffer.from(String(payload), "utf8"),
            verified.officerCertificate.publicKey,
            Buffer.from(signatureBase64 || "", "base64")
        );

        return {
            chain_valid: true,
            signature_valid: signatureValid,
            metadata: verified.metadata,
            reason: signatureValid
                ? "VALID_CERTIFICATE_SIGNATURE"
                : "INVALID_CERTIFICATE_SIGNATURE",
        };
    } catch (error) {
        return {
            chain_valid: false,
            signature_valid: false,
            metadata: null,
            reason: error.code || "CERTIFICATE_VERIFICATION_FAILED",
            error: error.message,
        };
    }
}

/** Consolidated PKI status helper. */
export function getConfiguredPkiStatus() {
    const identity = loadOfficerCertificateIdentity();
    return {
        status: "ready",
        certificate: identity.metadata,
        paths: {
            officer_certificate: identity.officerCertificatePath,
            root_ca_certificate: identity.rootCertificatePath,
        },
    };
}
