import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
    PKI_ROOT_CA_CERT_PATH,
    PKI_CRL_PATH,
    PKI_CRL_CONFIG_PATH,
    PKI_REQUIRE_CRL,
    OPENSSL_BIN,
} from "../config/env.config.js";
import { listCertificates } from "../services/certificate.repository.js";
import { atomicWriteJsonSync } from "../utils/atomic-file.util.js";
import {
    OfficerCertificateError,
    normalizeFingerprint,
} from "./x509-pki.service.js";

const ALLOWED_REVOCATION_REASONS = new Set([
    "unspecified",
    "keyCompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
]);

export function normalizeCertificateSerial(value = "") {
    const normalized = String(value)
        .replace(/[^0-9a-f]/gi, "")
        .toUpperCase();

    if (!normalized) {
        return "00";
    }

    return normalized.length % 2 === 0
        ? normalized
        : `0${normalized}`;
}

export function normalizeRevocationReason(value = "unspecified") {
    const reason = String(value || "unspecified").trim();
    if (!ALLOWED_REVOCATION_REASONS.has(reason)) {
        throw new OfficerCertificateError(
            `Unsupported revocation reason: ${reason}`,
            "INVALID_REVOCATION_REASON",
            400
        );
    }
    return reason;
}

function resolveFromBackend(value) {
    return path.resolve(process.cwd(), value);
}

function runOpenSsl(args, { capture = true } = {}) {
    const result = spawnSync(OPENSSL_BIN, args, {
        cwd: process.cwd(),
        encoding: "utf8",
        windowsHide: true,
        stdio: capture ? "pipe" : "inherit",
    });

    if (result.error) {
        throw new OfficerCertificateError(
            `Unable to run OpenSSL: ${result.error.message}`,
            "OPENSSL_NOT_AVAILABLE",
            500
        );
    }

    if (result.status !== 0) {
        const details = String(result.stderr || result.stdout || "").trim();
        throw new OfficerCertificateError(
            `OpenSSL command failed: ${details || `exit ${result.status}`}`,
            "OPENSSL_COMMAND_FAILED",
            500
        );
    }

    return String(result.stdout || "").trim();
}

function toOpenSslUtcTime(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        throw new Error(`Invalid certificate date: ${value}`);
    }
    const yy = String(date.getUTCFullYear() % 100).padStart(2, "0");
    const MM = String(date.getUTCMonth() + 1).padStart(2, "0");
    const dd = String(date.getUTCDate()).padStart(2, "0");
    const hh = String(date.getUTCHours()).padStart(2, "0");
    const mm = String(date.getUTCMinutes()).padStart(2, "0");
    const ss = String(date.getUTCSeconds()).padStart(2, "0");
    return `${yy}${MM}${dd}${hh}${mm}${ss}Z`;
}

function toOpenSslSubject(subject = "") {
    const fields = String(subject)
        .split(/\r?\n|,(?=[A-Za-z][A-Za-z0-9]*=)/)
        .map((item) => item.trim())
        .filter(Boolean)
        .map((item) => item.replaceAll("/", "\\/"));
    return `/${fields.join("/")}`;
}

export function buildOpenSslIndex(certificates, { now = new Date() } = {}) {
    if (!Array.isArray(certificates)) {
        throw new Error("certificates must be an array");
    }

    return certificates.map((certificate) => {
        const expiry = toOpenSslUtcTime(certificate.valid_to);
        const serial = normalizeCertificateSerial(certificate.serial_number);
        const subject = toOpenSslSubject(certificate.subject);
        const revoked = certificate.status === "revoked" || Boolean(certificate.revoked_at);
        const expired = certificate.status === "expired" || new Date(certificate.valid_to) < new Date(now);

        if (revoked) {
            const revokedAt = toOpenSslUtcTime(
                certificate.revoked_at || new Date(now).toISOString()
            );
            const reason = normalizeRevocationReason(
                certificate.revocation_reason || "unspecified"
            );
            return `R\t${expiry}\t${revokedAt},${reason}\t${serial}\tunknown\t${subject}`;
        }

        const status = expired ? "E" : "V";
        return `${status}\t${expiry}\t\t${serial}\tunknown\t${subject}`;
    }).join("\n") + (certificates.length ? "\n" : "");
}

export function prepareOpenSslCaDatabase(certificates = listCertificates()) {
    const configPath = resolveFromBackend(PKI_CRL_CONFIG_PATH);
    const rootDirectory = path.dirname(resolveFromBackend(PKI_ROOT_CA_CERT_PATH));
    const databaseDirectory = path.join(rootDirectory, "ca-database");
    const newCertificatesDirectory = path.join(databaseDirectory, "newcerts");
    const indexPath = path.join(databaseDirectory, "index.txt");
    const attrPath = path.join(databaseDirectory, "index.txt.attr");
    const crlNumberPath = path.join(databaseDirectory, "crlnumber");

    if (!fs.existsSync(configPath)) {
        throw new OfficerCertificateError(
            `OpenSSL CA configuration not found: ${configPath}`,
            "CRL_CONFIG_NOT_FOUND",
            500
        );
    }

    fs.mkdirSync(newCertificatesDirectory, { recursive: true });
    fs.writeFileSync(indexPath, buildOpenSslIndex(certificates), "utf8");
    fs.writeFileSync(attrPath, "unique_subject = no\n", "utf8");
    if (!fs.existsSync(crlNumberPath)) {
        fs.writeFileSync(crlNumberPath, "1000\n", "ascii");
    }

    return {
        configPath,
        rootDirectory,
        databaseDirectory,
        indexPath,
        crlNumberPath,
    };
}

export function generateCertificateRevocationList({
    certificates = listCertificates(),
    outputPath = PKI_CRL_PATH,
} = {}) {
    const prepared = prepareOpenSslCaDatabase(certificates);
    const resolvedOutput = resolveFromBackend(outputPath);
    fs.mkdirSync(path.dirname(resolvedOutput), { recursive: true });

    runOpenSsl([
        "ca",
        "-gencrl",
        "-config", prepared.configPath,
        "-out", resolvedOutput,
        "-batch",
    ], { capture: true });

    const verification = verifyCertificateRevocationList({
        crlPath: outputPath,
        throwOnError: true,
    });

    const metadataPath = path.join(
        path.dirname(resolvedOutput),
        "root-ca-crl-metadata.json"
    );
    atomicWriteJsonSync(metadataPath, {
        generated_at: new Date().toISOString(),
        crl_path: outputPath,
        certificate_count: certificates.length,
        revoked_certificate_count: certificates.filter(
            (item) => item.status === "revoked" || item.revoked_at
        ).length,
        ...verification,
    }, { backup: true });

    return verification;
}

export function parseCrlText(text = "") {
    const serials = [...String(text).matchAll(/Serial Number:\s*([0-9A-Fa-f]+)/g)]
        .map((match) => normalizeCertificateSerial(match[1]));
    const issuer = String(text).match(/Issuer:\s*(.+)/)?.[1]?.trim() || null;
    const lastUpdate = String(text).match(/Last Update:\s*(.+)/)?.[1]?.trim() || null;
    const nextUpdate = String(text).match(/Next Update:\s*(.+)/)?.[1]?.trim() || null;
    const crlNumberText = String(text).match(/X509v3 CRL Number:\s*\n\s*([0-9]+)/)?.[1] || null;

    return {
        issuer,
        last_update: lastUpdate,
        next_update: nextUpdate,
        crl_number: crlNumberText ? Number.parseInt(crlNumberText, 10) : null,
        revoked_serials: serials,
        revoked_count: serials.length,
    };
}

export function verifyCertificateRevocationList({
    crlPath = PKI_CRL_PATH,
    rootCertPath = PKI_ROOT_CA_CERT_PATH,
    throwOnError = false,
} = {}) {
    const resolvedCrl = resolveFromBackend(crlPath);
    const resolvedRoot = resolveFromBackend(rootCertPath);

    if (!fs.existsSync(resolvedCrl)) {
        const result = {
            available: false,
            signature_valid: false,
            reason: "CRL_NOT_FOUND",
            crl_path: resolvedCrl,
        };
        if (throwOnError) {
            throw new OfficerCertificateError(
                `CRL file not found: ${resolvedCrl}`,
                result.reason,
                500
            );
        }
        return result;
    }

    if (!fs.existsSync(resolvedRoot)) {
        const result = {
            available: true,
            signature_valid: false,
            reason: "ROOT_CA_CERTIFICATE_NOT_FOUND",
            crl_path: resolvedCrl,
        };
        if (throwOnError) {
            throw new OfficerCertificateError(
                `Root CA certificate not found: ${resolvedRoot}`,
                result.reason,
                500
            );
        }
        return result;
    }

    try {
        runOpenSsl([
            "crl", "-in", resolvedCrl,
            "-noout", "-verify",
            "-CAfile", resolvedRoot,
        ]);
        const text = runOpenSsl([
            "crl", "-in", resolvedCrl,
            "-text", "-noout",
        ]);
        const parsed = parseCrlText(text);
        const fingerprint = runOpenSsl([
            "crl", "-in", resolvedCrl,
            "-noout", "-fingerprint", "-sha256",
        ]).split("=").at(-1)?.trim() || "";

        return {
            available: true,
            signature_valid: true,
            reason: "CRL_VALID",
            crl_path: resolvedCrl,
            fingerprint_sha256: normalizeFingerprint(fingerprint),
            ...parsed,
        };
    } catch (error) {
        const result = {
            available: true,
            signature_valid: false,
            reason: "CRL_SIGNATURE_INVALID",
            crl_path: resolvedCrl,
            error: error.message,
            revoked_serials: [],
            revoked_count: 0,
        };
        if (throwOnError) {
            throw new OfficerCertificateError(
                error.message,
                result.reason,
                409
            );
        }
        return result;
    }
}

export function checkCertificateRevocation({
    certificateRecord = null,
    serialNumber = certificateRecord?.serial_number || "",
    requireCrl = PKI_REQUIRE_CRL,
} = {}) {
    const crl = verifyCertificateRevocationList();

    if (requireCrl && !crl.available) {
        return {
            checked: false,
            trusted: false,
            revoked: false,
            reason: "CRL_NOT_FOUND",
            crl,
        };
    }
    if (requireCrl && !crl.signature_valid) {
        return {
            checked: true,
            trusted: false,
            revoked: false,
            reason: "CRL_SIGNATURE_INVALID",
            crl,
        };
    }

    const serial = normalizeCertificateSerial(serialNumber);
    const registryRevoked = Boolean(
        certificateRecord &&
        (certificateRecord.status === "revoked" || certificateRecord.revoked_at)
    );
    const crlRevoked = Boolean(
        crl.signature_valid && crl.revoked_serials?.includes(serial)
    );
    const outOfSync = registryRevoked && crl.signature_valid && !crlRevoked;
    const revoked = registryRevoked || crlRevoked;

    return {
        checked: crl.available && crl.signature_valid,
        trusted: !outOfSync && (!requireCrl || crl.signature_valid),
        revoked,
        registry_revoked: registryRevoked,
        crl_revoked: crlRevoked,
        out_of_sync: outOfSync,
        reason: outOfSync
            ? "CRL_OUT_OF_SYNC"
            : revoked
                ? "OFFICER_CERTIFICATE_REVOKED"
                : "CERTIFICATE_NOT_REVOKED",
        revoked_at: certificateRecord?.revoked_at || null,
        revocation_reason: certificateRecord?.revocation_reason || null,
        serial_number: serial,
        crl,
    };
}

export function assertCertificateNotRevoked(certificateRecord) {
    const status = checkCertificateRevocation({ certificateRecord });

    if (!status.trusted) {
        throw new OfficerCertificateError(
            status.reason === "CRL_OUT_OF_SYNC"
                ? "Certificate registry and CRL are out of sync"
                : "Certificate Revocation List is unavailable or invalid",
            status.reason,
            409
        );
    }

    if (status.revoked) {
        throw new OfficerCertificateError(
            "Officer certificate has been revoked",
            "OFFICER_CERTIFICATE_REVOKED",
            403
        );
    }

    return status;
}

export { ALLOWED_REVOCATION_REASONS };
