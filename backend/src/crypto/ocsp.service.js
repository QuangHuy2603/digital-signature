import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
    OPENSSL_BIN,
    PKI_ROOT_CA_CERT_PATH,
    PKI_OCSP_RESPONDER_CERT_PATH,
    PKI_OCSP_RESPONDER_KEY_PATH,
    PKI_OCSP_RESPONSE_TTL_SECONDS,
    PKI_OCSP_ALLOW_CRL_FALLBACK,
} from "../config/env.config.js";
import { listCertificates, findCertificateById } from "../services/certificate.repository.js";
import {
    buildOpenSslIndex,
    checkCertificateRevocation,
    normalizeCertificateSerial,
} from "./crl.service.js";
import { OfficerCertificateError } from "./x509-pki.service.js";

function resolveFromBackend(value) {
    return path.resolve(process.cwd(), value);
}

function runOpenSsl(args) {
    const result = spawnSync(OPENSSL_BIN, args, {
        cwd: process.cwd(),
        encoding: "utf8",
        windowsHide: true,
        stdio: "pipe",
    });
    if (result.error) {
        throw new OfficerCertificateError(
            `Unable to run OpenSSL: ${result.error.message}`,
            "OCSP_RESPONDER_UNAVAILABLE",
            503
        );
    }
    if (result.status !== 0) {
        const details = String(result.stderr || result.stdout || "").trim();
        throw new OfficerCertificateError(
            details || `OpenSSL OCSP command failed with exit ${result.status}`,
            "OCSP_RESPONSE_GENERATION_FAILED",
            503
        );
    }
    return `${result.stdout || ""}\n${result.stderr || ""}`.trim();
}

function parseDate(value) {
    if (!value) return null;
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

export function parseOcspResponseText(text = "") {
    const status = String(text).match(/Cert Status:\s*(good|revoked|unknown)/i)?.[1]?.toLowerCase() || "unknown";
    const producedAt = parseDate(String(text).match(/Produced At:\s*(.+)/i)?.[1]?.trim());
    const thisUpdate = parseDate(String(text).match(/This Update:\s*(.+)/i)?.[1]?.trim());
    const nextUpdate = parseDate(String(text).match(/Next Update:\s*(.+)/i)?.[1]?.trim());
    const revokedAt = parseDate(String(text).match(/Revocation Time:\s*(.+)/i)?.[1]?.trim());
    const reason = String(text).match(/Revocation Reason:\s*([^\r\n]+)/i)?.[1]?.trim() || null;
    const serial = normalizeCertificateSerial(
        String(text).match(/Serial Number:\s*([0-9A-Fa-f]+)/i)?.[1] || ""
    );
    return {
        certificate_status: status,
        serial_number: serial,
        produced_at: producedAt,
        this_update: thisUpdate,
        next_update: nextUpdate,
        revoked_at: revokedAt,
        revocation_reason: reason,
    };
}

export function getOcspResponderStatus() {
    const certPath = resolveFromBackend(PKI_OCSP_RESPONDER_CERT_PATH);
    const keyPath = resolveFromBackend(PKI_OCSP_RESPONDER_KEY_PATH);
    const rootPath = resolveFromBackend(PKI_ROOT_CA_CERT_PATH);
    return {
        ready: fs.existsSync(certPath) && fs.existsSync(keyPath) && fs.existsSync(rootPath),
        responder_certificate_path: certPath,
        responder_key_path: keyPath,
        root_ca_path: rootPath,
        response_ttl_seconds: PKI_OCSP_RESPONSE_TTL_SECONDS,
        crl_fallback_enabled: PKI_OCSP_ALLOW_CRL_FALLBACK,
        protocol: "RFC 6960 (OpenSSL-generated DER response)",
        lab_only: true,
    };
}

export function generateOcspResponse({
    serialNumber,
    certificateId = null,
    now = new Date(),
    responderCertPath = PKI_OCSP_RESPONDER_CERT_PATH,
    responderKeyPath = PKI_OCSP_RESPONDER_KEY_PATH,
    includeDer = true,
} = {}) {
    const serial = normalizeCertificateSerial(serialNumber);
    if (!serial || serial === "0") {
        throw new OfficerCertificateError("Certificate serial is required", "OCSP_SERIAL_REQUIRED", 400);
    }

    const rootPath = resolveFromBackend(PKI_ROOT_CA_CERT_PATH);
    const ocspCertPath = resolveFromBackend(responderCertPath);
    const ocspKeyPath = resolveFromBackend(responderKeyPath);
    for (const required of [rootPath, ocspCertPath, ocspKeyPath]) {
        if (!fs.existsSync(required)) {
            throw new OfficerCertificateError(
                `OCSP material not found: ${required}`,
                "OCSP_RESPONDER_UNAVAILABLE",
                503
            );
        }
    }

    const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-ocsp-"));
    const requestPath = path.join(tempDirectory, "request.der");
    const responsePath = path.join(tempDirectory, "response.der");
    const indexPath = path.join(tempDirectory, "index.txt");

    try {
        fs.writeFileSync(indexPath, buildOpenSslIndex(listCertificates(), { now }), "utf8");
        runOpenSsl([
            "ocsp",
            "-issuer", rootPath,
            "-serial", `0x${serial}`,
            "-reqout", requestPath,
        ]);
        const minutes = Math.max(1, Math.ceil(PKI_OCSP_RESPONSE_TTL_SECONDS / 60));
        runOpenSsl([
            "ocsp",
            "-index", indexPath,
            "-rsigner", ocspCertPath,
            "-rkey", ocspKeyPath,
            "-CA", rootPath,
            "-reqin", requestPath,
            "-respout", responsePath,
            "-nmin", String(minutes),
            "-resp_key_id",
        ]);
        runOpenSsl([
            "ocsp",
            "-respin", responsePath,
            "-reqin", requestPath,
            "-CAfile", rootPath,
            "-verify_other", ocspCertPath,
            "-trust_other",
        ]);
        const text = runOpenSsl(["ocsp", "-respin", responsePath, "-text", "-noverify"]);
        const parsed = parseOcspResponseText(text);
        const referenceTime = new Date(now);
        const stale = Boolean(parsed.next_update && new Date(parsed.next_update) < referenceTime);
        const record = certificateId ? findCertificateById(certificateId) : listCertificates().find(
            (item) => normalizeCertificateSerial(item.serial_number) === serial
        );

        return {
            protocol: "RFC6960",
            response_status: "successful",
            response_signature_valid: true,
            stale,
            trusted: !stale,
            certificate_id: record?.certificate_id || certificateId || null,
            officer_id: record?.officer_id || null,
            responder_subject: "CN=NT219 OCSP Responder",
            generated_at: new Date().toISOString(),
            ...parsed,
            request_der_base64: includeDer ? fs.readFileSync(requestPath).toString("base64") : undefined,
            response_der_base64: includeDer ? fs.readFileSync(responsePath).toString("base64") : undefined,
        };
    } finally {
        fs.rmSync(tempDirectory, { recursive: true, force: true });
    }
}

export function verifyOcspResponse({
    requestDerBase64,
    responseDerBase64,
    now = new Date(),
} = {}) {
    const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-ocsp-verify-"));
    const requestPath = path.join(tempDirectory, "request.der");
    const responsePath = path.join(tempDirectory, "response.der");
    try {
        fs.writeFileSync(requestPath, Buffer.from(String(requestDerBase64 || ""), "base64"));
        fs.writeFileSync(responsePath, Buffer.from(String(responseDerBase64 || ""), "base64"));
        const rootPath = resolveFromBackend(PKI_ROOT_CA_CERT_PATH);
        const certPath = resolveFromBackend(PKI_OCSP_RESPONDER_CERT_PATH);
        runOpenSsl([
            "ocsp", "-respin", responsePath, "-reqin", requestPath,
            "-CAfile", rootPath, "-verify_other", certPath, "-trust_other",
        ]);
        const text = runOpenSsl(["ocsp", "-respin", responsePath, "-text", "-noverify"]);
        const parsed = parseOcspResponseText(text);
        const stale = Boolean(parsed.next_update && new Date(parsed.next_update) < new Date(now));
        return {
            valid: !stale,
            response_signature_valid: true,
            stale,
            reason: stale ? "OCSP_RESPONSE_STALE" : "OCSP_RESPONSE_VALID",
            ...parsed,
        };
    } catch (error) {
        return {
            valid: false,
            response_signature_valid: false,
            stale: false,
            reason: "OCSP_RESPONSE_SIGNATURE_INVALID",
            error: error.message,
        };
    } finally {
        fs.rmSync(tempDirectory, { recursive: true, force: true });
    }
}

export function checkCertificateStatusWithOcsp({
    certificateRecord,
    serialNumber = certificateRecord?.serial_number,
    allowCrlFallback = PKI_OCSP_ALLOW_CRL_FALLBACK,
    includeDer = true,
    now = new Date(),
    responderCertPath,
    responderKeyPath,
} = {}) {
    try {
        const ocsp = generateOcspResponse({
            serialNumber,
            certificateId: certificateRecord?.certificate_id || null,
            now,
            includeDer,
            responderCertPath,
            responderKeyPath,
        });
        return {
            checked: true,
            source: "OCSP",
            trusted: ocsp.trusted,
            status: ocsp.certificate_status,
            revoked: ocsp.certificate_status === "revoked",
            unknown: ocsp.certificate_status === "unknown",
            reason: ocsp.stale
                ? "OCSP_RESPONSE_STALE"
                : ocsp.certificate_status === "revoked"
                    ? "OCSP_CERTIFICATE_REVOKED"
                    : ocsp.certificate_status === "unknown"
                        ? "OCSP_CERTIFICATE_UNKNOWN"
                        : "OCSP_CERTIFICATE_GOOD",
            ocsp,
            crl: null,
        };
    } catch (error) {
        if (!allowCrlFallback) throw error;
        const crl = checkCertificateRevocation({ certificateRecord, serialNumber });
        return {
            checked: crl.checked,
            source: "CRL_FALLBACK",
            trusted: crl.trusted,
            status: crl.revoked ? "revoked" : "good",
            revoked: crl.revoked,
            unknown: false,
            reason: crl.revoked ? "OCSP_UNAVAILABLE_CERTIFICATE_REVOKED" : "OCSP_UNAVAILABLE_CRL_FALLBACK_GOOD",
            ocsp: {
                available: false,
                response_signature_valid: false,
                reason: error.code || "OCSP_RESPONDER_UNAVAILABLE",
                error: error.message,
            },
            crl,
        };
    }
}

export function assertCertificateGoodViaOcsp(certificateRecord) {
    const result = checkCertificateStatusWithOcsp({ certificateRecord });
    if (!result.trusted) {
        throw new OfficerCertificateError(
            "Certificate revocation status is not trusted",
            result.reason || "OCSP_STATUS_NOT_TRUSTED",
            503
        );
    }
    if (result.revoked) {
        throw new OfficerCertificateError(
            `Officer certificate is revoked: ${certificateRecord?.certificate_id || "unknown"}`,
            "OCSP_CERTIFICATE_REVOKED",
            403
        );
    }
    if (result.unknown) {
        throw new OfficerCertificateError(
            "Officer certificate status is unknown",
            "OCSP_CERTIFICATE_UNKNOWN",
            403
        );
    }
    return result;
}
