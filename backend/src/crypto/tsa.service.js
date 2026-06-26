import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
    OPENSSL_BIN,
    PKI_ROOT_CA_CERT_PATH,
    PKI_TSA_CERT_PATH,
    PKI_TSA_KEY_PATH,
    PKI_TSA_DEFAULT_POLICY,
} from "../config/env.config.js";
import { OfficerCertificateError } from "./x509-pki.service.js";

function resolveFromBackend(value) {
    return path.resolve(process.cwd(), value);
}

function runOpenSsl(args) {
    const environment = { ...process.env };
    const configuredOpenSslConf = environment.OPENSSL_CONF;
    if (!configuredOpenSslConf || !fs.existsSync(configuredOpenSslConf)) {
        environment.OPENSSL_CONF = path.resolve(process.cwd(), "../pki/config/openssl-base.cnf");
    }
    const result = spawnSync(OPENSSL_BIN, args, {
        cwd: process.cwd(),
        encoding: "utf8",
        windowsHide: true,
        stdio: "pipe",
        env: environment,
    });
    if (result.error) {
        throw new OfficerCertificateError(
            `Unable to run OpenSSL: ${result.error.message}`,
            "TSA_UNAVAILABLE",
            503
        );
    }
    if (result.status !== 0) {
        const details = String(result.stderr || result.stdout || "").trim();
        throw new OfficerCertificateError(
            details || `OpenSSL TSA command failed with exit ${result.status}`,
            "TSA_OPERATION_FAILED",
            503
        );
    }
    return `${result.stdout || ""}\n${result.stderr || ""}`.trim();
}

function dynamicTsaConfig(tempDirectory) {
    const tsaCert = resolveFromBackend(PKI_TSA_CERT_PATH);
    const tsaKey = resolveFromBackend(PKI_TSA_KEY_PATH);
    const rootCert = resolveFromBackend(PKI_ROOT_CA_CERT_PATH);
    const chainPath = path.join(tempDirectory, "tsa-chain.pem");
    const serialPath = path.join(tempDirectory, "tsa-serial");
    const configPath = path.join(tempDirectory, "tsa.cnf");
    fs.writeFileSync(
        chainPath,
        `${fs.readFileSync(tsaCert, "utf8").trim()}\n${fs.readFileSync(rootCert, "utf8").trim()}\n`,
        "ascii"
    );
    fs.writeFileSync(serialPath, `${crypto.randomBytes(16).toString("hex").toUpperCase()}\n`, "ascii");
    const normalize = (p) => p.replace(/\\/g, "/");
    fs.writeFileSync(configPath, `[ tsa ]
default_tsa = tsa_config1

[ tsa_config1 ]
serial = ${normalize(serialPath)}
crypto_device = builtin
signer_cert = ${normalize(tsaCert)}
certs = ${normalize(chainPath)}
signer_key = ${normalize(tsaKey)}
signer_digest = sha256
default_policy = ${PKI_TSA_DEFAULT_POLICY}
digests = sha256
accuracy = secs:1
clock_precision_digits = 3
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
`, "utf8");
    return { configPath, tsaCert, rootCert };
}

function parseTimestampText(text = "") {
    const value = String(text);
    const timestampText = value.match(/Time stamp:\s*(.+)/i)?.[1]?.trim() || null;
    const parsedTime = timestampText ? new Date(timestampText) : null;
    const imprintLines = value.match(/Message data:\s*([\s\S]*?)Serial number:/i)?.[1] || "";
    const imprint = imprintLines
        .split(/\r?\n/)
        .map((line) => line.match(/^[\s]*[0-9a-f]+\s*-\s*([^\r\n]+?)(?:\s{2,}[^0-9a-f].*)?$/i)?.[1] || "")
        .flatMap((line) => line.match(/[0-9a-f]{2}/gi) || [])
        .join("")
        .toUpperCase();
    return {
        status: value.match(/Status:\s*([^\r\n]+)/i)?.[1]?.trim() || null,
        policy_oid: value.match(/Policy OID:\s*([^\r\n]+)/i)?.[1]?.trim() || null,
        hash_algorithm: value.match(/Hash Algorithm:\s*([^\r\n]+)/i)?.[1]?.trim() || null,
        message_imprint_sha256: imprint || null,
        serial_number: value.match(/Serial number:\s*([^\r\n]+)/i)?.[1]?.trim() || null,
        timestamp: parsedTime && !Number.isNaN(parsedTime.getTime()) ? parsedTime.toISOString() : timestampText,
        tsa_subject: value.match(/TSA:\s*([^\r\n]+)/i)?.[1]?.trim() || null,
    };
}

export function getTsaStatus() {
    const certPath = resolveFromBackend(PKI_TSA_CERT_PATH);
    const keyPath = resolveFromBackend(PKI_TSA_KEY_PATH);
    const rootPath = resolveFromBackend(PKI_ROOT_CA_CERT_PATH);
    return {
        ready: fs.existsSync(certPath) && fs.existsSync(keyPath) && fs.existsSync(rootPath),
        tsa_certificate_path: certPath,
        tsa_key_path: keyPath,
        root_ca_path: rootPath,
        policy_oid: PKI_TSA_DEFAULT_POLICY,
        protocol: "RFC 3161",
        digest_algorithm: "SHA-256",
        lab_only: true,
    };
}

export function createTimestampToken({
    dataBuffer,
    outputDirectory = null,
    baseName = "timestamp",
} = {}) {
    const data = Buffer.isBuffer(dataBuffer) ? dataBuffer : Buffer.from(dataBuffer || "");
    if (data.length === 0) {
        throw new OfficerCertificateError("Timestamp input is empty", "TSA_INPUT_REQUIRED", 400);
    }
    const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-tsa-"));
    const dataPath = path.join(tempDirectory, "data.bin");
    const requestPath = path.join(tempDirectory, "request.tsq");
    const responsePath = path.join(tempDirectory, "response.tsr");
    try {
        const { configPath, tsaCert, rootCert } = dynamicTsaConfig(tempDirectory);
        fs.writeFileSync(dataPath, data);
        runOpenSsl(["ts", "-query", "-data", dataPath, "-sha256", "-cert", "-out", requestPath]);
        runOpenSsl(["ts", "-reply", "-queryfile", requestPath, "-config", configPath, "-section", "tsa_config1", "-out", responsePath]);
        runOpenSsl(["ts", "-verify", "-data", dataPath, "-in", responsePath, "-CAfile", rootCert, "-untrusted", tsaCert]);
        const text = runOpenSsl(["ts", "-reply", "-in", responsePath, "-text"]);
        const parsed = parseTimestampText(text);
        const request = fs.readFileSync(requestPath);
        const response = fs.readFileSync(responsePath);
        let saved = null;
        if (outputDirectory) {
            fs.mkdirSync(outputDirectory, { recursive: true });
            const savedRequest = path.join(outputDirectory, `${baseName}.tsq`);
            const savedResponse = path.join(outputDirectory, `${baseName}.tsr`);
            fs.copyFileSync(requestPath, savedRequest);
            fs.copyFileSync(responsePath, savedResponse);
            saved = { request_path: savedRequest, response_path: savedResponse };
        }
        return {
            protocol: "RFC3161",
            valid: true,
            reason: "TIMESTAMP_VALID",
            created_at: new Date().toISOString(),
            input_sha256: crypto.createHash("sha256").update(data).digest("hex").toUpperCase(),
            request_der_base64: request.toString("base64"),
            response_der_base64: response.toString("base64"),
            ...parsed,
            ...saved,
        };
    } finally {
        fs.rmSync(tempDirectory, { recursive: true, force: true });
    }
}

export function verifyTimestampToken({ dataBuffer, responseDerBase64, responsePath: suppliedPath } = {}) {
    const data = Buffer.isBuffer(dataBuffer) ? dataBuffer : Buffer.from(dataBuffer || "");
    const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-tsa-verify-"));
    const dataPath = path.join(tempDirectory, "data.bin");
    const responsePath = path.join(tempDirectory, "response.tsr");
    try {
        fs.writeFileSync(dataPath, data);
        if (suppliedPath) fs.copyFileSync(suppliedPath, responsePath);
        else fs.writeFileSync(responsePath, Buffer.from(String(responseDerBase64 || ""), "base64"));
        const tsaCert = resolveFromBackend(PKI_TSA_CERT_PATH);
        const rootCert = resolveFromBackend(PKI_ROOT_CA_CERT_PATH);
        runOpenSsl(["ts", "-verify", "-data", dataPath, "-in", responsePath, "-CAfile", rootCert, "-untrusted", tsaCert]);
        const text = runOpenSsl(["ts", "-reply", "-in", responsePath, "-text"]);
        return {
            valid: true,
            reason: "TIMESTAMP_VALID",
            input_sha256: crypto.createHash("sha256").update(data).digest("hex").toUpperCase(),
            ...parseTimestampText(text),
        };
    } catch (error) {
        return {
            valid: false,
            reason: "TIMESTAMP_INVALID",
            error: error.message,
        };
    } finally {
        fs.rmSync(tempDirectory, { recursive: true, force: true });
    }
}
