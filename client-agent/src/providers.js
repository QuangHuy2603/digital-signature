import crypto, { X509Certificate } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

function resolveProjectPath(projectRoot, value) {
    if (!value) return null;
    return path.isAbsolute(value) ? value : path.resolve(projectRoot, value);
}

/*
 * Certificate records from backend use paths relative to backend,
 * for example ../pki/citizens/...
 *
 * Client Agent registry records use paths relative to project root,
 * for example pki/citizens/...
 *
 * Support both formats.
 */
function resolveStoredPath(projectRoot, value) {
    if (!value) return null;
    if (path.isAbsolute(value)) return value;

    const projectRelative = path.resolve(projectRoot, value);
    if (fs.existsSync(projectRelative)) return projectRelative;

    const backendRelative = path.resolve(
        projectRoot,
        "backend",
        value,
    );

    if (fs.existsSync(backendRelative)) return backendRelative;

    return projectRelative;
}

function normalizeId(value = "") {
    return String(value).replace(/^0x/i, "").replace(/[^0-9a-f]/gi, "").toLowerCase();
}

function encodeId(value = "") {
    const normalized = normalizeId(value);
    return normalized ? normalized.match(/../g).map((item) => `%${item.toUpperCase()}`).join("") : "";
}

function command(commandName, args, { env = {}, cwd = process.cwd(), allowFailure = false } = {}) {
    const result = spawnSync(commandName, args, {
        cwd,
        encoding: "utf8",
        windowsHide: true,
        stdio: "pipe",
        env: { ...process.env, ...env },
    });
    if (!allowFailure && (result.error || result.status !== 0)) {
        const message = result.error?.message || String(result.stderr || result.stdout || `exit ${result.status}`).trim();
        const error = new Error(message);
        error.code = "CLIENT_AGENT_PKCS11_COMMAND_FAILED";
        error.status = 503;
        throw error;
    }
    return result;
}


export function validateCitizenPkcs11Binding(record = {}) {
    if ((record.signer_type || "citizen") !== "citizen") {
        const error = new Error("PKCS#11 certificate is not registered for a citizen");
        error.code = "CERTIFICATE_ROLE_MISMATCH";
        error.status = 403;
        throw error;
    }
    const missing = ["citizen_id", "certificate_id", "version", "pkcs11_token_label", "pkcs11_key_label", "pkcs11_key_id"]
        .filter((key) => !record[key]);
    if (missing.length) {
        const error = new Error(`Citizen PKCS#11 binding is incomplete: ${missing.join(", ")}`);
        error.code = "CITIZEN_PKCS11_BINDING_MISSING";
        error.status = 409;
        throw error;
    }
    if (record.pkcs11_binding_scheme && record.pkcs11_binding_scheme !== "nt219-citizen-deterministic-v1") {
        const error = new Error("Unsupported citizen PKCS#11 binding scheme");
        error.code = "CITIZEN_PKCS11_BINDING_SCHEME_UNSUPPORTED";
        error.status = 409;
        throw error;
    }
    const expectedId = crypto.createHash("sha256").update(String(record.certificate_id)).digest("hex").slice(0, 32);
    const expectedLabel = `NT219-${record.citizen_id}-SIGNING-V${record.version}`;
    if (normalizeId(record.pkcs11_key_id) !== expectedId) {
        const error = new Error("Citizen PKCS#11 key ID does not match the certificate identity");
        error.code = "CITIZEN_PKCS11_KEY_ID_MISMATCH";
        error.status = 409;
        throw error;
    }
    if (record.pkcs11_key_label !== expectedLabel) {
        const error = new Error("Citizen PKCS#11 key label does not match the citizen certificate");
        error.code = "CITIZEN_PKCS11_KEY_OWNER_MISMATCH";
        error.status = 409;
        throw error;
    }
    return { token_label: record.pkcs11_token_label, key_label: record.pkcs11_key_label, key_id: normalizeId(record.pkcs11_key_id) };
}

export function buildClientAgentPkcs11Uri(record = {}) {
    const token = record.pkcs11_token_label || process.env.CLIENT_AGENT_PKCS11_TOKEN_LABEL || "NT219-CITIZEN";
    const label = record.pkcs11_key_label || "";
    const id = encodeId(record.pkcs11_key_id || "");
    return `pkcs11:token=${encodeURIComponent(token)};object=${encodeURIComponent(label)}${id ? `;id=${id}` : ""};type=private`;
}

export function getClientAgentPkcs11Environment(projectRoot) {
    const modulePath = resolveProjectPath(projectRoot, process.env.CLIENT_AGENT_PKCS11_MODULE_PATH || process.env.SOFTHSM_PKCS11_MODULE_PATH || "");
    const configPath = resolveProjectPath(projectRoot, process.env.CLIENT_AGENT_SOFTHSM2_CONF || process.env.SOFTHSM2_CONF || "");
    const pin = process.env.CLIENT_AGENT_PKCS11_USER_PIN || process.env.SOFTHSM_USER_PIN || "";
    return {
        ...(configPath ? { SOFTHSM2_CONF: configPath } : {}),
        ...(modulePath ? { PKCS11_MODULE_PATH: modulePath, PKCS11_PROVIDER_MODULE: modulePath } : {}),
        ...(pin ? { PKCS11_PIN: pin, PKCS11_PROVIDER_PIN: pin } : {}),
    };
}

function providerArgs(projectRoot) {
    const providerName = process.env.CLIENT_AGENT_PKCS11_PROVIDER_NAME || process.env.SOFTHSM_OPENSSL_PROVIDER_NAME || "pkcs11prov";
    const providerPath = resolveProjectPath(projectRoot, process.env.CLIENT_AGENT_PKCS11_PROVIDER_PATH || process.env.SOFTHSM_PKCS11_PROVIDER_PATH || "");
    return [
        ...(providerPath ? ["-provider-path", providerPath] : []),
        "-provider", "default",
        "-provider", providerName,
    ];
}

export function getPkcs11CertificateStatus(record, projectRoot) {
    try { validateCitizenPkcs11Binding(record); } catch (error) {
        return { ready: false, configured: false, key_reference: buildClientAgentPkcs11Uri(record), error: error.message, code: error.code };
    }
    const modulePath = resolveProjectPath(projectRoot, process.env.CLIENT_AGENT_PKCS11_MODULE_PATH || process.env.SOFTHSM_PKCS11_MODULE_PATH || "");
    const providerPath = resolveProjectPath(projectRoot, process.env.CLIENT_AGENT_PKCS11_PROVIDER_PATH || process.env.SOFTHSM_PKCS11_PROVIDER_PATH || "");
    const certificatePath = resolveStoredPath(projectRoot, record.certificate_path);
    const openssl = process.env.CLIENT_AGENT_OPENSSL_BIN || process.env.OPENSSL_BIN || "openssl";
    const uri = buildClientAgentPkcs11Uri(record);
    const configured = Boolean(
        modulePath && fs.existsSync(modulePath) &&
        certificatePath && fs.existsSync(certificatePath) &&
        record.pkcs11_token_label && record.pkcs11_key_label && record.pkcs11_key_id
    );
    if (!configured) {
        return {
            ready: false,
            configured: false,
            key_reference: uri,
            error: "PKCS#11 certificate binding is incomplete",
            module_path_exists: Boolean(modulePath && fs.existsSync(modulePath)),
            provider_path_exists: Boolean(providerPath && fs.existsSync(providerPath)),
        };
    }
    const result = command(openssl, [
        "pkey",
        ...providerArgs(projectRoot),
        "-in", uri,
        "-pubout",
        "-outform", "PEM",
    ], {
        env: getClientAgentPkcs11Environment(projectRoot),
        cwd: projectRoot,
        allowFailure: true,
    });
    return {
        ready: !result.error && result.status === 0,
        configured: true,
        key_reference: uri,
        module_path_exists: true,
        provider_path_exists: Boolean(providerPath && fs.existsSync(providerPath)),
        error: !result.error && result.status === 0 ? null : String(result.stderr || result.stdout || result.error?.message || "PKCS#11 key unavailable").trim(),
    };
}

function verifyResult(canonicalPayload, signature, certificatePem) {
    const certificate = new X509Certificate(certificatePem);
    return crypto.verify("sha256", Buffer.from(canonicalPayload, "utf8"), certificate.publicKey, signature);
}

export function signCanonicalPayloadWithSoftware({ record, projectRoot, canonicalPayload }) {
    const privateKeyPath = resolveStoredPath(projectRoot, record.private_key_path);
    const certificatePath = resolveStoredPath(projectRoot, record.certificate_path);
    if (!privateKeyPath || !fs.existsSync(privateKeyPath) || !certificatePath || !fs.existsSync(certificatePath)) {
        const error = new Error("Citizen software key or certificate is unavailable");
        error.code = "CLIENT_AGENT_SOFTWARE_KEY_UNAVAILABLE";
        error.status = 409;
        throw error;
    }
    const signature = crypto.sign("sha256", Buffer.from(canonicalPayload, "utf8"), fs.readFileSync(privateKeyPath));
    const certificatePem = fs.readFileSync(certificatePath, "utf8");
    if (!verifyResult(canonicalPayload, signature, certificatePem)) {
        const error = new Error("Software provider self-verification failed");
        error.code = "CLIENT_AGENT_SIGNATURE_SELF_VERIFY_FAILED";
        error.status = 500;
        throw error;
    }
    return {
        signature,
        certificatePem,
        provider: "software",
        keyReference: `client-agent-software:${record.certificate_id}`,
        keyExportable: true,
    };
}

export function signCanonicalPayloadWithPkcs11({ record, projectRoot, canonicalPayload }) {
    validateCitizenPkcs11Binding(record);
    const status = getPkcs11CertificateStatus(record, projectRoot);
    if (!status.ready) {
        const error = new Error(`Citizen PKCS#11 key is unavailable: ${status.error || "not ready"}`);
        error.code = "CLIENT_AGENT_PKCS11_KEY_UNAVAILABLE";
        error.status = 503;
        throw error;
    }
    const certificatePath = resolveStoredPath(projectRoot, record.certificate_path);
    const certificatePem = fs.readFileSync(certificatePath, "utf8");
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-citizen-pkcs11-"));
    try {
        const inputPath = path.join(temp, "payload.txt");
        const signaturePath = path.join(temp, "signature.der");
        fs.writeFileSync(inputPath, canonicalPayload, "utf8");
        const openssl = process.env.CLIENT_AGENT_OPENSSL_BIN || process.env.OPENSSL_BIN || "openssl";
        const uri = buildClientAgentPkcs11Uri(record);
        command(openssl, [
            "dgst",
            ...providerArgs(projectRoot),
            "-sha256",
            "-sign", uri,
            "-out", signaturePath,
            inputPath,
        ], {
            env: getClientAgentPkcs11Environment(projectRoot),
            cwd: projectRoot,
        });
        const signature = fs.readFileSync(signaturePath);
        if (!verifyResult(canonicalPayload, signature, certificatePem)) {
            const error = new Error("PKCS#11 provider self-verification failed");
            error.code = "CLIENT_AGENT_SIGNATURE_SELF_VERIFY_FAILED";
            error.status = 500;
            throw error;
        }
        return {
            signature,
            certificatePem,
            provider: "pkcs11",
            keyReference: uri,
            keyExportable: false,
        };
    } finally {
        fs.rmSync(temp, { recursive: true, force: true });
    }
}

