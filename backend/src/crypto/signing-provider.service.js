import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { OPENSSL_BIN } from "../config/env.config.js";
import { OfficerCertificateError } from "./x509-pki.service.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BACKEND_ROOT = path.resolve(__dirname, "../..");

function bool(value, fallback = false) {
    if (value === undefined || value === null || value === "") return fallback;
    return String(value).toLowerCase() === "true";
}

function resolveBackendPath(value = "") {
    if (!value) return "";
    return path.isAbsolute(value) ? value : path.resolve(BACKEND_ROOT, value);
}

function encodePkcs11Value(value = "") {
    return encodeURIComponent(String(value))
        .replaceAll("!", "%21")
        .replaceAll("'", "%27")
        .replaceAll("(", "%28")
        .replaceAll(")", "%29")
        .replaceAll("*", "%2A");
}

function normalizedPkcs11Id(value = "") {
    return String(value || "")
        .replace(/^0x/i, "")
        .replace(/[^0-9a-f]/gi, "")
        .toLowerCase();
}

function commandResult(command, args = [], { env = {}, cwd = BACKEND_ROOT } = {}) {
    return spawnSync(command, args, {
        cwd,
        encoding: "utf8",
        windowsHide: true,
        stdio: "pipe",
        env: { ...process.env, ...env },
    });
}

function commandAvailable(command, args = ["--version"]) {
    const result = commandResult(command, args);
    return !result.error && result.status === 0;
}

function safeCommandError(result) {
    return String(result?.stderr || result?.stdout || result?.error?.message || "")
        .replaceAll(process.env.SOFTHSM_USER_PIN || "__NO_PIN__", "[REDACTED]")
        .trim();
}

export function getSelectedSigningProvider() {
    return String(process.env.SIGNING_PROVIDER || "file").trim().toLowerCase();
}

export function getPkcs11KeyLabel(certificateRecord = {}) {
    return certificateRecord.pkcs11_key_label ||
        `NT219-${certificateRecord.officer_id || "OFFICER"}-${certificateRecord.certificate_id || "KEY"}`;
}

export function getPkcs11KeyId(certificateRecord = {}) {
    return normalizedPkcs11Id(certificateRecord.pkcs11_key_id || "");
}

export function buildPkcs11Uri(certificateRecord = {}, { includePin = false } = {}) {
    const label = getPkcs11KeyLabel(certificateRecord);
    const token = certificateRecord.pkcs11_token_label ||
        process.env.SOFTHSM_TOKEN_LABEL || "NT219-TSP";
    const id = getPkcs11KeyId(certificateRecord);
    const template = process.env.SOFTHSM_PKCS11_URI_TEMPLATE ||
        "pkcs11:token={token};object={label};id={id};type=private";

    let uri = template
        .replaceAll("{token}", encodePkcs11Value(token))
        .replaceAll("{label}", encodePkcs11Value(label))
        .replaceAll("{id}", id ? id.match(/../g).map((byte) => `%${byte.toUpperCase()}`).join("") : "");

    // Remove an empty id attribute when legacy records do not have a PKCS#11 id.
    uri = uri.replace(/;id=(?=;|$)/, "");

    if (includePin) {
        const pin = process.env.SOFTHSM_USER_PIN || "";
        if (pin) {
            uri += `${uri.includes("?") ? "&" : "?"}pin-value=${encodeURIComponent(pin)}`;
        }
    }
    return uri;
}

export function getPkcs11Environment() {
    const pin = process.env.SOFTHSM_USER_PIN || "";
    const modulePath = resolveBackendPath(process.env.SOFTHSM_PKCS11_MODULE_PATH || "");
    const configPath = resolveBackendPath(process.env.SOFTHSM2_CONF || "");
    return {
        ...(configPath ? { SOFTHSM2_CONF: configPath } : {}),
        ...(modulePath ? {
            PKCS11_MODULE_PATH: modulePath,
            PKCS11_PROVIDER_MODULE: modulePath,
        } : {}),
        ...(pin ? {
            PKCS11_PIN: pin,
            PKCS11_PROVIDER_PIN: pin,
        } : {}),
    };
}

function providerBaseArgs() {
    const providerName = process.env.SOFTHSM_OPENSSL_PROVIDER_NAME || "pkcs11prov";
    const providerPath = resolveBackendPath(process.env.SOFTHSM_PKCS11_PROVIDER_PATH || "");
    const args = [];
    if (providerPath) args.push("-provider-path", providerPath);
    args.push("-provider", "default", "-provider", providerName);
    return args;
}

export function resolvePkcs11KeyArguments(certificateRecord = {}, {
    keyOption = "-inkey",
} = {}) {
    const mode = String(process.env.SOFTHSM_OPENSSL_MODE || "provider").trim().toLowerCase();
    const pinMode = String(process.env.SOFTHSM_PIN_MODE || "environment").trim().toLowerCase();
    const uri = buildPkcs11Uri(certificateRecord, { includePin: pinMode === "uri" });
    const environment = getPkcs11Environment();

    if (mode === "engine") {
        return {
            mode,
            uri,
            args: [
                "-engine", process.env.SOFTHSM_ENGINE_ID || "pkcs11",
                "-keyform", "engine",
                keyOption, uri,
            ],
            env: environment,
        };
    }

    if (mode !== "provider") {
        throw new OfficerCertificateError(
            `Unsupported SOFTHSM_OPENSSL_MODE: ${mode}`,
            "SOFTHSM_OPENSSL_MODE_UNSUPPORTED",
            500
        );
    }

    return {
        mode,
        uri,
        args: [...providerBaseArgs(), keyOption, uri],
        env: environment,
    };
}

export function validateSoftHsmCertificateBinding(certificateRecord = {}) {
    if (certificateRecord.key_provider && certificateRecord.key_provider !== "softhsm") {
        throw new OfficerCertificateError(
            `Certificate ${certificateRecord.certificate_id || "unknown"} is not registered for SoftHSM remote signing`,
            "SOFTHSM_CERTIFICATE_PROVIDER_MISMATCH",
            409
        );
    }
    const missing = [];
    if (!certificateRecord.pkcs11_token_label) missing.push("pkcs11_token_label");
    if (!certificateRecord.pkcs11_key_label) missing.push("pkcs11_key_label");
    if (!getPkcs11KeyId(certificateRecord)) missing.push("pkcs11_key_id");
    if (missing.length) {
        throw new OfficerCertificateError(
            `SoftHSM certificate binding is incomplete: ${missing.join(", ")}`,
            "SOFTHSM_KEY_BINDING_MISSING",
            409
        );
    }

    const bindingScheme = certificateRecord.pkcs11_binding_scheme || null;
    if (bindingScheme && bindingScheme !== "nt219-deterministic-v1") {
        throw new OfficerCertificateError(
            `Unsupported PKCS#11 binding scheme: ${bindingScheme}`,
            "SOFTHSM_BINDING_SCHEME_UNSUPPORTED",
            409
        );
    }
    if (bindingScheme === "nt219-deterministic-v1") {
        const expectedId = crypto.createHash("sha256")
            .update(String(certificateRecord.certificate_id || ""))
            .digest("hex")
            .slice(0, 32);
        const expectedLabel = `NT219-${certificateRecord.officer_id}-REMOTE-V${certificateRecord.version}`;
        if (getPkcs11KeyId(certificateRecord) !== expectedId) {
            throw new OfficerCertificateError(
                "SoftHSM key ID does not match the registered certificate identity",
                "SOFTHSM_KEY_ID_MISMATCH",
                409
            );
        }
        if (certificateRecord.pkcs11_key_label !== expectedLabel) {
            throw new OfficerCertificateError(
                "SoftHSM key label does not match the registered officer certificate",
                "SOFTHSM_KEY_OWNER_MISMATCH",
                409
            );
        }
    }
    return {
        certificate_id: certificateRecord.certificate_id || null,
        token_label: certificateRecord.pkcs11_token_label,
        key_label: certificateRecord.pkcs11_key_label,
        key_id: getPkcs11KeyId(certificateRecord),
    };
}

function assertSoftHsmConfiguration() {
    const pin = process.env.SOFTHSM_USER_PIN || "";
    const modulePath = resolveBackendPath(process.env.SOFTHSM_PKCS11_MODULE_PATH || "");
    const configPath = resolveBackendPath(process.env.SOFTHSM2_CONF || "");
    if (!pin) {
        throw new OfficerCertificateError(
            "SOFTHSM_USER_PIN is required for the SoftHSM provider",
            "SOFTHSM_PIN_REQUIRED",
            503
        );
    }
    if (!modulePath || !fs.existsSync(modulePath)) {
        throw new OfficerCertificateError(
            "SOFTHSM_PKCS11_MODULE_PATH does not point to the SoftHSM PKCS#11 module",
            "SOFTHSM_MODULE_NOT_FOUND",
            503
        );
    }
    if (!configPath || !fs.existsSync(configPath)) {
        throw new OfficerCertificateError(
            "SOFTHSM2_CONF does not point to a readable SoftHSM configuration file",
            "SOFTHSM_CONFIG_NOT_FOUND",
            503
        );
    }
}

export function probeSoftHsmPrivateKey(certificateRecord = {}) {
    try {
        assertSoftHsmConfiguration();
    } catch (error) {
        return { ready: false, code: error.code, error: error.message };
    }

    const resolved = resolvePkcs11KeyArguments(certificateRecord, { keyOption: "-in" });
    const mode = resolved.mode;
    let args;
    if (mode === "provider") {
        args = ["pkey", ...resolved.args, "-pubout", "-outform", "PEM"];
    } else {
        // OpenSSL pkey does not consistently accept engine key options on all builds.
        // `req -new` is a portable read/sign probe for the legacy engine path.
        args = [
            "req", "-new", "-sha256",
            ...resolvePkcs11KeyArguments(certificateRecord, { keyOption: "-key" }).args,
            "-subj", "/CN=NT219 SoftHSM Runtime Probe",
            "-outform", "PEM",
        ];
    }
    const result = commandResult(OPENSSL_BIN, args, { env: resolved.env });
    return {
        ready: !result.error && result.status === 0,
        code: !result.error && result.status === 0 ? "SOFTHSM_KEY_READY" : "SOFTHSM_KEY_UNAVAILABLE",
        key_reference: resolved.uri,
        error: !result.error && result.status === 0 ? null : safeCommandError(result),
    };
}

export function resolveCmsSigningProvider(certificateRecord = {}) {
    const provider = getSelectedSigningProvider();
    if (provider === "file") {
        const privateKeyPath = resolveBackendPath(certificateRecord.private_key_path || "");
        if (!certificateRecord.private_key_path || !fs.existsSync(privateKeyPath)) {
            throw new OfficerCertificateError(
                "Officer private key file is unavailable",
                "SIGNING_KEY_NOT_FOUND",
                503
            );
        }
        return {
            provider: "file",
            key_reference: `file-key:${certificateRecord.certificate_id || certificateRecord.officer_id || "officer"}`,
            key_exportable: true,
            openssl_args: ["-inkey", privateKeyPath],
            env: {},
        };
    }

    if (provider !== "softhsm") {
        throw new OfficerCertificateError(
            `Unsupported SIGNING_PROVIDER: ${provider}`,
            "SIGNING_PROVIDER_UNSUPPORTED",
            500
        );
    }

    validateSoftHsmCertificateBinding(certificateRecord);
    assertSoftHsmConfiguration();
    const resolved = resolvePkcs11KeyArguments(certificateRecord, { keyOption: "-inkey" });
    const runtimeProbeEnabled = bool(process.env.SOFTHSM_RUNTIME_PROBE, true);
    if (runtimeProbeEnabled) {
        const probe = probeSoftHsmPrivateKey(certificateRecord);
        if (!probe.ready) {
            throw new OfficerCertificateError(
                `SoftHSM private key is not accessible: ${probe.error || probe.code}`,
                probe.code || "SOFTHSM_KEY_UNAVAILABLE",
                503
            );
        }
    }

    return {
        provider: "softhsm",
        key_reference: resolved.uri,
        key_exportable: false,
        openssl_args: resolved.args,
        env: resolved.env,
    };
}

export function getSigningProviderStatus({ certificateRecord = null } = {}) {
    const selected = getSelectedSigningProvider();
    const softhsmUtil = process.env.SOFTHSM2_UTIL_BIN || "softhsm2-util";
    const pkcs11Tool = process.env.PKCS11_TOOL_BIN || "pkcs11-tool";
    const modulePath = resolveBackendPath(process.env.SOFTHSM_PKCS11_MODULE_PATH || "");
    const configPath = resolveBackendPath(process.env.SOFTHSM2_CONF || "");
    const providerName = process.env.SOFTHSM_OPENSSL_PROVIDER_NAME || "pkcs11prov";
    const providerPath = resolveBackendPath(process.env.SOFTHSM_PKCS11_PROVIDER_PATH || "");
    const environment = getPkcs11Environment();

    const providerProbe = String(process.env.SOFTHSM_OPENSSL_MODE || "provider").toLowerCase() === "provider"
        ? commandResult(OPENSSL_BIN, [
            "list", "-providers", "-verbose",
            ...(providerPath ? ["-provider-path", providerPath] : []),
            "-provider", providerName,
        ], { env: environment })
        : commandResult(OPENSSL_BIN, ["engine", "-t", process.env.SOFTHSM_ENGINE_ID || "pkcs11"], { env: environment });

    const slotProbe = commandResult(softhsmUtil, ["--show-slots"], { env: environment });
    const tokenLabel = process.env.SOFTHSM_TOKEN_LABEL || "NT219-TSP";
    const tokenPresent = !slotProbe.error && slotProbe.status === 0 &&
        String(slotProbe.stdout || "").includes(tokenLabel);

    const status = {
        selected_provider: selected,
        supported_providers: ["file", "softhsm"],
        file_provider: {
            ready: true,
            private_keys_exportable: true,
            intended_use: "development/test fallback",
        },
        softhsm_provider: {
            ready: false,
            private_keys_exportable: false,
            openssl_mode: process.env.SOFTHSM_OPENSSL_MODE || "provider",
            openssl_provider_name: providerName,
            token_label: tokenLabel,
            module_path: modulePath || null,
            module_path_exists: Boolean(modulePath && fs.existsSync(modulePath)),
            provider_path: providerPath || null,
            provider_path_exists: providerPath ? fs.existsSync(providerPath) : null,
            config_path: configPath || null,
            config_path_exists: Boolean(configPath && fs.existsSync(configPath)),
            softhsm2_util_available: commandAvailable(softhsmUtil, ["--version"]),
            pkcs11_tool_available: commandAvailable(pkcs11Tool, ["--version"]),
            openssl_provider_available: !providerProbe.error && providerProbe.status === 0,
            token_present: tokenPresent,
            configured: Boolean(
                process.env.SOFTHSM_USER_PIN &&
                modulePath && fs.existsSync(modulePath) &&
                configPath && fs.existsSync(configPath)
            ),
            runtime_key_probe: certificateRecord
                ? probeSoftHsmPrivateKey(certificateRecord)
                : { ready: null, code: "SOFTHSM_CERTIFICATE_NOT_SUPPLIED" },
        },
    };
    const keyReady = status.softhsm_provider.runtime_key_probe.ready;
    status.softhsm_provider.ready =
        status.softhsm_provider.softhsm2_util_available &&
        status.softhsm_provider.openssl_provider_available &&
        status.softhsm_provider.configured &&
        status.softhsm_provider.token_present &&
        (keyReady === null || keyReady === true);
    status.ready = selected === "file"
        ? status.file_provider.ready
        : status.softhsm_provider.ready;
    status.fail_closed = bool(process.env.SIGNING_PROVIDER_FAIL_CLOSED, true);
    return status;
}
