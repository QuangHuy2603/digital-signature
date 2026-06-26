import path from "node:path";
import { fileURLToPath } from "node:url";
import { config as loadDotenv } from "dotenv";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Load backend/.env from a path anchored to this module instead of process.cwd().
// This keeps CLI tools, tests and attack scripts consistent when started directly.
loadDotenv({
    path: path.resolve(__dirname, "../../.env"),
    quiet: true,
});

/**
 * Centralised environment configuration.
 *
 * This module loads `backend/.env` itself so every entry point (server, CLI,
 * tests and attack scripts) sees the same validated configuration.
 */

const NODE_ENV = process.env.NODE_ENV || "development";
const IS_DEV = NODE_ENV !== "production";

const PUBLIC_VERIFY_URL =
    process.env.PUBLIC_VERIFY_URL ||
    "http://localhost:3000/api/public/documents/verify";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "24h";
const SIGNING_REQUEST_TTL_SECONDS = Number.parseInt(
    process.env.SIGNING_REQUEST_TTL_SECONDS || "300",
    10
);
const CITIZEN_SIGNING_REQUEST_TTL_SECONDS = Number.parseInt(
    process.env.CITIZEN_SIGNING_REQUEST_TTL_SECONDS || "300",
    10
);

const REMOTE_OTP_REQUIRED = String(
    process.env.REMOTE_OTP_REQUIRED || "true"
).toLowerCase() === "true";
const REMOTE_OTP_TTL_SECONDS = Number.parseInt(
    process.env.REMOTE_OTP_TTL_SECONDS || "120",
    10
);
const REMOTE_OTP_AUTHORIZATION_TTL_SECONDS = Number.parseInt(
    process.env.REMOTE_OTP_AUTHORIZATION_TTL_SECONDS || "120",
    10
);
const REMOTE_OTP_MAX_ATTEMPTS = Number.parseInt(
    process.env.REMOTE_OTP_MAX_ATTEMPTS || "5",
    10
);
const REMOTE_OTP_DEMO_EXPOSE = String(
    process.env.REMOTE_OTP_DEMO_EXPOSE || (IS_DEV ? "true" : "false")
).toLowerCase() === "true";

const PKI_ROOT_CA_CERT_PATH = process.env.PKI_ROOT_CA_CERT_PATH || "../pki/root-ca/root-ca.crt";
const PKI_OFFICERS_DIRECTORY = process.env.PKI_OFFICERS_DIRECTORY || "../pki/officers";
const PKI_CRL_PATH = process.env.PKI_CRL_PATH || "../pki/root-ca/root-ca.crl";
const PKI_CRL_CONFIG_PATH = process.env.PKI_CRL_CONFIG_PATH || "../pki/config/openssl-ca.cnf";
const PKI_REQUIRE_CRL = String(process.env.PKI_REQUIRE_CRL || "true").toLowerCase() === "true";
const OPENSSL_BIN = process.env.OPENSSL_BIN || "openssl";
const PYTHON_BIN = process.env.PYTHON_BIN || "python";

const PKI_OCSP_RESPONDER_CERT_PATH = process.env.PKI_OCSP_RESPONDER_CERT_PATH || "../pki/ocsp/ocsp-responder.crt";
const PKI_OCSP_RESPONDER_KEY_PATH = process.env.PKI_OCSP_RESPONDER_KEY_PATH || "../pki/ocsp/ocsp-responder.key";
const PKI_OCSP_RESPONSE_TTL_SECONDS = Number.parseInt(process.env.PKI_OCSP_RESPONSE_TTL_SECONDS || "300", 10);
const PKI_OCSP_ALLOW_CRL_FALLBACK = String(process.env.PKI_OCSP_ALLOW_CRL_FALLBACK || "true").toLowerCase() === "true";
const PKI_TSA_CERT_PATH = process.env.PKI_TSA_CERT_PATH || "../pki/tsa/tsa.crt";
const PKI_TSA_KEY_PATH = process.env.PKI_TSA_KEY_PATH || "../pki/tsa/tsa.key";
const PKI_TSA_DEFAULT_POLICY = process.env.PKI_TSA_DEFAULT_POLICY || "1.3.6.1.4.1.55555.1.7.1";
const PKI_OFFICER_CERT_PATH = process.env.PKI_OFFICER_CERT_PATH || "../pki/officers/OFFICER-001/v1/officer.crt";
const PKI_OFFICER_PRIVATE_KEY_PATH = process.env.PKI_OFFICER_PRIVATE_KEY_PATH || "../pki/officers/OFFICER-001/v1/officer.key";
const PKI_OFFICER_CERT_FINGERPRINT_SHA256 = (
    process.env.PKI_OFFICER_CERT_FINGERPRINT_SHA256 || ""
).replace(/:/g, "").trim().toUpperCase();
const PKI_REQUIRE_CERTIFICATE = String(
    process.env.PKI_REQUIRE_CERTIFICATE || "true"
).toLowerCase() === "true";

const DEFAULT_SECRETS = new Set([
    "change-me-in-production",
    "change-me-in-production-jwt-secret",
    "replace-with-a-long-random-secret",
    "secret",
    "password",
    "123456",
]);

// Stable development fallback keeps JWT sessions readable after restart
// when a developer forgets to create .env.
const DEVELOPMENT_DEFAULTS = {
    JWT_SECRET: "nt219-development-jwt-secret-change-me",
};

function resolveSecret(name, value) {
    if (!value) {
        if (!IS_DEV) {
            throw new Error(
                `[env] ${name} must be set when NODE_ENV=production`
            );
        }

        const fallback = DEVELOPMENT_DEFAULTS[name];
        console.warn(
            `[env] ${name} is not set. Using a stable development-only fallback. ` +
            "Create backend/.env before submitting or deploying the project."
        );
        return fallback;
    }

    if (!IS_DEV && DEFAULT_SECRETS.has(value.toLowerCase())) {
        throw new Error(
            `[env] ${name} uses a known default/weak value in production`
        );
    }

    return value;
}

if (!Number.isInteger(SIGNING_REQUEST_TTL_SECONDS) ||
    SIGNING_REQUEST_TTL_SECONDS < 30 ||
    SIGNING_REQUEST_TTL_SECONDS > 3600) {
    throw new Error(
        "[env] SIGNING_REQUEST_TTL_SECONDS must be an integer from 30 to 3600"
    );
}

if (!Number.isInteger(CITIZEN_SIGNING_REQUEST_TTL_SECONDS) ||
    CITIZEN_SIGNING_REQUEST_TTL_SECONDS < 30 ||
    CITIZEN_SIGNING_REQUEST_TTL_SECONDS > 3600) {
    throw new Error("[env] CITIZEN_SIGNING_REQUEST_TTL_SECONDS must be an integer from 30 to 3600");
}

if (!Number.isInteger(PKI_OCSP_RESPONSE_TTL_SECONDS) || PKI_OCSP_RESPONSE_TTL_SECONDS < 60 || PKI_OCSP_RESPONSE_TTL_SECONDS > 86400) {
    throw new Error("[env] PKI_OCSP_RESPONSE_TTL_SECONDS must be an integer from 60 to 86400");
}

if (!Number.isInteger(REMOTE_OTP_TTL_SECONDS) || REMOTE_OTP_TTL_SECONDS < 30 || REMOTE_OTP_TTL_SECONDS > 600) {
    throw new Error("[env] REMOTE_OTP_TTL_SECONDS must be an integer from 30 to 600");
}

if (!Number.isInteger(REMOTE_OTP_AUTHORIZATION_TTL_SECONDS) || REMOTE_OTP_AUTHORIZATION_TTL_SECONDS < 30 || REMOTE_OTP_AUTHORIZATION_TTL_SECONDS > 600) {
    throw new Error("[env] REMOTE_OTP_AUTHORIZATION_TTL_SECONDS must be an integer from 30 to 600");
}

if (!Number.isInteger(REMOTE_OTP_MAX_ATTEMPTS) || REMOTE_OTP_MAX_ATTEMPTS < 1 || REMOTE_OTP_MAX_ATTEMPTS > 10) {
    throw new Error("[env] REMOTE_OTP_MAX_ATTEMPTS must be an integer from 1 to 10");
}


const JWT_SECRET = resolveSecret("JWT_SECRET", process.env.JWT_SECRET);
const REMOTE_OTP_SECRET = resolveSecret(
    "REMOTE_OTP_SECRET",
    process.env.REMOTE_OTP_SECRET || (IS_DEV ? "nt219-development-remote-otp-secret-change-me" : "")
);

const env = Object.freeze({
    NODE_ENV,
    PUBLIC_VERIFY_URL,
    JWT_SECRET,
    JWT_EXPIRES_IN,
    IS_DEV,
    SIGNING_REQUEST_TTL_SECONDS,
    CITIZEN_SIGNING_REQUEST_TTL_SECONDS,
    REMOTE_OTP_REQUIRED,
    REMOTE_OTP_TTL_SECONDS,
    REMOTE_OTP_AUTHORIZATION_TTL_SECONDS,
    REMOTE_OTP_MAX_ATTEMPTS,
    REMOTE_OTP_DEMO_EXPOSE,
    REMOTE_OTP_SECRET,
    PKI_ROOT_CA_CERT_PATH,
    PKI_OFFICERS_DIRECTORY,
    PKI_CRL_PATH,
    PKI_CRL_CONFIG_PATH,
    PKI_REQUIRE_CRL,
    OPENSSL_BIN,
    PYTHON_BIN,
    PKI_OCSP_RESPONDER_CERT_PATH,
    PKI_OCSP_RESPONDER_KEY_PATH,
    PKI_OCSP_RESPONSE_TTL_SECONDS,
    PKI_OCSP_ALLOW_CRL_FALLBACK,
    PKI_TSA_CERT_PATH,
    PKI_TSA_KEY_PATH,
    PKI_TSA_DEFAULT_POLICY,
    PKI_OFFICER_CERT_PATH,
    PKI_OFFICER_PRIVATE_KEY_PATH,
    PKI_OFFICER_CERT_FINGERPRINT_SHA256,
    PKI_REQUIRE_CERTIFICATE,
});

export {
    NODE_ENV,
    PUBLIC_VERIFY_URL,
    JWT_SECRET,
    JWT_EXPIRES_IN,
    IS_DEV,
    SIGNING_REQUEST_TTL_SECONDS,
    CITIZEN_SIGNING_REQUEST_TTL_SECONDS,
    REMOTE_OTP_REQUIRED,
    REMOTE_OTP_TTL_SECONDS,
    REMOTE_OTP_AUTHORIZATION_TTL_SECONDS,
    REMOTE_OTP_MAX_ATTEMPTS,
    REMOTE_OTP_DEMO_EXPOSE,
    REMOTE_OTP_SECRET,
    PKI_ROOT_CA_CERT_PATH,
    PKI_OFFICERS_DIRECTORY,
    PKI_CRL_PATH,
    PKI_CRL_CONFIG_PATH,
    PKI_REQUIRE_CRL,
    OPENSSL_BIN,
    PYTHON_BIN,
    PKI_OCSP_RESPONDER_CERT_PATH,
    PKI_OCSP_RESPONDER_KEY_PATH,
    PKI_OCSP_RESPONSE_TTL_SECONDS,
    PKI_OCSP_ALLOW_CRL_FALLBACK,
    PKI_TSA_CERT_PATH,
    PKI_TSA_KEY_PATH,
    PKI_TSA_DEFAULT_POLICY,
    PKI_OFFICER_CERT_PATH,
    PKI_OFFICER_PRIVATE_KEY_PATH,
    PKI_OFFICER_CERT_FINGERPRINT_SHA256,
    PKI_REQUIRE_CERTIFICATE,
};

export default env;
