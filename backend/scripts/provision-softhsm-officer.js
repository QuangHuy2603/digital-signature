import crypto, { X509Certificate } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import "../src/config/env.config.js";
import { parseCliArgs } from "./cli-args.js";
import {
    findOfficerByOfficerId,
    assignSigningCertificate,
    normalizeOfficerId,
} from "../src/services/officer-account.service.js";
import {
    findCertificatesByOfficerId,
    findCertificateById,
    saveCertificate,
    updateCertificate,
} from "../src/services/certificate.repository.js";
import {
    normalizeFingerprint,
    verifyOfficerCertificate,
} from "../src/crypto/x509-pki.service.js";
import {
    buildPkcs11Uri,
    getPkcs11KeyId,
    getPkcs11KeyLabel,
    getPkcs11Environment,
    getSigningProviderStatus,
    resolvePkcs11KeyArguments,
} from "../src/crypto/signing-provider.service.js";
import { generateCertificateRevocationList } from "../src/crypto/crl.service.js";
import { atomicWriteJsonSync } from "../src/utils/atomic-file.util.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(__dirname, "..");
const projectRoot = path.resolve(backendRoot, "..");
const args = parseCliArgs();
const officerId = normalizeOfficerId(args["officer-id"] || "OFFICER-001");
const days = Number.parseInt(args.days || "825", 10);
const force = args.force === true;
const activate = args.activate !== "false";

function fail(message, code = 2) {
    console.error(message);
    process.exit(code);
}

function run(command, commandArgs, { env = {}, capture = true, allowFailure = false } = {}) {
    const result = spawnSync(command, commandArgs, {
        cwd: backendRoot,
        encoding: "utf8",
        windowsHide: true,
        stdio: capture ? "pipe" : "inherit",
        env: { ...process.env, ...env },
    });
    if (result.error && !allowFailure) {
        throw new Error(`Unable to run ${command}: ${result.error.message}`);
    }
    if (result.status !== 0 && !allowFailure) {
        const details = String(result.stderr || result.stdout || "").trim();
        throw new Error(`${command} failed (${result.status}): ${details}`);
    }
    return result;
}

function nextVersion(records) {
    const versions = records.map((record) => Number(record.version) || 0);
    return versions.length ? Math.max(...versions) + 1 : 1;
}

function safeConfigValue(value, name) {
    const text = String(value || "").trim();
    if (!text || /[\r\n\0]/.test(text)) throw new Error(`${name} contains invalid characters`);
    return text.replace(/\\/g, "\\\\");
}

function relativeFromBackend(absolutePath) {
    return path.relative(backendRoot, absolutePath).replaceAll("\\", "/");
}

function updateEnvValue(name, value) {
    const envPath = path.join(backendRoot, ".env");
    let text = fs.existsSync(envPath) ? fs.readFileSync(envPath, "utf8") : "";
    const line = `${name}=${value}`;
    const regex = new RegExp(`^${name}=.*$`, "m");
    text = regex.test(text)
        ? text.replace(regex, line)
        : `${text.replace(/\s*$/, "")}\n${line}\n`;
    fs.writeFileSync(envPath, text, "utf8");
    process.env[name] = String(value);
}

function tokenExists(label) {
    const util = process.env.SOFTHSM2_UTIL_BIN || "softhsm2-util";
    const result = run(util, ["--show-slots"], {
        env: getPkcs11Environment(),
        allowFailure: true,
    });
    if (result.error) throw new Error(`SoftHSM utility unavailable: ${result.error.message}`);
    if (result.status !== 0) throw new Error(String(result.stderr || result.stdout || "SoftHSM slot query failed"));
    return String(result.stdout || "").includes(label);
}

function ensureToken() {
    const label = process.env.SOFTHSM_TOKEN_LABEL || "NT219-TSP";
    if (tokenExists(label)) return { created: false, label };
    const soPin = process.env.SOFTHSM_SO_PIN || "";
    const userPin = process.env.SOFTHSM_USER_PIN || "";
    if (!soPin || !userPin) throw new Error("SOFTHSM_SO_PIN and SOFTHSM_USER_PIN are required");
    const util = process.env.SOFTHSM2_UTIL_BIN || "softhsm2-util";
    run(util, [
        "--init-token", "--free",
        "--label", label,
        "--so-pin", soPin,
        "--pin", userPin,
    ], { env: getPkcs11Environment() });
    if (!tokenExists(label)) throw new Error(`SoftHSM token ${label} was not created`);
    return { created: true, label };
}

function privateKeyExists({ label, idHex }) {
    const tool = process.env.PKCS11_TOOL_BIN || "pkcs11-tool";
    const modulePath = process.env.SOFTHSM_PKCS11_MODULE_PATH;
    const result = run(tool, [
        "--module", modulePath,
        "--login", "--pin", process.env.SOFTHSM_USER_PIN,
        "--token-label", process.env.SOFTHSM_TOKEN_LABEL || "NT219-TSP",
        "--list-objects", "--type", "privkey",
    ], { env: getPkcs11Environment(), allowFailure: true });
    if (result.error) throw new Error(`pkcs11-tool unavailable: ${result.error.message}`);
    if (result.status !== 0) throw new Error(String(result.stderr || result.stdout || "PKCS#11 object listing failed"));
    const output = String(result.stdout || "");
    return output.includes(label) || output.toLowerCase().includes(idHex.toLowerCase());
}

function generateKeyPair({ label, idHex }) {
    const tool = process.env.PKCS11_TOOL_BIN || "pkcs11-tool";
    const modulePath = process.env.SOFTHSM_PKCS11_MODULE_PATH;
    run(tool, [
        "--module", modulePath,
        "--login", "--pin", process.env.SOFTHSM_USER_PIN,
        "--token-label", process.env.SOFTHSM_TOKEN_LABEL || "NT219-TSP",
        "--keypairgen",
        "--key-type", "EC:prime256v1",
        "--usage-sign",
        "--label", label,
        "--id", idHex,
    ], { env: getPkcs11Environment() });
}

function writeCertificateObject(certificateDerPath, { label, idHex }) {
    const tool = process.env.PKCS11_TOOL_BIN || "pkcs11-tool";
    const modulePath = process.env.SOFTHSM_PKCS11_MODULE_PATH;
    const result = run(tool, [
        "--module", modulePath,
        "--login", "--pin", process.env.SOFTHSM_USER_PIN,
        "--token-label", process.env.SOFTHSM_TOKEN_LABEL || "NT219-TSP",
        "--write-object", certificateDerPath,
        "--type", "cert",
        "--label", label,
        "--id", idHex,
    ], { env: getPkcs11Environment(), allowFailure: true });
    if (result.status !== 0) {
        const output = String(result.stderr || result.stdout || "");
        if (!/already exists|object exists/i.test(output)) {
            throw new Error(`Unable to store certificate object: ${output.trim()}`);
        }
    }
}

try {
    if (!Number.isInteger(days) || days < 1 || days > 3650) {
        throw new Error("--days must be an integer from 1 to 3650");
    }
    const officer = findOfficerByOfficerId(officerId);
    if (!officer) throw new Error(`Officer ${officerId} was not found`);
    if (officer.status !== "active") throw new Error(`Officer ${officerId} is not active`);

    const allRecords = findCertificatesByOfficerId(officerId);
    const existingRemote = officer.remote_certificate_id
        ? findCertificateById(officer.remote_certificate_id)
        : allRecords.find((record) => record.status === "active" && record.key_provider === "softhsm");
    if (existingRemote && !force) {
        if (activate) {
            updateEnvValue("SIGNING_PROVIDER", "softhsm");
            updateEnvValue("SOFTHSM_RUNTIME_PROBE", "true");
        }
        const existingStatus = getSigningProviderStatus({ certificateRecord: existingRemote });
        const output = {
            status: existingStatus.softhsm_provider.ready ? "already_provisioned_ready" : "already_provisioned_not_ready",
            officer_id: officerId,
            local_certificate_id: officer.local_certificate_id || officer.active_certificate_id || null,
            remote_certificate_id: existingRemote.certificate_id,
            signing_provider: activate ? "softhsm" : process.env.SIGNING_PROVIDER,
            pkcs11_uri: buildPkcs11Uri(existingRemote),
            private_key_exportable: false,
            runtime_probe: existingStatus.softhsm_provider.runtime_key_probe,
            hint: "Use --force only when you intentionally want a new remote certificate version.",
        };
        fs.mkdirSync(path.join(projectRoot, "evidence"), { recursive: true });
        atomicWriteJsonSync(path.join(projectRoot, "evidence", "softhsm-provisioning.json"), {
            generated_at: new Date().toISOString(),
            ...output,
        }, { backup: true });
        console.log(JSON.stringify(output, null, 2));
        process.exit(existingStatus.softhsm_provider.ready ? 0 : 3);
    }

    console.log("[1/9] Validate SoftHSM and PKCS#11 configuration");
    const token = ensureToken();
    console.log(`Token ${token.label}: ${token.created ? "created" : "already present"}`);

    const version = nextVersion(allRecords);
    const certificateId = `CERT-${officerId}-REMOTE-V${version}`;
    const keyId = crypto.createHash("sha256").update(certificateId).digest("hex").slice(0, 32);
    const provisionalRecord = {
        certificate_id: certificateId,
        officer_id: officerId,
        pkcs11_token_label: process.env.SOFTHSM_TOKEN_LABEL || "NT219-TSP",
        pkcs11_key_label: `NT219-${officerId}-REMOTE-V${version}`,
        pkcs11_key_id: keyId,
    };
    const keyLabel = getPkcs11KeyLabel(provisionalRecord);

    console.log("[2/9] Generate a non-exportable ECDSA P-256 key pair inside SoftHSM");
    if (privateKeyExists({ label: keyLabel, idHex: keyId })) {
        if (!force) throw new Error(`PKCS#11 private key already exists: ${keyLabel}`);
        console.log(`Reusing existing PKCS#11 key ${keyLabel} because --force was supplied.`);
    } else {
        generateKeyPair({ label: keyLabel, idHex: keyId });
    }

    const versionDirectory = path.join(projectRoot, "pki", "officers", officerId, `remote-v${version}`);
    fs.mkdirSync(versionDirectory, { recursive: true });
    const csrPath = path.join(versionDirectory, "officer-remote.csr");
    const certificatePath = path.join(versionDirectory, "officer-remote.crt");
    const certificateDerPath = path.join(versionDirectory, "officer-remote.der");
    const chainPath = path.join(versionDirectory, "officer-remote-chain.pem");
    const publicKeyPath = path.join(versionDirectory, "officer-remote-public.pem");
    const requestConfigPath = path.join(versionDirectory, "request.cnf");
    const extensionConfigPath = path.join(versionDirectory, "extensions.cnf");
    const rootCertificatePath = path.join(projectRoot, "pki", "root-ca", "root-ca.crt");
    const rootPrivateKeyPath = path.join(projectRoot, "pki", "root-ca", "root-ca.key");
    const rootSerialPath = path.join(projectRoot, "pki", "root-ca", "root-ca.srl");

    const fullName = safeConfigValue(officer.full_name, "full_name");
    const email = safeConfigValue(officer.email, "email");
    fs.writeFileSync(requestConfigPath, `[ req ]\nprompt = no\nutf8 = yes\nstring_mask = utf8only\ndistinguished_name = dn\nreq_extensions = req_ext\n\n[ dn ]\nC = VN\nST = Ho Chi Minh\nL = Thu Duc\nO = HCMUTE\nOU = Remote Signing Officer\nCN = ${fullName}\nUID = ${officerId}\nemailAddress = ${email}\n\n[ req_ext ]\nsubjectAltName = @alt_names\n\n[ alt_names ]\nemail.1 = ${email}\nURI.1 = urn:nt219:officer:${officerId}\nURI.2 = urn:nt219:signing-provider:softhsm\n`, "utf8");
    fs.writeFileSync(extensionConfigPath, `[ v3_officer ]\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\nbasicConstraints = critical, CA:false\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = emailProtection, clientAuth\nsubjectAltName = @alt_names\ncertificatePolicies = 1.3.6.1.4.1.55555.1.1\n\n[ alt_names ]\nemail.1 = ${email}\nURI.1 = urn:nt219:officer:${officerId}\nURI.2 = urn:nt219:signing-provider:softhsm\n`, "utf8");

    console.log("[3/9] Create a CSR using the private key inside SoftHSM");
    const keyArgs = resolvePkcs11KeyArguments(provisionalRecord, { keyOption: "-key" });
    run(process.env.OPENSSL_BIN || "openssl", [
        "req", "-new", "-sha256",
        ...keyArgs.args,
        "-out", csrPath,
        "-config", requestConfigPath,
    ], { env: keyArgs.env });

    console.log("[4/9] Issue the remote-signing certificate from the NT219 Test Root CA");
    const signArgs = [
        "x509", "-req",
        "-in", csrPath,
        "-CA", rootCertificatePath,
        "-CAkey", rootPrivateKeyPath,
        ...(fs.existsSync(rootSerialPath) ? ["-CAserial", rootSerialPath] : ["-CAcreateserial"]),
        "-out", certificatePath,
        "-days", String(days),
        "-sha256",
        "-extfile", extensionConfigPath,
        "-extensions", "v3_officer",
    ];
    run(process.env.OPENSSL_BIN || "openssl", signArgs);

    console.log("[5/9] Export public artifacts and store the certificate object in SoftHSM");
    run(process.env.OPENSSL_BIN || "openssl", ["x509", "-in", certificatePath, "-outform", "DER", "-out", certificateDerPath]);
    const publicResult = run(process.env.OPENSSL_BIN || "openssl", ["x509", "-in", certificatePath, "-pubkey", "-noout"]);
    fs.writeFileSync(publicKeyPath, `${String(publicResult.stdout || "").trim()}\n`, "ascii");
    const certPem = fs.readFileSync(certificatePath, "utf8");
    const rootPem = fs.readFileSync(rootCertificatePath, "utf8");
    fs.writeFileSync(chainPath, `${certPem.trim()}\n${rootPem.trim()}\n`, "ascii");
    writeCertificateObject(certificateDerPath, { label: keyLabel, idHex: keyId });

    console.log("[6/9] Validate certificate ownership and certificate chain");
    const parsed = new X509Certificate(certPem);
    const fingerprint = normalizeFingerprint(parsed.fingerprint256);
    const verified = verifyOfficerCertificate({
        officerCertificatePem: certPem,
        rootCertificatePem: rootPem,
        expectedFingerprint: fingerprint,
        expectedOfficerId: officerId,
        expectedEmail: officer.email,
    });

    const issuedAt = new Date().toISOString();
    const record = {
        certificate_id: certificateId,
        version,
        user_id: officer.id,
        officer_id: officerId,
        full_name: officer.full_name,
        email: officer.email,
        subject: verified.metadata.subject,
        issuer: verified.metadata.issuer,
        serial_number: verified.metadata.serial_number,
        fingerprint_sha256: verified.metadata.fingerprint_sha256,
        root_ca_fingerprint_sha256: verified.metadata.root_ca_fingerprint_sha256,
        certificate_path: relativeFromBackend(certificatePath),
        private_key_path: null,
        certificate_chain_path: relativeFromBackend(chainPath),
        public_key_path: relativeFromBackend(publicKeyPath),
        root_ca_certificate_path: relativeFromBackend(rootCertificatePath),
        status: "active",
        purpose: "remote-signing",
        key_provider: "softhsm",
        private_key_exportable: false,
        pkcs11_token_label: provisionalRecord.pkcs11_token_label,
        pkcs11_key_label: keyLabel,
        pkcs11_key_id: getPkcs11KeyId(provisionalRecord),
        pkcs11_binding_scheme: "nt219-deterministic-v1",
        pkcs11_uri: buildPkcs11Uri(provisionalRecord),
        valid_from: verified.metadata.valid_from,
        valid_to: verified.metadata.valid_to,
        issued_at: issuedAt,
        revoked_at: null,
        revocation_reason: null,
    };

    console.log("[7/9] Register the dedicated remote certificate without replacing the local certificate");
    saveCertificate(record);
    if (force && existingRemote && existingRemote.certificate_id !== certificateId) {
        updateCertificate(existingRemote.certificate_id, {
            status: "superseded",
            superseded_at: issuedAt,
            superseded_by_certificate_id: certificateId,
            status_updated_at: issuedAt,
        });
    }
    assignSigningCertificate({ officerId, certificateId, signingMethod: "remote" });
    generateCertificateRevocationList();

    if (activate) {
        console.log("[8/9] Activate SoftHSM as the remote TSP signing provider");
        updateEnvValue("SIGNING_PROVIDER", "softhsm");
        updateEnvValue("SOFTHSM_RUNTIME_PROBE", "true");
    } else {
        console.log("[8/9] Keep current provider because --activate=false was supplied");
    }

    console.log("[9/9] Verify runtime access to the SoftHSM key");
    const status = getSigningProviderStatus({ certificateRecord: record });
    const output = {
        status: status.softhsm_provider.ready ? "ready" : "not_ready",
        officer_id: officerId,
        local_certificate_id: officer.local_certificate_id || officer.active_certificate_id || null,
        remote_certificate_id: certificateId,
        signing_provider: activate ? "softhsm" : process.env.SIGNING_PROVIDER,
        token_label: record.pkcs11_token_label,
        key_label: record.pkcs11_key_label,
        key_id: record.pkcs11_key_id,
        key_reference: record.pkcs11_uri,
        private_key_exportable: false,
        runtime_probe: status.softhsm_provider.runtime_key_probe,
        certificate_path: record.certificate_path,
    };
    fs.mkdirSync(path.join(projectRoot, "evidence"), { recursive: true });
    atomicWriteJsonSync(path.join(projectRoot, "evidence", "softhsm-provisioning.json"), {
        generated_at: new Date().toISOString(),
        ...output,
    }, { backup: true });
    console.log(JSON.stringify(output, null, 2));
    if (!status.softhsm_provider.ready) process.exitCode = 3;
} catch (error) {
    fail(`[SOFTHSM_PROVISIONING_FAILED] ${error.message}`);
}
