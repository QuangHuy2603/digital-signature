import crypto, { X509Certificate } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import "../src/config/env.config.js";
import { parseCliArgs } from "./cli-args.js";
import { listUsers, updateUser } from "../src/services/auth.service.js";
import { findActiveCitizenCertificate, findCertificatesByCitizenId, saveCertificate, updateCertificate } from "../src/services/certificate.repository.js";
import { generateCertificateRevocationList } from "../src/crypto/crl.service.js";
import { normalizeFingerprint } from "../src/crypto/x509-pki.service.js";
import { atomicWriteJsonSync, readJsonFileSync } from "../src/utils/atomic-file.util.js";
import { buildClientAgentPkcs11Uri, getClientAgentPkcs11Environment, getPkcs11CertificateStatus, signCanonicalPayloadWithPkcs11 } from "../../client-agent/src/providers.js";
import { buildCitizenSignaturePayload } from "../src/crypto/citizen-signature-payload.js";
import { verifyCitizenDetachedSignature } from "../src/crypto/citizen-signature.service.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(__dirname, "..");
const projectRoot = path.resolve(backendRoot, "..");
const args = parseCliArgs();
const userId = String(args["user-id"] || "2");
const force = args.force === true;
const days = Number.parseInt(args.days || "825", 10);

function run(command, commandArgs, { env = {}, allowFailure = false } = {}) {
    const result = spawnSync(command, commandArgs, {
        cwd: backendRoot,
        encoding: "utf8",
        windowsHide: true,
        stdio: "pipe",
        env: { ...process.env, ...env },
    });
    if (!allowFailure && (result.error || result.status !== 0)) {
        throw new Error(result.error?.message || String(result.stderr || result.stdout || `exit ${result.status}`).trim());
    }
    return result;
}
function envValue(name, fallback = "") {
    return String(process.env[name] || fallback).trim();
}
function safe(value) {
    return String(value || "").replace(/[\r\n\0]/g, " ").replace(/[\\]/g, "\\\\");
}
function relativeProject(filePath) {
    return path.relative(projectRoot, filePath).replaceAll("\\", "/");
}
function relativeBackend(filePath) {
    return path.relative(backendRoot, filePath).replaceAll("\\", "/");
}
function nextVersion(records) {
    return Math.max(0, ...records.map((item) => Number(item.version) || 0)) + 1;
}
function tokenExists(label) {
    const util = envValue("CLIENT_AGENT_SOFTHSM2_UTIL_BIN", envValue("SOFTHSM2_UTIL_BIN", "softhsm2-util"));
    const result = run(util, ["--show-slots"], { env: getClientAgentPkcs11Environment(projectRoot), allowFailure: true });
    if (result.error || result.status !== 0) throw new Error(result.error?.message || String(result.stderr || result.stdout || "SoftHSM slot query failed"));
    return String(result.stdout || "").includes(label);
}
function ensureToken(label) {
    if (tokenExists(label)) return false;
    const util = envValue("CLIENT_AGENT_SOFTHSM2_UTIL_BIN", envValue("SOFTHSM2_UTIL_BIN", "softhsm2-util"));
    const soPin = envValue("CLIENT_AGENT_PKCS11_SO_PIN", "87654321");
    const userPin = envValue("CLIENT_AGENT_PKCS11_USER_PIN", "654321");
    run(util, ["--init-token", "--free", "--label", label, "--so-pin", soPin, "--pin", userPin], { env: getClientAgentPkcs11Environment(projectRoot) });
    if (!tokenExists(label)) throw new Error(`SoftHSM token ${label} was not created`);
    return true;
}
function listPrivateKeys(label) {
    const tool = envValue("CLIENT_AGENT_PKCS11_TOOL_BIN", envValue("PKCS11_TOOL_BIN", "pkcs11-tool"));
    const modulePath = envValue("CLIENT_AGENT_PKCS11_MODULE_PATH", envValue("SOFTHSM_PKCS11_MODULE_PATH"));
    const pin = envValue("CLIENT_AGENT_PKCS11_USER_PIN", "654321");
    const result = run(tool, ["--module", modulePath, "--login", "--pin", pin, "--token-label", label, "--list-objects", "--type", "privkey"], { env: getClientAgentPkcs11Environment(projectRoot), allowFailure: true });
    if (result.error || result.status !== 0) throw new Error(result.error?.message || String(result.stderr || result.stdout || "PKCS#11 key listing failed"));
    return String(result.stdout || "");
}
function generateKeyPair(tokenLabel, keyLabel, keyId) {
    const tool = envValue("CLIENT_AGENT_PKCS11_TOOL_BIN", envValue("PKCS11_TOOL_BIN", "pkcs11-tool"));
    const modulePath = envValue("CLIENT_AGENT_PKCS11_MODULE_PATH", envValue("SOFTHSM_PKCS11_MODULE_PATH"));
    const pin = envValue("CLIENT_AGENT_PKCS11_USER_PIN", "654321");
    run(tool, ["--module", modulePath, "--login", "--pin", pin, "--token-label", tokenLabel, "--keypairgen", "--key-type", "EC:prime256v1", "--usage-sign", "--label", keyLabel, "--id", keyId], { env: getClientAgentPkcs11Environment(projectRoot) });
}
function writeCertificateObject(tokenLabel, certDer, keyLabel, keyId) {
    const tool = envValue("CLIENT_AGENT_PKCS11_TOOL_BIN", envValue("PKCS11_TOOL_BIN", "pkcs11-tool"));
    const modulePath = envValue("CLIENT_AGENT_PKCS11_MODULE_PATH", envValue("SOFTHSM_PKCS11_MODULE_PATH"));
    const pin = envValue("CLIENT_AGENT_PKCS11_USER_PIN", "654321");
    const result = run(tool, ["--module", modulePath, "--login", "--pin", pin, "--token-label", tokenLabel, "--write-object", certDer, "--type", "cert", "--label", keyLabel, "--id", keyId], { env: getClientAgentPkcs11Environment(projectRoot), allowFailure: true });
    if (result.status !== 0 && !/already exists|object exists/i.test(String(result.stderr || result.stdout || ""))) {
        throw new Error(String(result.stderr || result.stdout || "Unable to store certificate object").trim());
    }
}
function providerArgs() {
    const name = envValue("CLIENT_AGENT_PKCS11_PROVIDER_NAME", envValue("SOFTHSM_OPENSSL_PROVIDER_NAME", "pkcs11prov"));
    const directory = envValue("CLIENT_AGENT_PKCS11_PROVIDER_PATH", envValue("SOFTHSM_PKCS11_PROVIDER_PATH"));
    return [...(directory ? ["-provider-path", directory] : []), "-provider", "default", "-provider", name];
}

try {
    if (!Number.isInteger(days) || days < 1 || days > 3650) throw new Error("--days must be from 1 to 3650");
    const user = listUsers().find((item) => String(item.id) === userId);
    if (!user || !(user.roles || []).includes("citizen")) throw new Error(`Citizen user ${userId} was not found`);
    const citizenId = user.citizen_id || `CITIZEN-${String(user.id).padStart(3, "0")}`;
    if (!user.citizen_id) updateUser(user.id, { citizen_id: citizenId });
    const existing = findActiveCitizenCertificate(citizenId, "pkcs11");
    if (existing && !force) {
        const status = getPkcs11CertificateStatus(existing, projectRoot);
        console.log(JSON.stringify({ status: status.ready ? "already_provisioned_ready" : "already_provisioned_not_ready", user_id: user.id, citizen_id: citizenId, certificate_id: existing.certificate_id, provider: "pkcs11", key_reference: buildClientAgentPkcs11Uri(existing), runtime_probe: status }, null, 2));
        process.exit(status.ready ? 0 : 3);
    }

    const tokenLabel = envValue("CLIENT_AGENT_PKCS11_TOKEN_LABEL", "NT219-CITIZEN");
    console.log("[1/8] Validate Client Agent PKCS#11 configuration and token");
    const tokenCreated = ensureToken(tokenLabel);
    console.log(`Token ${tokenLabel}: ${tokenCreated ? "created" : "already present"}`);

    const version = nextVersion(findCertificatesByCitizenId(citizenId));
    const certificateId = `CERT-${citizenId}-PKCS11-V${version}`;
    const keyId = crypto.createHash("sha256").update(certificateId).digest("hex").slice(0, 32);
    const keyLabel = `NT219-${citizenId}-SIGNING-V${version}`;
    const provisional = {
        certificate_id: certificateId,
        user_id: user.id,
        citizen_id: citizenId,
        pkcs11_token_label: tokenLabel,
        pkcs11_key_label: keyLabel,
        pkcs11_key_id: keyId,
    };

    console.log("[2/8] Generate non-exportable ECDSA P-256 key in citizen token");
    const existingKeys = listPrivateKeys(tokenLabel);
    if (!existingKeys.includes(keyLabel) && !existingKeys.toLowerCase().includes(keyId.toLowerCase())) {
        generateKeyPair(tokenLabel, keyLabel, keyId);
    } else if (!force && !existing) {
        throw new Error(`PKCS#11 key already exists without matching registry record: ${keyLabel}`);
    }

    const directory = path.join(projectRoot, "pki", "citizens", citizenId, `pkcs11-v${version}`);
    fs.mkdirSync(directory, { recursive: true });
    const csrPath = path.join(directory, "citizen-pkcs11.csr");
    const certPath = path.join(directory, "citizen-pkcs11.crt");
    const certDer = path.join(directory, "citizen-pkcs11.der");
    const publicPath = path.join(directory, "citizen-pkcs11-public.pem");
    const chainPath = path.join(directory, "citizen-pkcs11-chain.pem");
    const requestConfig = path.join(directory, "request.cnf");
    const extensionConfig = path.join(directory, "extensions.cnf");
    const rootCert = path.join(projectRoot, "pki", "root-ca", "root-ca.crt");
    const rootKey = path.join(projectRoot, "pki", "root-ca", "root-ca.key");
    const rootSerial = path.join(projectRoot, "pki", "root-ca", "root-ca.srl");
    fs.writeFileSync(requestConfig, `[ req ]\nprompt = no\nutf8 = yes\ndistinguished_name = dn\nreq_extensions = req_ext\n\n[ dn ]\nC = VN\nST = Ho Chi Minh\nL = Thu Duc\nO = HCMUTE\nOU = Citizen PKCS11 Signing\nCN = ${safe(user.full_name)}\nUID = ${citizenId}\nemailAddress = ${safe(user.email)}\n\n[ req_ext ]\nsubjectAltName = @alt\n\n[ alt ]\nemail.1 = ${safe(user.email)}\nURI.1 = urn:nt219:citizen:${citizenId}\nURI.2 = urn:nt219:client-agent:pkcs11\n`, "utf8");
    fs.writeFileSync(extensionConfig, `[ v3_citizen ]\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\nbasicConstraints = critical, CA:false\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = clientAuth, emailProtection\nsubjectAltName = @alt\ncertificatePolicies = 1.3.6.1.4.1.55555.1.15\n\n[ alt ]\nemail.1 = ${safe(user.email)}\nURI.1 = urn:nt219:citizen:${citizenId}\nURI.2 = urn:nt219:client-agent:pkcs11\n`, "utf8");
    const openssl = envValue("CLIENT_AGENT_OPENSSL_BIN", envValue("OPENSSL_BIN", "openssl"));
    const uri = buildClientAgentPkcs11Uri(provisional);
    console.log("[3/8] Create CSR using the citizen private key inside SoftHSM/token");
    run(openssl, ["req", "-new", "-sha256", ...providerArgs(), "-key", uri, "-out", csrPath, "-config", requestConfig], { env: getClientAgentPkcs11Environment(projectRoot) });
    console.log("[4/8] Issue citizen PKCS#11 certificate from NT219 Test Root CA");
    run(openssl, ["x509", "-req", "-in", csrPath, "-CA", rootCert, "-CAkey", rootKey, ...(fs.existsSync(rootSerial) ? ["-CAserial", rootSerial] : ["-CAcreateserial"]), "-out", certPath, "-days", String(days), "-sha256", "-extfile", extensionConfig, "-extensions", "v3_citizen"]);
    console.log("[5/8] Export certificate and public artifacts");
    run(openssl, ["x509", "-in", certPath, "-outform", "DER", "-out", certDer]);
    const pub = run(openssl, ["x509", "-in", certPath, "-pubkey", "-noout"]);
    fs.writeFileSync(publicPath, pub.stdout, "ascii");
    const certPem = fs.readFileSync(certPath, "utf8");
    const rootPem = fs.readFileSync(rootCert, "utf8");
    fs.writeFileSync(chainPath, `${certPem.trim()}\n${rootPem.trim()}\n`, "ascii");
    writeCertificateObject(tokenLabel, certDer, keyLabel, keyId);
    const cert = new X509Certificate(certPem);
    const root = new X509Certificate(rootPem);
    if (!cert.verify(root.publicKey)) throw new Error("Citizen PKCS#11 certificate chain verification failed");

    console.log("[6/8] Register provider-specific citizen certificate");
    const record = {
        certificate_id: certificateId,
        version,
        signer_type: "citizen",
        purpose: "citizen-signing",
        user_id: user.id,
        citizen_id: citizenId,
        full_name: user.full_name,
        email: user.email,
        subject: cert.subject,
        issuer: cert.issuer,
        serial_number: cert.serialNumber,
        fingerprint_sha256: normalizeFingerprint(cert.fingerprint256),
        root_ca_fingerprint_sha256: normalizeFingerprint(root.fingerprint256),
        certificate_path: relativeBackend(certPath),
        private_key_path: null,
        certificate_chain_path: relativeBackend(chainPath),
        public_key_path: relativeBackend(publicPath),
        root_ca_certificate_path: relativeBackend(rootCert),
        status: "active",
        key_provider: "pkcs11",
        provider: "pkcs11",
        private_key_exportable: false,
        pkcs11_token_label: tokenLabel,
        pkcs11_key_label: keyLabel,
        pkcs11_key_id: keyId,
        pkcs11_binding_scheme: "nt219-citizen-deterministic-v1",
        pkcs11_uri: uri,
        valid_from: new Date(cert.validFrom).toISOString(),
        valid_to: new Date(cert.validTo).toISOString(),
        issued_at: new Date().toISOString(),
        revoked_at: null,
        revocation_reason: null,
    };
    saveCertificate(record);
    if (existing && force) updateCertificate(existing.certificate_id, { status: "superseded", superseded_at: new Date().toISOString(), superseded_by_certificate_id: certificateId });
    updateUser(user.id, {
        citizen_id: citizenId,
        citizen_pkcs11_certificate_id: certificateId,
        active_citizen_certificate_id: certificateId,
        citizen_certificate_status: "active",
    });
    const registryPath = path.join(projectRoot, "client-agent", "storage", "certificates.json");
    const registry = readJsonFileSync(registryPath, []).filter((item) => item.certificate_id !== certificateId);
    registry.push({
        certificate_id: certificateId,
        version,
        signer_type: "citizen",
        user_id: user.id,
        citizen_id: citizenId,
        full_name: user.full_name,
        email: user.email,
        status: "active",
        certificate_path: relativeProject(certPath),
        private_key_path: null,
        certificate_chain_path: relativeProject(chainPath),
        root_ca_certificate_path: relativeProject(rootCert),
        fingerprint_sha256: record.fingerprint_sha256,
        serial_number: record.serial_number,
        provider: "pkcs11",
        key_provider: "pkcs11",
        private_key_exportable: false,
        pkcs11_token_label: tokenLabel,
        pkcs11_key_label: keyLabel,
        pkcs11_key_id: keyId,
        pkcs11_binding_scheme: "nt219-citizen-deterministic-v1",
    });
    atomicWriteJsonSync(registryPath, registry, { backup: true });
    generateCertificateRevocationList();

    console.log("[7/8] Probe citizen PKCS#11 key");
    const status = getPkcs11CertificateStatus(record, projectRoot);
    if (!status.ready) throw new Error(`Citizen PKCS#11 key probe failed: ${status.error || "unknown"}`);
    console.log("[8/8] Sign and verify a canonical citizen payload");
    const canonicalPayload = buildCitizenSignaturePayload({ requestId: crypto.randomUUID(), documentId: "CITIZEN_PKCS11-PROBE", citizenId, userId: user.id, certificateId, documentDigestSha256: crypto.createHash("sha256").update("citizen-pkcs11-probe").digest("hex"), createdAt: new Date().toISOString() });
    const signed = signCanonicalPayloadWithPkcs11({ record, projectRoot, canonicalPayload });
    const signatureValid = verifyCitizenDetachedSignature({ signatureBase64: signed.signature.toString("base64"), canonicalPayload, certificatePem: signed.certificatePem });
    if (!signatureValid) throw new Error("Citizen PKCS#11 signature verification failed");
    const output = { status: "ready", user_id: user.id, citizen_id: citizenId, certificate_id: certificateId, provider: "pkcs11", key_reference: uri, private_key_exportable: false, runtime_probe: status, signature_probe_valid: true };
    fs.mkdirSync(path.join(projectRoot, "evidence"), { recursive: true });
    atomicWriteJsonSync(path.join(projectRoot, "evidence", "citizen-pkcs11-provisioning.json"), { generated_at: new Date().toISOString(), ...output }, { backup: true });
    console.log(JSON.stringify(output, null, 2));
} catch (error) {
    console.error(`[CITIZEN_PKCS11_PROVISIONING_FAILED] ${error.message}`);
    process.exit(2);
}

