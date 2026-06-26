import crypto, { X509Certificate } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import "../src/config/env.config.js";
import { parseCliArgs } from "./cli-args.js";
import { listUsers, updateUser } from "../src/services/auth.service.js";
import { findActiveCitizenCertificate, findCertificatesByCitizenId, saveCertificate } from "../src/services/certificate.repository.js";
import { generateCertificateRevocationList } from "../src/crypto/crl.service.js";
import { normalizeFingerprint } from "../src/crypto/x509-pki.service.js";
import { atomicWriteJsonSync, readJsonFileSync } from "../src/utils/atomic-file.util.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(__dirname, "..");
const projectRoot = path.resolve(backendRoot, "..");
const args = parseCliArgs();
const requestedUserId = args["user-id"]
    ? String(args["user-id"])
    : null;
const force = args.force === true;
const days = Number.parseInt(args.days || "825", 10);

function run(command, commandArgs) {
    const result = spawnSync(command, commandArgs, {
        cwd: backendRoot,
        encoding: "utf8",
        windowsHide: true,
        stdio: "pipe",
        env: process.env,
    });
    if (result.error || result.status !== 0) {
        throw new Error(result.error?.message || String(result.stderr || result.stdout || `exit ${result.status}`).trim());
    }
    return result;
}

function relativeProject(filePath) {
    return path.relative(projectRoot, filePath).replaceAll("\\", "/");
}
function relativeBackend(filePath) {
    return path.relative(backendRoot, filePath).replaceAll("\\", "/");
}
function safe(value) {
    return String(value || "").replace(/[\r\n\0]/g, " ").replace(/[\\]/g, "\\\\");
}
function nextVersion(records) {
    return Math.max(0, ...records.map((item) => Number(item.version) || 0)) + 1;
}

try {
    const users = listUsers();

    const user = requestedUserId
        ? users.find(
            (item) => String(item.id) === requestedUserId
        )
        : users.find(
            (item) => item.citizen_id === "CITIZEN-001"
        )
            || users.find(
                (item) =>
                    String(item.email || "").toLowerCase()
                    === "citizen@test.com"
            )
            || users.find(
                (item) =>
                    Array.isArray(item.roles)
                    && item.roles.includes("citizen")
            );

    if (
        !user
        || !Array.isArray(user.roles)
        || !user.roles.includes("citizen")
    ) {
        throw new Error(
            `Citizen user ${requestedUserId || "demo"} was not found`
        );
    }
    const citizenId = user.citizen_id || `CITIZEN-${String(user.id).padStart(3, "0")}`;
    if (!user.citizen_id) updateUser(user.id, { citizen_id: citizenId });
    const existing = findActiveCitizenCertificate(citizenId, "software");
    if (existing && !force) {
        console.log(JSON.stringify({ status: "already_provisioned", user_id: user.id, citizen_id: citizenId, certificate_id: existing.certificate_id }, null, 2));
        process.exit(0);
    }
    const version = nextVersion(findCertificatesByCitizenId(citizenId));
    const certificateId = `CERT-${citizenId}-SOFTWARE-V${version}`;
    const directory = path.join(projectRoot, "pki", "citizens", citizenId, `software-v${version}`);
    fs.mkdirSync(directory, { recursive: true });
    const keyPath = path.join(directory, "citizen.key");
    const csrPath = path.join(directory, "citizen.csr");
    const certPath = path.join(directory, "citizen.crt");
    const publicPath = path.join(directory, "citizen-public.pem");
    const chainPath = path.join(directory, "citizen-chain.pem");
    const requestConfig = path.join(directory, "request.cnf");
    const extensionConfig = path.join(directory, "extensions.cnf");
    const rootCert = path.join(projectRoot, "pki", "root-ca", "root-ca.crt");
    const rootKey = path.join(projectRoot, "pki", "root-ca", "root-ca.key");
    const rootSerial = path.join(projectRoot, "pki", "root-ca", "root-ca.srl");
    fs.writeFileSync(requestConfig, `[ req ]\nprompt = no\nutf8 = yes\ndistinguished_name = dn\nreq_extensions = req_ext\n\n[ dn ]\nC = VN\nST = Ho Chi Minh\nL = Thu Duc\nO = HCMUTE\nOU = Citizen Software Signing\nCN = ${safe(user.full_name)}\nUID = ${citizenId}\nemailAddress = ${safe(user.email)}\n\n[ req_ext ]\nsubjectAltName = @alt\n\n[ alt ]\nemail.1 = ${safe(user.email)}\nURI.1 = urn:nt219:citizen:${citizenId}\nURI.2 = urn:nt219:client-agent:software\n`, "utf8");
    fs.writeFileSync(extensionConfig, `[ v3_citizen ]\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\nbasicConstraints = critical, CA:false\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = clientAuth, emailProtection\nsubjectAltName = @alt\ncertificatePolicies = 1.3.6.1.4.1.55555.1.14\n\n[ alt ]\nemail.1 = ${safe(user.email)}\nURI.1 = urn:nt219:citizen:${citizenId}\nURI.2 = urn:nt219:client-agent:software\n`, "utf8");
    const openssl = process.env.OPENSSL_BIN || "openssl";
    run(openssl, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", keyPath]);
    run(openssl, ["req", "-new", "-sha256", "-key", keyPath, "-out", csrPath, "-config", requestConfig]);
    run(openssl, ["x509", "-req", "-in", csrPath, "-CA", rootCert, "-CAkey", rootKey, ...(fs.existsSync(rootSerial) ? ["-CAserial", rootSerial] : ["-CAcreateserial"]), "-out", certPath, "-days", String(days), "-sha256", "-extfile", extensionConfig, "-extensions", "v3_citizen"]);
    const publicResult = run(openssl, ["x509", "-in", certPath, "-pubkey", "-noout"]);
    fs.writeFileSync(publicPath, publicResult.stdout, "ascii");
    const certPem = fs.readFileSync(certPath, "utf8");
    const rootPem = fs.readFileSync(rootCert, "utf8");
    fs.writeFileSync(chainPath, `${certPem.trim()}\n${rootPem.trim()}\n`, "ascii");
    const cert = new X509Certificate(certPem);
    const root = new X509Certificate(rootPem);
    if (!cert.verify(root.publicKey)) throw new Error("Issued citizen certificate chain verification failed");
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
        private_key_path: relativeBackend(keyPath),
        certificate_chain_path: relativeBackend(chainPath),
        public_key_path: relativeBackend(publicPath),
        root_ca_certificate_path: relativeBackend(rootCert),
        status: "active",
        key_provider: "software",
        provider: "software",
        private_key_exportable: true,
        valid_from: new Date(cert.validFrom).toISOString(),
        valid_to: new Date(cert.validTo).toISOString(),
        issued_at: new Date().toISOString(),
        revoked_at: null,
        revocation_reason: null,
    };
    saveCertificate(record);
    updateUser(user.id, {
        citizen_id: citizenId,
        citizen_software_certificate_id: certificateId,
        active_citizen_certificate_id: certificateId,
        citizen_certificate_status: "active",
    });
    const agentRegistryPath = path.join(projectRoot, "client-agent", "storage", "certificates.json");
    const registry = readJsonFileSync(agentRegistryPath, []);
    registry.push({
        certificate_id: certificateId,
        signer_type: "citizen",
        user_id: user.id,
        citizen_id: citizenId,
        full_name: user.full_name,
        email: user.email,
        status: "active",
        certificate_path: relativeProject(certPath),
        private_key_path: relativeProject(keyPath),
        certificate_chain_path: relativeProject(chainPath),
        root_ca_certificate_path: relativeProject(rootCert),
        fingerprint_sha256: record.fingerprint_sha256,
        serial_number: record.serial_number,
        provider: "software",
        key_provider: "software",
        private_key_exportable: true,
    });
    atomicWriteJsonSync(agentRegistryPath, registry, { backup: true });
    generateCertificateRevocationList();
    console.log(JSON.stringify({ status: "ready", user_id: user.id, citizen_id: citizenId, certificate_id: certificateId, provider: "software", private_key_exportable: true }, null, 2));
} catch (error) {
    console.error(`[CITIZEN_SOFTWARE_CERTIFICATE_FAILED] ${error.message}`);
    process.exit(2);
}

