import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { parseCliArgs, requireArg } from "./cli-args.js";
import {
    findOfficerByOfficerId,
    assignActiveCertificate,
    normalizeOfficerId,
} from "../src/services/officer-account.service.js";
import {
    findCertificatesByOfficerId,
    saveCertificate,
    updateCertificate,
} from "../src/services/certificate.repository.js";
import {
    verifyOfficerCertificate,
    normalizeFingerprint,
} from "../src/crypto/x509-pki.service.js";
import { PKI_ROOT_CA_CERT_PATH } from "../src/config/env.config.js";
import { atomicWriteJsonSync } from "../src/utils/atomic-file.util.js";
import { generateCertificateRevocationList } from "../src/crypto/crl.service.js";
import { writeAuditLog } from "../src/services/audit.service.js";

function runOpenSsl(args, { capture = false } = {}) {
    const result = spawnSync("openssl", args, {
        encoding: "utf8",
        stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit",
        shell: false,
    });

    if (result.error) {
        throw new Error(
            `Unable to run openssl: ${result.error.message}. Check: openssl version`
        );
    }
    if (result.status !== 0) {
        const details = capture ? (result.stderr || result.stdout || "") : "";
        throw new Error(`OpenSSL command failed (${result.status}) ${details}`.trim());
    }
    return capture ? String(result.stdout || "").trim() : "";
}

function safeConfigValue(value, name) {
    const text = String(value || "").trim();
    if (!text || /[\r\n\0]/.test(text)) {
        throw new Error(`${name} contains invalid characters`);
    }
    return text.replace(/\\/g, "\\\\");
}

function relativeFromBackend(absolutePath) {
    return path.relative(process.cwd(), absolutePath).replace(/\\/g, "/");
}

function nextVersion(officerId) {
    const versions = findCertificatesByOfficerId(officerId)
        .map((certificate) => {
            const match = String(certificate.certificate_id || "").match(/-V(\d+)$/);
            return match ? Number(match[1]) : 0;
        });
    return versions.length === 0 ? 1 : Math.max(...versions) + 1;
}

try {
    const args = parseCliArgs();
    const officerId = normalizeOfficerId(requireArg(args, "officer-id"));
    const renew = args.renew === true;
    const days = Number.parseInt(args.days || "825", 10);

    if (!Number.isInteger(days) || days < 1 || days > 3650) {
        throw new Error("--days must be an integer from 1 to 3650");
    }

    runOpenSsl(["version"], { capture: true });

    const officer = findOfficerByOfficerId(officerId);
    if (!officer) throw new Error("OFFICER_NOT_FOUND");
    if (!Array.isArray(officer.roles) || !officer.roles.includes("officer")) {
        throw new Error("USER_IS_NOT_OFFICER");
    }
    if (officer.status !== "active") {
        throw new Error("OFFICER_ACCOUNT_NOT_ACTIVE");
    }

    const activeCertificate = findCertificatesByOfficerId(officerId).find((certificate) =>
        certificate.status === "active" &&
        certificate.purpose !== "remote-signing" &&
        String(certificate.key_provider || certificate.provider || "software").toLowerCase() !== "softhsm"
    ) || null;
    if (activeCertificate && !renew) {
        throw new Error(
            `ACTIVE_CERTIFICATE_ALREADY_EXISTS (${activeCertificate.certificate_id}). ` +
            "Use --renew to issue a new version."
        );
    }

    const projectRoot = path.resolve(process.cwd(), "..");
    const pkiRoot = path.join(projectRoot, "pki");
    const rootCertificatePath = path.resolve(process.cwd(), PKI_ROOT_CA_CERT_PATH);
    const rootPrivateKeyPath = path.join(pkiRoot, "root-ca", "root-ca.key");
    const rootSerialPath = path.join(pkiRoot, "root-ca", "root-ca.srl");

    if (!fs.existsSync(rootCertificatePath) || !fs.existsSync(rootPrivateKeyPath)) {
        throw new Error("ROOT_CA_NOT_FOUND");
    }

    const version = nextVersion(officerId);
    const certificateId = `CERT-${officerId}-V${version}`;
    const versionDirectory = path.join(
        pkiRoot,
        "officers",
        officerId,
        `v${version}`
    );

    if (fs.existsSync(versionDirectory)) {
        throw new Error(`Certificate directory already exists: ${versionDirectory}`);
    }
    fs.mkdirSync(versionDirectory, { recursive: true });

    const keyPath = path.join(versionDirectory, "officer.key");
    const csrPath = path.join(versionDirectory, "officer.csr");
    const certificatePath = path.join(versionDirectory, "officer.crt");
    const chainPath = path.join(versionDirectory, "officer-chain.pem");
    const publicKeyPath = path.join(versionDirectory, "officer-public.pem");
    const fingerprintPath = path.join(
        versionDirectory,
        "officer-fingerprint-sha256.txt"
    );
    const requestConfigPath = path.join(versionDirectory, "request.cnf");
    const extensionConfigPath = path.join(versionDirectory, "extensions.cnf");

    const fullName = safeConfigValue(officer.full_name, "full_name");
    const email = safeConfigValue(officer.email, "email");

    const requestConfig = `[ req ]
prompt = no
utf8 = yes
string_mask = utf8only
distinguished_name = dn
req_extensions = req_ext

[ dn ]
C = VN
ST = Ho Chi Minh
L = Thu Duc
O = HCMUTE
OU = Public Administrative Services Officer
CN = ${fullName}
UID = ${officerId}
emailAddress = ${email}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
email.1 = ${email}
URI.1 = urn:nt219:officer:${officerId}
`;

    const extensionConfig = `[ v3_officer ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = emailProtection, clientAuth
subjectAltName = @alt_names
certificatePolicies = 1.3.6.1.4.1.55555.1.1

[ alt_names ]
email.1 = ${email}
URI.1 = urn:nt219:officer:${officerId}
`;

    fs.writeFileSync(requestConfigPath, requestConfig, "utf8");
    fs.writeFileSync(extensionConfigPath, extensionConfig, "utf8");

    try {
        console.log(`[1/7] Generate ECDSA P-256 private key for ${officerId}`);
        runOpenSsl([
            "genpkey",
            "-algorithm", "EC",
            "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-out", keyPath,
        ]);

        try { fs.chmodSync(keyPath, 0o600); } catch { /* Windows may ignore */ }

        console.log("[2/7] Create certificate signing request (CSR)");
        runOpenSsl([
            "req", "-new", "-sha256",
            "-key", keyPath,
            "-out", csrPath,
            "-config", requestConfigPath,
        ]);

        console.log("[3/7] Issue officer certificate from NT219 Test Root CA");
        const signArgs = [
            "x509", "-req",
            "-in", csrPath,
            "-CA", rootCertificatePath,
            "-CAkey", rootPrivateKeyPath,
        ];
        if (fs.existsSync(rootSerialPath)) {
            signArgs.push("-CAserial", rootSerialPath);
        } else {
            signArgs.push("-CAcreateserial");
        }
        signArgs.push(
            "-out", certificatePath,
            "-days", String(days),
            "-sha256",
            "-extfile", extensionConfigPath,
            "-extensions", "v3_officer"
        );
        runOpenSsl(signArgs);

        console.log("[4/7] Export chain, public key and fingerprint");
        const certificatePem = fs.readFileSync(certificatePath, "utf8");
        const rootCertificatePem = fs.readFileSync(rootCertificatePath, "utf8");
        fs.writeFileSync(chainPath, `${certificatePem.trim()}\n${rootCertificatePem.trim()}\n`, "ascii");

        const publicKeyPem = runOpenSsl(
            ["x509", "-in", certificatePath, "-pubkey", "-noout"],
            { capture: true }
        );
        fs.writeFileSync(publicKeyPath, `${publicKeyPem}\n`, "ascii");

        const parsed = new X509Certificate(certificatePem);
        const fingerprint = normalizeFingerprint(parsed.fingerprint256);
        fs.writeFileSync(fingerprintPath, `${fingerprint}\n`, "ascii");

        console.log("[5/7] Validate certificate owner, chain and validity");
        const verified = verifyOfficerCertificate({
            officerCertificatePem: certificatePem,
            rootCertificatePem,
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
            private_key_path: relativeFromBackend(keyPath),
            certificate_chain_path: relativeFromBackend(chainPath),
            public_key_path: relativeFromBackend(publicKeyPath),
            root_ca_certificate_path: relativeFromBackend(rootCertificatePath),
            status: "active",
            valid_from: verified.metadata.valid_from,
            valid_to: verified.metadata.valid_to,
            issued_at: issuedAt,
            revoked_at: null,
            revocation_reason: null,
            replaced_at: null,
            replaced_by_certificate_id: null,
        };

        console.log("[6/7] Register certificate and bind it to officer account");
        saveCertificate(record);
        if (activeCertificate && renew) {
            updateCertificate(activeCertificate.certificate_id, {
                status: "superseded",
                superseded_at: issuedAt,
                superseded_by_certificate_id: certificateId,
                replaced_at: issuedAt,
                replaced_by_certificate_id: certificateId,
            });
        }
        assignActiveCertificate({
            officerId,
            certificateId,
            certificateStatus: "active",
        });

        atomicWriteJsonSync(
            path.join(versionDirectory, "metadata.json"),
            {
                ...record,
                lab_only: true,
                note: "NT219 Test CA certificate for PoC only",
            },
            { backup: false }
        );

        generateCertificateRevocationList();
        await writeAuditLog({
            action: renew ? "CERTIFICATE_RENEWED" : "CERTIFICATE_ISSUED",
            userId: officer.id,
            result: "success",
            details: {
                officer_id: officerId,
                certificate_id: certificateId,
                previous_certificate_id: activeCertificate?.certificate_id || null,
            },
        });

        console.log("[7/7] Certificate issuance completed and CRL refreshed");
        console.log("\nOFFICER CERTIFICATE ISSUANCE: PASS");
        console.log(JSON.stringify({
            officer_id: officerId,
            user_id: officer.id,
            certificate_id: certificateId,
            subject: verified.metadata.subject,
            issuer: verified.metadata.issuer,
            fingerprint_sha256: fingerprint,
            valid_from: verified.metadata.valid_from,
            valid_to: verified.metadata.valid_to,
            certificate_path: record.certificate_path,
        }, null, 2));
    } catch (error) {
        fs.rmSync(versionDirectory, { recursive: true, force: true });
        throw error;
    }
} catch (error) {
    console.error("\nOFFICER CERTIFICATE ISSUANCE: FAIL");
    console.error(error.message);
    process.exitCode = 1;
}
