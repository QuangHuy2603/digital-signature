import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { atomicWriteJsonSync, readJsonFileSync } from "../utils/atomic-file.util.js";
import { verifyPadesPdf } from "../crypto/pades.service.js";
import { OPENSSL_BIN, PKI_ROOT_CA_CERT_PATH, PKI_CRL_PATH } from "../config/env.config.js";
import { OfficerCertificateError } from "../crypto/x509-pki.service.js";

const ARCHIVE_ROOT = path.resolve(process.cwd(), process.env.LTV_ARCHIVE_PATH || "storage/archive");
const SEAL_KEY = path.resolve(process.cwd(), process.env.ARCHIVE_SEAL_KEY_PATH || "../pki/archive/archive-seal.key");
const SEAL_CERT = path.resolve(process.cwd(), process.env.ARCHIVE_SEAL_CERT_PATH || "../pki/archive/archive-seal.crt");
const ROOT_CERT = path.resolve(process.cwd(), PKI_ROOT_CA_CERT_PATH);
const CRL_PATH = path.resolve(process.cwd(), PKI_CRL_PATH);

function sha256File(filePath) {
    return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex").toUpperCase();
}
function projectOpenSslConfig() {
    return path.resolve(process.cwd(), "../pki/config/openssl-base.cnf");
}
function runOpenSsl(args, { allowFailure = false } = {}) {
    const env = { ...process.env };
    if (!env.OPENSSL_CONF || !fs.existsSync(env.OPENSSL_CONF)) env.OPENSSL_CONF = projectOpenSslConfig();
    const result = spawnSync(OPENSSL_BIN, args, {
        cwd: process.cwd(), encoding: "utf8", windowsHide: true, stdio: "pipe", env,
    });
    if ((result.error || result.status !== 0) && !allowFailure) {
        throw new OfficerCertificateError(
            String(result.stderr || result.stdout || result.error?.message || "Archive OpenSSL operation failed").trim(),
            "ARCHIVE_SEAL_OPERATION_FAILED",
            500
        );
    }
    return result;
}
function ensureDir(dir) { fs.mkdirSync(dir, { recursive: true }); return dir; }
function safeCopy(source, target) {
    if (!source || !fs.existsSync(source)) return false;
    ensureDir(path.dirname(target));
    fs.copyFileSync(source, target);
    return true;
}
function writeBinaryBase64(encoded, target) {
    if (!encoded) return false;
    ensureDir(path.dirname(target));
    fs.writeFileSync(target, Buffer.from(encoded, "base64"));
    return true;
}
function listFilesRecursively(root, current = root) {
    const output = [];
    if (!fs.existsSync(current)) return output;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
        const full = path.join(current, entry.name);
        if (entry.isDirectory()) output.push(...listFilesRecursively(root, full));
        else output.push(path.relative(root, full).replaceAll("\\", "/"));
    }
    return output;
}
function archiveIdFor(documentId) {
    return `ARCH-${documentId}-${Date.now()}-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
}

export function getArchiveStatus() {
    ensureDir(ARCHIVE_ROOT);
    let sealTrusted = false;
    if (fs.existsSync(SEAL_CERT) && fs.existsSync(ROOT_CERT)) {
        sealTrusted = runOpenSsl(["verify", "-CAfile", ROOT_CERT, SEAL_CERT], { allowFailure: true }).status === 0;
    }
    const archives = fs.readdirSync(ARCHIVE_ROOT, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => entry.name);
    return {
        ready: fs.existsSync(SEAL_KEY) && fs.existsSync(SEAL_CERT) && sealTrusted,
        service: "nt219-ltv-archive",
        archive_root: ARCHIVE_ROOT,
        archive_count: archives.length,
        seal_certificate_path: SEAL_CERT,
        seal_certificate_trusted: sealTrusted,
        manifest_algorithm: "SHA-256",
        manifest_signature_algorithm: "ECDSA-P256-SHA256",
        evidence_model: "embedded PAdES-LT DSS/VRI plus external sealed evidence bundle (PoC)",
    };
}

export function createLtvArchive({
    documentId,
    originalPdfPath,
    signedPdfPath,
    metadata,
    certificateRecord,
    ocspEvidence,
    padesEvidence,
    timestampEvidence,
} = {}) {
    if (!documentId || !originalPdfPath || !signedPdfPath || !metadata) {
        throw new OfficerCertificateError("LTV archive input is incomplete", "ARCHIVE_INPUT_REQUIRED", 400);
    }
    const status = getArchiveStatus();
    if (!status.ready) {
        throw new OfficerCertificateError("Archive seal identity is not ready", "ARCHIVE_SEAL_NOT_READY", 503);
    }
    const archiveId = archiveIdFor(documentId);
    const archivePath = path.join(ARCHIVE_ROOT, archiveId);
    ensureDir(archivePath);

    try {
        safeCopy(originalPdfPath, path.join(archivePath, "documents/original.pdf"));
        safeCopy(signedPdfPath, path.join(archivePath, "documents/signed.pdf"));
        atomicWriteJsonSync(path.join(archivePath, "metadata/document-metadata.json"), metadata, { backup: false });
        const padesVerification = padesEvidence?.verification?.valid === true
            ? padesEvidence.verification
            : verifyPadesPdf({
                pdfPath: signedPdfPath,
                expectedFingerprint: certificateRecord?.fingerprint_sha256 || "",
            });
        atomicWriteJsonSync(path.join(archivePath, "reports/verification-report.json"), {
            generated_at: new Date().toISOString(),
            document_id: documentId,
            pades: padesVerification,
            ocsp_status_at_signing: ocspEvidence?.certificate_status || null,
            certificate_id: certificateRecord?.certificate_id || null,
        }, { backup: false });
        atomicWriteJsonSync(path.join(archivePath, "reports/pades-lt-evidence.json"), {
            generated_at: new Date().toISOString(),
            document_id: documentId,
            baseline_level: padesVerification.baseline_level || null,
            dss_present: padesVerification.dss_present === true,
            vri_present: padesVerification.vri_present === true,
            offline_verification_ready: padesVerification.offline_verification_ready === true,
            pades_lt: padesVerification.pades_lt || null,
        }, { backup: false });

        safeCopy(path.resolve(process.cwd(), certificateRecord?.certificate_path || ""), path.join(archivePath, "certificates/officer.crt"));
        safeCopy(ROOT_CERT, path.join(archivePath, "certificates/root-ca.crt"));
        safeCopy(SEAL_CERT, path.join(archivePath, "certificates/archive-seal.crt"));
        safeCopy(CRL_PATH, path.join(archivePath, "revocation/root-ca.crl"));
        writeBinaryBase64(ocspEvidence?.request_der_base64, path.join(archivePath, "revocation/ocsp-request.der"));
        writeBinaryBase64(ocspEvidence?.response_der_base64, path.join(archivePath, "revocation/ocsp-response.der"));
        atomicWriteJsonSync(path.join(archivePath, "revocation/ocsp-status.json"), ocspEvidence || {}, { backup: false });

        safeCopy(padesEvidence?.cms_bb_der_path, path.join(archivePath, "signatures/pades-bb.cms.der"));
        safeCopy(padesEvidence?.cms_der_path, path.join(archivePath, "signatures/pades-bt.cms.der"));
        safeCopy(timestampEvidence?.request_path, path.join(archivePath, "timestamps/pades-signature-timestamp.tsq"));
        safeCopy(timestampEvidence?.response_path, path.join(archivePath, "timestamps/pades-signature-timestamp.tsr"));

        atomicWriteJsonSync(path.join(archivePath, "archive-metadata.json"), {
            archive_id: archiveId,
            document_id: documentId,
            created_at: new Date().toISOString(),
            archive_profile: "NT219-PADES-LT-ARCHIVE-V2",
            pades_level: metadata.pades_level || "PAdES-LT",
            certificate_id: certificateRecord?.certificate_id || null,
            key_provider: metadata.key_provider || null,
            tsp_mode: metadata.tsp_mode || null,
            limitation: "PAdES-LT with embedded DSS/VRI plus external sealed archive; not a claim of PAdES-LTA archival timestamps.",
        }, { backup: false });

        const excluded = new Set(["manifest.json", "manifest.sig"]);
        const files = listFilesRecursively(archivePath)
            .filter((relative) => !excluded.has(relative))
            .sort()
            .map((relative) => {
                const full = path.join(archivePath, relative);
                return { path: relative, size_bytes: fs.statSync(full).size, sha256: sha256File(full) };
            });
        const manifest = {
            archive_id: archiveId,
            document_id: documentId,
            profile: "NT219-PADES-LT-ARCHIVE-V2",
            created_at: new Date().toISOString(),
            hash_algorithm: "SHA-256",
            files,
        };
        const manifestPath = path.join(archivePath, "manifest.json");
        const signaturePath = path.join(archivePath, "manifest.sig");
        atomicWriteJsonSync(manifestPath, manifest, { backup: false });
        runOpenSsl(["dgst", "-sha256", "-sign", SEAL_KEY, "-out", signaturePath, manifestPath]);
        const verification = verifyLtvArchive(archiveId);
        if (!verification.valid) {
            throw new OfficerCertificateError(`Archive self-verification failed: ${verification.reason}`, "ARCHIVE_SELF_VERIFICATION_FAILED", 500);
        }
        return {
            archive_id: archiveId,
            archive_path: archivePath,
            manifest_path: manifestPath,
            manifest_signature_path: signaturePath,
            manifest_sha256: sha256File(manifestPath),
            file_count: files.length,
            valid: true,
            verification,
        };
    } catch (error) {
        fs.rmSync(archivePath, { recursive: true, force: true });
        throw error;
    }
}

export function verifyLtvArchive(archiveId) {
    const archivePath = path.join(ARCHIVE_ROOT, String(archiveId || ""));
    const manifestPath = path.join(archivePath, "manifest.json");
    const signaturePath = path.join(archivePath, "manifest.sig");
    if (!fs.existsSync(manifestPath) || !fs.existsSync(signaturePath)) {
        return { valid: false, reason: "ARCHIVE_MANIFEST_NOT_FOUND", archive_id: archiveId };
    }
    let manifest;
    try { manifest = readJsonFileSync(manifestPath, null, { recoverFromBackup: false }); }
    catch { return { valid: false, reason: "ARCHIVE_MANIFEST_INVALID", archive_id: archiveId }; }
    if (!manifest || manifest.archive_id !== archiveId || !Array.isArray(manifest.files)) {
        return { valid: false, reason: "ARCHIVE_MANIFEST_INVALID", archive_id: archiveId };
    }
    const mismatches = [];
    for (const item of manifest.files) {
        const full = path.resolve(archivePath, item.path);
        if (!full.startsWith(`${path.resolve(archivePath)}${path.sep}`) || !fs.existsSync(full)) {
            mismatches.push({ path: item.path, reason: "MISSING" });
            continue;
        }
        const digest = sha256File(full);
        if (digest !== item.sha256 || fs.statSync(full).size !== item.size_bytes) {
            mismatches.push({ path: item.path, reason: "HASH_OR_SIZE_MISMATCH" });
        }
    }
    const archivedSealCert = path.join(archivePath, "certificates/archive-seal.crt");
    const sealCertificateForVerification = fs.existsSync(archivedSealCert) ? archivedSealCert : SEAL_CERT;
    const tempPub = path.join(archivePath, ".archive-seal-public.pem");
    const extract = runOpenSsl(["x509", "-in", sealCertificateForVerification, "-pubkey", "-noout"], { allowFailure: true });
    let signatureValid = false;
    if (extract.status === 0) {
        fs.writeFileSync(tempPub, extract.stdout);
        signatureValid = runOpenSsl([
            "dgst", "-sha256", "-verify", tempPub, "-signature", signaturePath, manifestPath,
        ], { allowFailure: true }).status === 0;
        fs.rmSync(tempPub, { force: true });
    }
    const certTrusted = runOpenSsl(["verify", "-CAfile", ROOT_CERT, sealCertificateForVerification], { allowFailure: true }).status === 0;
    const valid = mismatches.length === 0 && signatureValid && certTrusted;
    return {
        valid,
        reason: valid ? "VALID_LTV_ARCHIVE" : mismatches.length ? "ARCHIVE_FILE_TAMPERED" : !signatureValid ? "ARCHIVE_MANIFEST_SIGNATURE_INVALID" : "ARCHIVE_SEAL_CERTIFICATE_UNTRUSTED",
        archive_id: archiveId,
        document_id: manifest.document_id,
        file_count: manifest.files.length,
        mismatches,
        manifest_signature_valid: signatureValid,
        archive_seal_certificate_trusted: certTrusted,
        manifest_sha256: sha256File(manifestPath),
    };
}

export function listArchives() {
    ensureDir(ARCHIVE_ROOT);
    return fs.readdirSync(ARCHIVE_ROOT, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => verifyLtvArchive(entry.name));
}
