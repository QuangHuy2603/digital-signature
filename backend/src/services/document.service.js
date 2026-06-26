/**
 * document.service.js - Điều phối nghiệp vụ tài liệu
 * Xử lý toàn bộ vòng đời tài liệu: nộp hồ sơ → ký số → xác minh
 */
import crypto from "crypto";
import fs from "fs";
import { hashFile, hashText } from "../crypto/hash.service.js";
import { saveDocument, updateDocument, findDocumentById, listDocuments } from "./document.repository.js";
import { writeAuditLog } from "./audit.service.js";
import { getUserById } from "./auth.service.js";
import path from "path";
import fsExtra from "fs-extra";
import { createDocumentFolder } from "../utils/storage.util.js";
import { generateQrCode } from "./qr.service.js";
import { embedQrIntoPdf } from "./pdf.service.js";
import { atomicWriteJsonSync } from "../utils/atomic-file.util.js";
import { OfficerCertificateError } from "../crypto/x509-pki.service.js";
import { loadOfficerSigningIdentity } from "../crypto/officer-pki.service.js";
import { PKI_REQUIRE_CERTIFICATE, REMOTE_OTP_REQUIRED } from "../config/env.config.js";
import { checkCertificateRevocation } from "../crypto/crl.service.js";
import {
    assertCertificateGoodViaOcsp,
    checkCertificateStatusWithOcsp,
    verifyOcspResponse,
} from "../crypto/ocsp.service.js";
import { findCertificateById } from "./certificate.repository.js";
import { verifyPadesPdf } from "../crypto/pades.service.js";
import { upgradePadesBtToLt } from "../crypto/pades-lt.service.js";
import { signPadesViaTsp } from "./tsp-client.service.js";
import { signPadesViaClientAgent } from "./client-agent-client.service.js";
import { createLtvArchive, verifyLtvArchive } from "./archive.service.js";
import {
    reserveSigningRequest,
    completeSigningRequest,
    failSigningRequest,
} from "./signing-request.service.js";
import {
    reserveRemoteSigningAuthorization,
    completeRemoteSigningAuthorization,
    failRemoteSigningAuthorization,
} from "./remote-signing-authorization.service.js";

/** Tạo mã hồ sơ duy nhất theo định dạng HS-{NĂM}-{8 ký tự UUID} */
const generateDocumentId = () => {
    return `HS-${new Date().getFullYear()}-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
};

/** Tạo token xác minh ngẫu nhiên 32 bytes, mã hóa base64url */
const generateVerificationToken = () => {
    return crypto.randomBytes(32).toString("base64url");
};

/** Tạo URL xác minh công khai từ PUBLIC_VERIFY_URL trong .env */
const buildVerifyUrl = (documentId, token) => {
    const baseUrl = process.env.PUBLIC_VERIFY_URL || "http://localhost:3000/api/public/documents/verify";
    return `${baseUrl}/${documentId}?token=${token}`;
};

/**
 * Xác minh tính hợp lệ của tài liệu: kiểm tra token, hash file và chữ ký PAdES-LT.
 * @param {Object} params - { documentId, token, filePath (tùy chọn), userId, ipAddress }
 * @returns {Object} Kết quả xác minh: valid, reason, hash_matched, signature_valid, ...
 */
export const verifyDocument = async ({ documentId, token, filePath = null, userId = null, ipAddress = null }) => {
    const document = await findDocumentById(documentId);
    if (!document) {
        await writeAuditLog({ action: "verify", documentId, userId, ipAddress, result: "fail" });
        return { valid: false, reason: "DOCUMENT_NOT_FOUND" };
    }
    if (document.token_hash !== hashText(token || "")) {
        await writeAuditLog({ action: "verify", documentId, userId, ipAddress, result: "fail" });
        return { valid: false, reason: "INVALID_TOKEN" };
    }
    if (document.status !== "issued") {
        return { valid: false, reason: "DOCUMENT_NOT_ACTIVE", status: document.status };
    }

    const targetPath = filePath || document.signed_pdf_path;
    if (!targetPath || !fs.existsSync(targetPath)) {
        return { valid: false, reason: "SIGNED_PDF_NOT_FOUND" };
    }
    const currentHash = await hashFile(targetPath);
    const hashMatched = currentHash === document.file_hash;
    const padesResult = verifyPadesPdf({
        pdfPath: targetPath,
        expectedFingerprint: document.officer_certificate?.fingerprint_sha256 || "",
    });

    const certificateRecord = document.certificate_id
        ? findCertificateById(document.certificate_id)
        : null;
    const storedOcspResult = document.ocsp_evidence_at_signing?.request_der_base64 &&
        document.ocsp_evidence_at_signing?.response_der_base64
        ? verifyOcspResponse({
            requestDerBase64: document.ocsp_evidence_at_signing.request_der_base64,
            responseDerBase64: document.ocsp_evidence_at_signing.response_der_base64,
            now: padesResult.timestamp ? new Date(padesResult.timestamp) : new Date(document.signed_at),
        })
        : { valid: false, reason: "OCSP_EVIDENCE_NOT_AVAILABLE" };
    const currentOcspResult = certificateRecord
        ? checkCertificateStatusWithOcsp({
            certificateRecord,
            serialNumber: document.officer_certificate?.serial_number || "",
            includeDer: false,
        })
        : null;
    const revocationResult = certificateRecord
        ? checkCertificateRevocation({
            certificateRecord,
            serialNumber: document.officer_certificate?.serial_number || "",
        })
        : {
            checked: false, trusted: false, revoked: false,
            reason: "CERTIFICATE_RECORD_NOT_FOUND",
            crl: { available: false, signature_valid: false },
        };

    const effectiveRevoked = currentOcspResult ? currentOcspResult.revoked : revocationResult.revoked;
    const effectiveRevocationTrusted = currentOcspResult ? currentOcspResult.trusted : revocationResult.trusted;
    const revokedAt = certificateRecord?.revoked_at || revocationResult.revoked_at || null;
    const timestampBeforeRevocation = Boolean(
        effectiveRevoked && padesResult.timestamp_valid && padesResult.timestamp && revokedAt &&
        new Date(padesResult.timestamp) < new Date(revokedAt)
    );
    const embeddedLtEvidenceValid = padesResult.baseline_level === "PAdES-LT" &&
        padesResult.pades_lt?.valid === true &&
        padesResult.pades_lt?.offline_verification_ready === true;
    const ocspAtSigningValid = embeddedLtEvidenceValid ||
        (storedOcspResult.valid && storedOcspResult.certificate_status === "good");
    const revocationValid = effectiveRevocationTrusted && (!effectiveRevoked || timestampBeforeRevocation);
    const archiveResult = document.archive_id
        ? verifyLtvArchive(document.archive_id)
        : { valid: false, reason: "LTV_ARCHIVE_NOT_AVAILABLE" };
    const archiveRequired = String(process.env.LTV_ARCHIVE_REQUIRED || "true").toLowerCase() === "true";
    const archiveValid = archiveRequired ? archiveResult.valid : true;
    const valid = hashMatched && padesResult.valid && ocspAtSigningValid && revocationValid && archiveValid;

    const reason = valid
        ? effectiveRevoked && timestampBeforeRevocation
            ? "VALID_DOCUMENT_SIGNED_BEFORE_REVOCATION"
            : "VALID_DOCUMENT"
        : !hashMatched
            ? "DOCUMENT_HASH_CHANGED"
            : !padesResult.valid
                ? padesResult.reason || "PADES_INVALID"
                : !archiveValid
                    ? archiveResult.reason || "LTV_ARCHIVE_INVALID"
                : !embeddedLtEvidenceValid && !storedOcspResult.valid
                    ? storedOcspResult.reason || "OCSP_EVIDENCE_INVALID"
                    : !embeddedLtEvidenceValid && storedOcspResult.certificate_status !== "good"
                        ? "OCSP_CERTIFICATE_NOT_GOOD_AT_SIGNING"
                        : !effectiveRevocationTrusted
                            ? currentOcspResult?.reason || revocationResult.reason || "REVOCATION_STATUS_NOT_TRUSTED"
                            : effectiveRevoked
                                ? "OFFICER_CERTIFICATE_REVOKED"
                                : "TAMPERED_OR_INVALID_SIGNATURE";

    await writeAuditLog({
        action: "verify", documentId, userId, ipAddress,
        result: valid ? "success" : "fail",
        details: {
            reason,
            format: padesResult.format || "PAdES",
            baseline_level: padesResult.baseline_level || null,
            certificate_id: document.certificate_id || null,
            certificate_revoked: effectiveRevoked,
            timestamp: padesResult.timestamp || null,
        },
    });

    return {
        valid,
        reason,
        document_id: document.document_id,
        file_hash: document.file_hash,
        current_hash: currentHash,
        hash_matched: hashMatched,
        status: document.status,
        signed_at: document.signed_at,
        algorithm: "ECDSA-P256-SHA256",
        signature_provider: "PAdES/CMS",
        signature_valid: padesResult.cms_signature_valid === true,
        pades_format: padesResult.format || "PAdES",
        pades_level: padesResult.baseline_level || null,
        pades_subfilter: padesResult.subfilter || null,
        pades_valid: padesResult.valid === true,
        pades_reason: padesResult.reason || null,
        pades_byte_range_valid: padesResult.byte_range_valid === true,
        pades_cms_signature_valid: padesResult.cms_signature_valid === true,
        pades_signing_certificate_attribute: padesResult.cades_signing_certificate_attribute === true,
        pades_dss_present: padesResult.dss_present === true,
        pades_vri_present: padesResult.vri_present === true,
        pades_vri_binding_valid: padesResult.pades_lt?.vri_binding_valid === true,
        pades_incremental_update_valid: padesResult.pades_lt?.incremental_update_valid === true,
        pades_embedded_certificate_count: padesResult.pades_lt?.embedded_certificate_count || 0,
        pades_embedded_ocsp_count: padesResult.pades_lt?.embedded_ocsp_count || 0,
        pades_embedded_crl_count: padesResult.pades_lt?.embedded_crl_count || 0,
        pades_offline_verification_ready: embeddedLtEvidenceValid,
        pki_version: document.pki_version || 4,
        certificate_available: Boolean(document.officer_certificate_pem),
        certificate_chain_valid: padesResult.cms_signature_valid === true,
        certificate_signature_valid: padesResult.cms_signature_valid === true,
        certificate_algorithm: "ECDSA-P256-SHA256",
        certificate_id: document.certificate_id || null,
        certificate_status_at_signing: document.certificate_status_at_signing || null,
        certificate_current_status: certificateRecord?.status || null,
        revocation_checked: currentOcspResult?.checked ?? revocationResult.checked,
        revocation_trusted: effectiveRevocationTrusted,
        revocation_source: currentOcspResult?.source || "CRL",
        ocsp_status: currentOcspResult?.status || null,
        ocsp_response_signature_valid: currentOcspResult?.ocsp?.response_signature_valid || false,
        ocsp_response_stale: currentOcspResult?.ocsp?.stale || false,
        ocsp_produced_at: currentOcspResult?.ocsp?.produced_at || null,
        ocsp_next_update: currentOcspResult?.ocsp?.next_update || null,
        ocsp_status_at_signing: storedOcspResult.certificate_status || null,
        ocsp_evidence_at_signing_valid: storedOcspResult.valid || false,
        certificate_revoked: effectiveRevoked,
        revocation_reason: certificateRecord?.revocation_reason || revocationResult.revocation_reason || null,
        revoked_at: revokedAt,
        crl_available: revocationResult.crl?.available || false,
        crl_signature_valid: revocationResult.crl?.signature_valid || false,
        crl_reason: revocationResult.crl?.reason || revocationResult.reason || null,
        crl_number: revocationResult.crl?.crl_number ?? null,
        crl_last_update: revocationResult.crl?.last_update || null,
        crl_next_update: revocationResult.crl?.next_update || null,
        timestamp_assurance: padesResult.timestamp_valid ? "RFC3161_EMBEDDED_IN_PADES" : "INVALID",
        timestamp_valid: padesResult.timestamp_valid === true,
        timestamp_reason: padesResult.timestamp_reason || null,
        trusted_signing_time: padesResult.timestamp || null,
        timestamp_policy_oid: padesResult.timestamp_policy_oid || null,
        timestamp_serial_number: padesResult.timestamp_serial_number || null,
        timestamp_tsa_subject: document.timestamp_evidence?.tsa_subject || null,
        timestamp_before_revocation: timestampBeforeRevocation,
        revocation_time_assessment: effectiveRevoked
            ? timestampBeforeRevocation
                ? "SIGNED_BEFORE_REVOCATION_CONFIRMED_BY_RFC3161"
                : "REVOKED_AT_OR_BEFORE_TRUSTED_SIGNING_TIME"
            : "CURRENTLY_NOT_REVOKED",
        signing_method: document.signing_method || "remote",
        remote_otp_required: document.remote_otp_required === true,
        remote_otp_authorization_id: document.remote_otp_authorization_id || null,
        remote_otp_verified_at: document.remote_otp_verified_at || null,
        tsp_mode: document.tsp_mode || null,
        client_agent_version: document.client_agent_version || null,
        key_provider: document.key_provider || null,
        key_exportable: document.key_exportable ?? null,
        archive_id: document.archive_id || null,
        archive_valid: archiveResult.valid === true,
        archive_reason: archiveResult.reason || null,
        archive_manifest_signature_valid: archiveResult.manifest_signature_valid || false,
        archive_file_count: archiveResult.file_count || 0,
        signed_by: document.signed_by || null,
        officer_certificate: document.officer_certificate || null,
        verify_url: document.verify_url,
        signed_pdf_url: `/api/app/documents/${document.document_id}/signed-pdf`,
    };
};

/** Lấy thông tin chi tiết một tài liệu theo documentId, bao gồm tên người nộp */
export const getDocument = async (documentId) => {
    const document = await findDocumentById(documentId);

    if (!document) {
        return null;
    }

    // Tra cứu tên người nộp từ bảng users
    let owner_name = null;
    try {
        const owner = await getUserById(document.owner_id);
        if (owner) owner_name = owner.full_name;
    } catch (_) { /* bỏ qua nếu không tìm thấy */ }

    const certificateRecord = document.certificate_id
        ? findCertificateById(document.certificate_id)
        : null;

    return {
        document_id: document.document_id,
        owner_id: document.owner_id,
        owner_name,
        original_name: document.original_name,
        file_hash: document.file_hash,
        hash: document.file_hash,
        file_path: document.signed_pdf_path || document.file_path,
        original_file_hash: document.original_file_hash || null,
        algorithm: document.algorithm,
        signature_provider: document.signature_provider,
        pades_level: document.pades_level || null,
        pades_subfilter: document.pades_subfilter || null,
        pades_cms_sha256: document.pades_cms_sha256 || null,
        pades_evidence: document.pades_evidence || null,
        verify_url: document.verify_url,
        signed_pdf_url: document.signed_pdf_path ? `/api/app/documents/${document.document_id}/signed-pdf` : null,
        status: document.status,
        created_at: document.created_at,
        signed_at: document.signed_at,
        pki_version: document.pki_version || null,
        certificate_id: document.certificate_id || null,
        certificate_status_at_signing: document.certificate_status_at_signing || null,
        certificate_current_status: certificateRecord?.status || null,
        certificate_revoked_at: certificateRecord?.revoked_at || null,
        certificate_revocation_reason: certificateRecord?.revocation_reason || null,
        signed_by: document.signed_by || null,
        certificate_signature_algorithm: document.certificate_signature_algorithm || null,
        officer_certificate: document.officer_certificate || null,
        ocsp_evidence_at_signing: document.ocsp_evidence_at_signing || null,
        revocation_source_at_signing: document.revocation_source_at_signing || null,
        timestamp_evidence: document.timestamp_evidence || null,
        signing_method: document.signing_method || "remote",
        remote_otp_required: document.remote_otp_required === true,
        remote_otp_authorization_id: document.remote_otp_authorization_id || null,
        remote_otp_verified_at: document.remote_otp_verified_at || null,
        tsp_mode: document.tsp_mode || null,
        tsp_request_id: document.tsp_request_id || null,
        client_agent_version: document.client_agent_version || null,
        client_agent_endpoint: document.client_agent_endpoint || null,
        client_agent_request_id: document.client_agent_request_id || null,
        key_provider: document.key_provider || null,
        key_reference: document.key_reference || null,
        key_exportable: document.key_exportable ?? null,
        archive_id: document.archive_id || null,
        archive_manifest_sha256: document.archive_manifest_sha256 || null,
        archive_file_count: document.archive_file_count || 0,
        archive_valid_at_creation: document.archive_valid_at_creation || false,
        rejection_reason: document.rejection_reason || null,
        rejected_at: document.rejected_at || null
    };
};

/** Lấy danh sách tài liệu thuộc về một công dân cụ thể */
export const getDocumentsByOwner = async (ownerId) => {
    const allDocs = await listDocuments();
    const filteredDocs = allDocs.filter((doc) => doc.owner_id === ownerId);
    const docs = await Promise.all(filteredDocs.map((doc) => getDocument(doc.document_id)));
    docs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    return docs;
};

/** Lấy đường dẫn file PDF đã ký để tải xuống */
export const getSignedDocumentFile = async (documentId) => {
    const document = await findDocumentById(documentId);

    if (!document || !document.signed_pdf_path) {
        return null;
    }

    return {
        filePath: document.signed_pdf_path,
        fileName: `${document.document_id}-signed.pdf`
    };
};

// ---------------------------------------------------------------------------
// Quy trình Citizen - Officer
// ---------------------------------------------------------------------------

/**
 * Công dân nộp hồ sơ: lưu file PDF, tạo bản ghi trạng thái "submitted".
 * @param {Object} params - { documentId, filePath, originalName, ownerId, ipAddress }
 * @returns {Object} Thông tin hồ sơ đã nộp
 */
export const submitDocument = async ({ documentId, filePath, originalName, ownerId = "citizen", ipAddress = null, requireCitizenSignature = true }) => {
    const folder = createDocumentFolder(documentId);
    const originalPdfPath = path.join(folder, "original.pdf");

    await fsExtra.move(filePath, originalPdfPath, { overwrite: true });

    const originalFileHash = await hashFile(originalPdfPath);
    const createdAt = new Date().toISOString();
    const token = generateVerificationToken();
    const tokenHash = hashText(token);

    const record = {
        document_id: documentId,
        owner_id: ownerId,
        original_name: originalName,
        file_path: originalPdfPath,
        original_file_hash: originalFileHash,
        status: requireCitizenSignature ? "awaiting_citizen_signature" : "submitted",
        created_at: createdAt,
        signature: "",
        file_hash: originalFileHash,
        token_hash: tokenHash,
        public_key_id: 0,
        signed_at: null,
        signature_payload: null,
        signed_pdf_path: null,
        verify_url: null,
        qr_payload: null,
        algorithm: null,
        signature_provider: null,
        citizen_signature_required: requireCitizenSignature,
        citizen_signed_at: null,
        citizen_signature: null,
        citizen_certificate_id: null,
        citizen_signing_provider: null,
        citizen_signature_valid: false
    };

    const saved = await saveDocument(record);

    atomicWriteJsonSync(
        path.join(folder, "metadata.json"),
        saved,
        { backup: true }
    );

    await writeAuditLog({
        action: "submit",
        documentId,
        userId: ownerId,
        ipAddress,
        result: "success"
    });

    return {
        document_id: saved.document_id,
        status: saved.status,
        created_at: saved.created_at
    };
};

/**
 * Cán bộ ký số hồ sơ: sinh QR, ký PAdES-B-T rồi nhúng DSS/VRI để tạo PAdES-LT.
 * @param {Object} params - { documentId, officerId, ipAddress }
 * @returns {Object} Thông tin tài liệu đã ký và phát hành
 */
export const signDocument = async ({
    documentId,
    officerId = "officer",
    ipAddress = null,
    requestId,
    nonce,
    bypassReplayProtection = false,
    bypassRemoteOtp = false,
    signingMethod = "remote",
    authorizationId = null,
    authorizationToken = null,
}) => {
    let reservedRequest = null;
    let reservedAuthorization = null;
    try {
        const normalizedSigningMethod = String(signingMethod || "remote").trim().toLowerCase();
        if (!new Set(["remote", "local"]).has(normalizedSigningMethod)) {
            throw new OfficerCertificateError(
                `Unsupported signing method: ${normalizedSigningMethod}`,
                "SIGNING_METHOD_UNSUPPORTED",
                400
            );
        }

        const document = await findDocumentById(documentId);
        if (!document) throw new Error("Document not found");
        if (document.status !== "submitted") {
            throw new Error(`Cannot sign document with status "${document.status}"`);
        }

        const officerIdentity = PKI_REQUIRE_CERTIFICATE
            ? await loadOfficerSigningIdentity(officerId, { signingMethod: normalizedSigningMethod })
            : null;
        if (!officerIdentity) {
            throw new OfficerCertificateError(
                "PAdES signing requires an officer X.509 certificate",
                "OFFICER_CERTIFICATE_NOT_ASSIGNED", 409
            );
        }

        if (normalizedSigningMethod === "remote" && REMOTE_OTP_REQUIRED && !bypassRemoteOtp) {
            reservedAuthorization = await reserveRemoteSigningAuthorization({
                authorizationId,
                authorizationToken,
                requestId,
                nonce,
                documentId,
                officerId,
                certificateId: officerIdentity.certificateRecord.certificate_id,
                ipAddress,
            });
        }

        if (!bypassReplayProtection) {
            reservedRequest = await reserveSigningRequest({
                requestId,
                nonce,
                documentId,
                officerId,
                ipAddress,
                signingMethod: normalizedSigningMethod,
            });
        }

        const ocspAtSigning = assertCertificateGoodViaOcsp(officerIdentity.certificateRecord);
        await writeAuditLog({
            action: "OFFICER_CERTIFICATE_VALIDATED",
            documentId,
            requestId: reservedRequest?.request_id || null,
            userId: officerId,
            ipAddress,
            result: "success",
            details: {
                certificate_id: officerIdentity.certificateRecord.certificate_id,
                officer_id: officerIdentity.user.officer_id,
                fingerprint_sha256: officerIdentity.identity.metadata.fingerprint_sha256,
                revocation_source: ocspAtSigning.source,
                ocsp_status: ocspAtSigning.status,
            },
        });

        const documentFolder = createDocumentFolder(documentId);
        const issuedAt = new Date().toISOString();
        const token = generateVerificationToken();
        const verifyUrl = buildVerifyUrl(documentId, token);
        let ownerName = "";
        try {
            const owner = await getUserById(document.owner_id);
            if (owner) ownerName = owner.full_name;
        } catch (_) { /* optional display metadata */ }

        const qrImagePath = await generateQrCode({ documentId, verifyUrl, token, status: "issued", ownerName });
        const preparedPdfPath = path.join(documentFolder, "prepared-with-qr.pdf");
        await embedQrIntoPdf({
            sourceFilePath: document.file_path,
            qrPath: qrImagePath,
            outputFilePath: preparedPdfPath,
            metadata: {
                document_id: documentId,
                verify_url: verifyUrl,
                algorithm: "PAdES-LT / ECDSA-P256-SHA256",
                key_id: officerIdentity.certificateRecord.certificate_id,
                issued_at: issuedAt,
                status: "issued",
                owner_name: ownerName,
                signing_request_id: reservedRequest?.request_id || null,
            },
        });

        const signedBtFilePath = path.join(documentFolder, "signed-bt-intermediate.pdf");
        const signedFilePath = path.join(documentFolder, "signed.pdf");
        const signingResult = normalizedSigningMethod === "local"
            ? await signPadesViaClientAgent({
                requestId: reservedRequest?.request_id || crypto.randomUUID(),
                documentId,
                inputPdfPath: preparedPdfPath,
                outputPdfPath: signedBtFilePath,
                evidenceDirectory: path.join(documentFolder, "timestamps"),
                certificateRecord: officerIdentity.certificateRecord,
                signer: officerIdentity.user,
                issuedAt,
            })
            : await signPadesViaTsp({
                requestId: reservedRequest?.request_id || crypto.randomUUID(),
                documentId,
                inputPdfPath: preparedPdfPath,
                outputPdfPath: signedBtFilePath,
                evidenceDirectory: path.join(documentFolder, "timestamps"),
                certificateRecord: officerIdentity.certificateRecord,
                signer: officerIdentity.user,
                issuedAt,
            });
        const padesBtEvidence = signingResult.pades;
        const padesLtEvidence = await upgradePadesBtToLt({
            inputPdfPath: signedBtFilePath,
            outputPdfPath: signedFilePath,
            certificateRecord: officerIdentity.certificateRecord,
            ocspEvidence: ocspAtSigning.ocsp,
            embeddedAt: new Date().toISOString(),
        });
        const padesLtVerification = verifyPadesPdf({
            pdfPath: signedFilePath,
            expectedFingerprint: officerIdentity.certificateRecord.fingerprint_sha256,
        });
        if (!padesLtVerification.valid || padesLtVerification.baseline_level !== "PAdES-LT") {
            throw new OfficerCertificateError(
                `Created PAdES-LT PDF failed self-verification: ${padesLtVerification.reason}`,
                "PADES_LT_SELF_VERIFICATION_FAILED",
                500
            );
        }
        const padesEvidence = {
            ...padesBtEvidence,
            baseline_level: "PAdES-LT",
            verification: padesLtVerification,
            lt_evidence: padesLtEvidence,
        };
        fs.rmSync(preparedPdfPath, { force: true });
        fs.rmSync(signedBtFilePath, { force: true });
        const fileHash = await hashFile(signedFilePath);

        await writeAuditLog({
            action: ocspAtSigning.source === "OCSP" ? "OCSP_STATUS_GOOD" : "CRL_FALLBACK_USED",
            documentId,
            requestId: reservedRequest?.request_id || null,
            userId: officerId,
            ipAddress,
            result: "success",
            details: {
                certificate_id: officerIdentity.certificateRecord.certificate_id,
                source: ocspAtSigning.source,
                status: ocspAtSigning.status,
            },
        });
        await writeAuditLog({
            action: "PADES_LT_CREATED",
            documentId,
            requestId: reservedRequest?.request_id || null,
            userId: officerId,
            ipAddress,
            result: "success",
            details: {
                level: padesEvidence.baseline_level,
                subfilter: padesEvidence.subfilter,
                cms_sha256: padesEvidence.cms_sha256,
                timestamp: padesEvidence.verification.timestamp,
            },
        });
        if (normalizedSigningMethod === "local") {
            await writeAuditLog({
                action: "CLIENT_AGENT_LOCAL_SIGNING_COMPLETED",
                documentId,
                requestId: reservedRequest?.request_id || signingResult.request_id || null,
                userId: officerId,
                ipAddress,
                result: "success",
                details: {
                    client_agent_version: signingResult.client_agent_version,
                    provider: signingResult.provider,
                    certificate_id: signingResult.certificate_id,
                    portal_verification_valid: signingResult.portal_verification?.valid === true,
                },
            });
        }

        const certificateMetadata = officerIdentity.identity.metadata;
        const updatePayload = {
            status: "issued",
            signed_at: issuedAt,
            signed_pdf_path: signedFilePath,
            file_hash: fileHash,
            signature: null,
            signature_payload: null,
            algorithm: "PAdES-LT",
            signature_provider: normalizedSigningMethod === "local"
                ? "NT219 Client Agent (software) + OpenSSL CMS/CAdES + RFC3161 TSA"
                : `NT219 TSP (${signingResult.key_provider}) + OpenSSL CMS/CAdES + RFC3161 TSA`,
            public_key_id: null,
            public_key: null,
            token_hash: hashText(token),
            verify_url: verifyUrl,
            signing_request_id: reservedRequest?.request_id || signingResult.request_id || null,
            pki_version: 7,
            pades_version: 3,
            pades_level: padesEvidence.baseline_level,
            pades_subfilter: padesEvidence.subfilter,
            pades_cms_sha256: padesEvidence.cms_sha256,
            signing_method: normalizedSigningMethod,
            remote_otp_required: normalizedSigningMethod === "remote" && REMOTE_OTP_REQUIRED,
            remote_otp_authorization_id: reservedAuthorization?.authorization_id || null,
            remote_otp_verified_at: reservedAuthorization?.verified_at || null,
            tsp_mode: normalizedSigningMethod === "remote" ? String(process.env.TSP_MODE || "http").toLowerCase() : null,
            tsp_request_id: normalizedSigningMethod === "remote" ? signingResult.request_id : null,
            tsp_completed_at: normalizedSigningMethod === "remote" ? signingResult.completed_at : null,
            tsp_local_fallback_used: normalizedSigningMethod === "remote" && signingResult.local_fallback_used === true,
            client_agent_version: normalizedSigningMethod === "local" ? signingResult.client_agent_version : null,
            client_agent_endpoint: normalizedSigningMethod === "local" ? (process.env.CLIENT_AGENT_URL || "http://127.0.0.1:3500") : null,
            client_agent_request_id: normalizedSigningMethod === "local" ? signingResult.request_id : null,
            key_provider: normalizedSigningMethod === "local" ? "client-agent-software" : signingResult.key_provider,
            key_reference: signingResult.key_reference,
            key_exportable: signingResult.key_exportable,
            pades_evidence: {
                format: padesEvidence.format,
                baseline_level: padesEvidence.baseline_level,
                subfilter: padesEvidence.subfilter,
                digest_algorithm: padesEvidence.digest_algorithm,
                signature_algorithm: padesEvidence.signature_algorithm,
                signature_field_name: padesEvidence.signature_field_name,
                byte_range: padesEvidence.byte_range,
                cms_sha256: padesEvidence.cms_sha256,
                cms_der_path: padesEvidence.cms_der_path,
                cms_bb_der_path: padesEvidence.cms_bb_der_path,
                signing_method: normalizedSigningMethod,
                key_provider: normalizedSigningMethod === "local" ? "client-agent-software" : signingResult.key_provider,
                key_exportable: signingResult.key_exportable,
                dss_present: padesEvidence.lt_evidence?.dss_present === true,
                vri_present: padesEvidence.lt_evidence?.vri_present === true,
                vri_key_sha1: padesEvidence.lt_evidence?.vri_key_sha1 || null,
                embedded_certificate_count: padesEvidence.lt_evidence?.embedded_certificate_count || 0,
                embedded_ocsp_count: padesEvidence.lt_evidence?.embedded_ocsp_count || 0,
                embedded_crl_count: padesEvidence.lt_evidence?.embedded_crl_count || 0,
                incremental_update: padesEvidence.lt_evidence?.incremental_update === true,
                offline_verification_ready: padesEvidence.verification?.offline_verification_ready === true,
                lt_evidence: padesEvidence.lt_evidence,
                self_verification: padesEvidence.verification,
            },
            certificate_id: officerIdentity.certificateRecord.certificate_id,
            ocsp_evidence_at_signing: ocspAtSigning.ocsp || null,
            revocation_source_at_signing: ocspAtSigning.source,
            timestamp_evidence: padesEvidence.timestamp_evidence,
            certificate_status_at_signing: officerIdentity.certificateRecord.status,
            certificate_signature: null,
            certificate_signature_algorithm: "ECDSA-P256-SHA256 (embedded CMS)",
            officer_certificate_pem: fs.readFileSync(
                path.resolve(process.cwd(), officerIdentity.certificateRecord.certificate_path), "utf8"
            ),
            officer_certificate: {
                ...certificateMetadata,
                certificate_id: officerIdentity.certificateRecord.certificate_id,
                status_at_signing: officerIdentity.certificateRecord.status,
            },
            signed_by: {
                user_id: officerIdentity.user.id,
                officer_id: officerIdentity.user.officer_id,
                full_name: officerIdentity.user.full_name,
                email: officerIdentity.user.email,
            },
            qr_payload: { document_id: documentId, verify_url: verifyUrl, token, status: "issued", owner_name: ownerName },
        };
        const provisionalMetadata = { ...document, ...updatePayload };
        const archive = createLtvArchive({
            documentId,
            originalPdfPath: document.file_path,
            signedPdfPath: signedFilePath,
            metadata: provisionalMetadata,
            certificateRecord: officerIdentity.certificateRecord,
            ocspEvidence: ocspAtSigning.ocsp || null,
            padesEvidence,
            timestampEvidence: padesEvidence.timestamp_evidence,
        });
        updatePayload.archive_id = archive.archive_id;
        updatePayload.archive_manifest_sha256 = archive.manifest_sha256;
        updatePayload.archive_file_count = archive.file_count;
        updatePayload.archive_valid_at_creation = archive.valid;
        const updated = await updateDocument(documentId, updatePayload);

        atomicWriteJsonSync(path.join(documentFolder, "metadata.json"), updated, { backup: true });
        await writeAuditLog({
            action: "LTV_ARCHIVE_CREATED",
            documentId,
            requestId: reservedRequest?.request_id || signingResult.request_id || null,
            userId: officerId,
            ipAddress,
            result: "success",
            details: {
                archive_id: archive.archive_id,
                manifest_sha256: archive.manifest_sha256,
                file_count: archive.file_count,
            },
        });
        await writeAuditLog({
            action: "sign", documentId,
            requestId: reservedRequest?.request_id || null,
            userId: officerId, ipAddress, result: "success",
            details: { format: "PAdES-LT", dss: true, vri: true },
        });
        if (reservedRequest) {
            await completeSigningRequest({ requestId: reservedRequest.request_id, documentId, officerId, ipAddress });
        }
        if (reservedAuthorization) {
            await completeRemoteSigningAuthorization({
                authorizationId: reservedAuthorization.authorization_id,
                documentId,
                officerId,
                ipAddress,
            });
        }
        return {
            document_id: updated.document_id,
            signing_request_id: reservedRequest?.request_id || null,
            remote_otp_authorization_id: reservedAuthorization?.authorization_id || null,
            remote_otp_verified: Boolean(reservedAuthorization),
            file_hash: updated.file_hash,
            hash: updated.file_hash,
            algorithm: updated.algorithm,
            signature_provider: updated.signature_provider,
            verify_url: updated.verify_url,
            qr_payload: updated.qr_payload,
            file_path: updated.signed_pdf_path,
            signed_file: updated.signed_pdf_path,
            signed_pdf_url: `/api/app/documents/${updated.document_id}/signed-pdf`,
            status: updated.status,
            signed_at: updated.signed_at,
            pki_version: updated.pki_version,
            pades_level: updated.pades_level,
            pades_valid: updated.pades_evidence?.self_verification?.valid || false,
            certificate_id: updated.certificate_id,
            ocsp_status_at_signing: updated.ocsp_evidence_at_signing?.certificate_status || null,
            timestamp_valid: updated.pades_evidence?.self_verification?.timestamp_valid || false,
            timestamp: updated.pades_evidence?.self_verification?.timestamp || null,
            signing_method: updated.signing_method,
            tsp_mode: updated.tsp_mode,
            client_agent_version: updated.client_agent_version,
            key_provider: updated.key_provider,
            key_exportable: updated.key_exportable,
            archive_id: updated.archive_id,
            archive_valid: updated.archive_valid_at_creation,
            signed_by: updated.signed_by,
            certificate_signature_algorithm: updated.certificate_signature_algorithm,
            officer_certificate: updated.officer_certificate,
        };
    } catch (error) {
        if (error instanceof OfficerCertificateError) {
            await writeAuditLog({
                action: error.code === "OFFICER_CERTIFICATE_REVOKED"
                    ? "REVOKED_CERTIFICATE_SIGNING_BLOCKED" : "PADES_SIGNING_REJECTED",
                documentId,
                requestId: reservedRequest?.request_id || requestId || null,
                userId: officerId,
                ipAddress,
                result: "blocked",
                details: { code: error.code, message: error.message },
            });
        }
        if (reservedRequest) {
            await failSigningRequest({
                requestId: reservedRequest.request_id, documentId, officerId, ipAddress,
                failureCode: error.code || "SIGNING_OPERATION_FAILED",
            });
        }
        if (reservedAuthorization) {
            await failRemoteSigningAuthorization({
                authorizationId: reservedAuthorization.authorization_id,
                documentId,
                officerId,
                ipAddress,
                failureCode: error.code || "SIGNING_OPERATION_FAILED",
            });
        }
        throw error;
    }
};

/** Lấy toàn bộ danh sách tài liệu (dành cho officer) */
export const getDocuments = async () => {
    const allDocs = await listDocuments();
    return Promise.all(
        allDocs.map((doc) => getDocument(doc.document_id))
    );
};

/** Lấy danh sách tài liệu theo trạng thái (submitted, issued, ...) */
export const getDocumentsByStatus = async (status) => {
    const allDocs = await listDocuments();
    const filteredDocs = allDocs.filter((doc) => doc.status === status);

    const docs = await Promise.all(
        filteredDocs.map((doc) => getDocument(doc.document_id))
    );

    // Sắp xếp mới nhất lên đầu
    const dateField = status === "issued" ? "signed_at" : status === "rejected" ? "rejected_at" : "created_at";
    docs.sort((a, b) => new Date(b[dateField]) - new Date(a[dateField]));

    return docs;
};

/**
 * Cán bộ từ chối hồ sơ: chuyển trạng thái "rejected", lưu lý do.
 * @param {Object} params - { documentId, officerId, reason, ipAddress }
 */
export const rejectDocument = async ({ documentId, officerId = "officer", reason, ipAddress = null }) => {
    const document = await findDocumentById(documentId);
    if (!document) throw new Error("Document not found");
    if (document.status !== "submitted") throw new Error(`Cannot reject document with status "${document.status}"`);

    const rejectedAt = new Date().toISOString();
    const updated = await updateDocument(documentId, {
        status: "rejected",
        rejection_reason: reason || "Không có lý do",
        rejected_at: rejectedAt
    });

    await writeAuditLog({ action: "reject", documentId, userId: officerId, ipAddress, result: "success" });

    return {
        document_id: updated.document_id,
        status: updated.status,
        rejection_reason: updated.rejection_reason,
        rejected_at: updated.rejected_at
    };
};

/** Lấy đường dẫn file PDF (gốc hoặc đã ký) để tải xuống */
export const getDocumentFile = async (documentId) => {
    const document = await findDocumentById(documentId);
    if (!document) return null;

    const filePath = document.signed_pdf_path || document.file_path;
    if (!filePath) return null;

    const suffix = document.status === "issued" ? "signed" : "original";
    return {
        filePath,
        fileName: `${document.document_id}-${suffix}.pdf`
    };
};
