/**
 * document.controller.js - Điều khiển các endpoint quản lý tài liệu.
 * Bao gồm: xem trước, nộp hồ sơ, ký số, xác minh, tải file, danh sách.
 */
import fs from "fs";
import path from "path";
import multer from "multer";
import { fileURLToPath } from "url";
import {
    createPreviewDocument,
    getPreviewById
} from "../services/preview.service.js";
import {
    getDocument,
    getDocuments,
    getSignedDocumentFile,
    getDocumentFile,
    getDocumentsByStatus,
    getDocumentsByOwner,
    submitDocument,
    signDocument,
    rejectDocument,
    verifyDocument
} from "../services/document.service.js";
import { hashFile } from "../crypto/hash.service.js";
import {
    validateCT01
} from "../validators/ct01.validator.js";
import { saveMembersForDocument } from "../repositories/household_members.repository.js";
import { validateFilePath } from "../utils/path-validator.util.js";
import { STORAGE_ROOT } from "../utils/storage.util.js";
import { IS_DEV } from "../config/env.config.js";
import {
    createSigningRequest,
    SigningRequestError,
} from "../services/signing-request.service.js";
import { OfficerCertificateError } from "../crypto/x509-pki.service.js";
import { loadOfficerSigningIdentity } from "../crypto/officer-pki.service.js";
import { CitizenSigningError } from "../crypto/citizen-signature.service.js";
import {
    createCitizenSigningRequest,
    signDocumentAsCitizen,
} from "../services/citizen-signing.service.js";
import { listCitizenClientAgentCertificates } from "../services/citizen-client-agent.service.js";
import {
    createRemoteSigningAuthorization,
    verifyRemoteSigningOtp,
    RemoteSigningAuthorizationError,
} from "../services/remote-signing-authorization.service.js";

/**
 * Safe error responses for document endpoints.
 * In production, don't leak internal error details.
 */
function safeError(res, error, statusCode = 500) {
    if (IS_DEV) {
        return res.status(statusCode).json({ message: error.message });
    }
    // Known safe error messages
    const safeMessages = [
        "Document not found",
        "Preview not found",
        "Preview expired",
        "Preview file not found",
        "File not found",
        "Signed PDF not found",
        "Cannot sign document with status",
    ];
    if (safeMessages.some(m => error.message.includes(m))) {
        return res.status(statusCode).json({ message: error.message });
    }
    return res.status(statusCode).json({ message: "An error occurred" });
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadDirectory = path.resolve(__dirname, "../uploads");

const uploadFolder = "src/uploads/";
if (!fs.existsSync(uploadFolder)) {
    fs.mkdirSync(uploadFolder, { recursive: true });
}

/** Cấu hình multer: chỉ chấp nhận file PDF, lưu vào thư mục uploads */
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        fs.mkdirSync(uploadDirectory, { recursive: true });
        cb(null, uploadDirectory);
    },
    filename: function (req, file, cb) {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const pdfOnly = (req, file, cb) => {
    if (file.mimetype !== "application/pdf") {
        return cb(new Error("Only PDF files are allowed"));
    }
    cb(null, true);
};

const upload = multer({ storage, fileFilter: pdfOnly });

/** Kiểm tra người dùng có phải officer (quản lý tất cả hồ sơ) */
const canManageAllDocuments = (user) => {
    const roles = user?.roles || [];
    return roles.includes("officer");
};

/** Kiểm tra người dùng có quyền truy cập tài liệu (là chủ sở hữu hoặc officer) */
const canAccessDocument = (user, document) => {
    if (!user || !document) return false;
    if (canManageAllDocuments(user)) return true;
    return String(document.owner_id) === String(user.id);
};

// ---------------------------------------------------------------------------
// Xem trước hồ sơ CT01
// ---------------------------------------------------------------------------

/** Tạo PDF xem trước từ dữ liệu form CT01 */
export const previewDocument = async (req, res) => {
    try {
        req.body.cccd = req.body.cccd || req.body.citizen_id;
        req.body.reason = req.body.reason || req.body.request_content;

        const dob =
            req.body.dob ||
            (req.body.birth_day && req.body.birth_month && req.body.birth_year
                ? `${req.body.birth_year}-${req.body.birth_month}-${req.body.birth_day}`
                : null);
        req.body.dob = dob;

        validateCT01(req.body);

        const result = await createPreviewDocument({
            ...req.body,
            owner_id: req.user?.id ? String(req.user.id) : null
        });

        res.status(200).json({
            message: "Preview generated",
            data: result
        });
    } catch (error) {
        safeError(res, error);
    }
};

// ---------------------------------------------------------------------------
// Nộp hồ sơ (Citizen nộp từ preview đã xác nhận)
// ---------------------------------------------------------------------------

/** Công dân nộp hồ sơ: kiểm tra preview hợp lệ, chuyển trạng thái submitted */
export const submitDocumentHandler = async (req, res) => {
    try {
        req.body.cccd = req.body.cccd || req.body.citizen_id;
        req.body.reason = req.body.reason || req.body.request_content;

        const dob =
            req.body.dob ||
            (req.body.birth_day && req.body.birth_month && req.body.birth_year
                ? `${req.body.birth_year}-${req.body.birth_month}-${req.body.birth_day}`
                : null);
        req.body.dob = dob;

        validateCT01(req.body);

        const preview = await getPreviewById(req.body.preview_id);
        if (!preview) {
            return res.status(404).json({ message: "Preview not found" });
        }
        if (preview.expired_at && new Date(preview.expired_at) < new Date()) {
            return res.status(400).json({ message: "Preview expired" });
        }

        const previewOwnerId = preview.owner_id ? String(preview.owner_id) : null;
        if (previewOwnerId && previewOwnerId !== String(req.user.id)) {
            return res.status(403).json({ message: "You do not have access to this preview" });
        }

        if (!preview.preview_path || !fs.existsSync(preview.preview_path)) {
            return res.status(400).json({ message: "Preview file not found" });
        }

        const result = await submitDocument({
            documentId: preview.document_id,
            filePath: preview.preview_path,
            originalName: "CT01.pdf",
            ownerId: req.user.id,
            ipAddress: req.ip
        });

        // Lưu thành viên hộ gia đình nếu có
        const members = req.body.members;
        if (Array.isArray(members) && members.length > 0) {
            await saveMembersForDocument(preview.document_id, members);
        }

        res.status(201).json({
            message: "CT01 submitted successfully",
            data: result
        });
    } catch (err) {
        safeError(res, err);
    }
};


// ---------------------------------------------------------------------------
// Citizen signature (Citizen signing + Citizen PKCS#11)
// ---------------------------------------------------------------------------

export const listCitizenSigningCertificatesHandler = async (req, res) => {
    try {
        const certificates = await listCitizenClientAgentCertificates({ userId: req.user.id });
        res.json({
            component: "citizen-signing",
            user_id: req.user.id,
            citizen_id: req.user.citizen_id || null,
            certificates,
        });
    } catch (error) {
        if (error instanceof CitizenSigningError) {
            return res.status(error.status).json({ message: error.message, code: error.code });
        }
        safeError(res, error);
    }
};

export const createCitizenSigningRequestHandler = async (req, res) => {
    try {
        const result = await createCitizenSigningRequest({
            documentId: req.params.documentId,
            userId: req.user.id,
            certificateId: req.body?.certificate_id || null,
            provider: req.body?.provider || "software",
            ipAddress: req.ip,
        });
        res.status(201).json({
            message: "Citizen signing request created",
            signingRequest: result,
        });
    } catch (error) {
        if (error instanceof CitizenSigningError) {
            return res.status(error.status).json({ message: error.message, code: error.code });
        }
        safeError(res, error);
    }
};

export const citizenSignDocumentHandler = async (req, res) => {
    try {
        const result = await signDocumentAsCitizen({
            documentId: req.params.documentId,
            userId: req.user.id,
            requestId: req.body?.request_id,
            nonce: req.body?.nonce,
            ipAddress: req.ip,
        });
        res.status(201).json({
            message: "Citizen signature verified; document submitted for officer review",
            data: result,
        });
    } catch (error) {
        if (error instanceof CitizenSigningError) {
            return res.status(error.status).json({ message: error.message, code: error.code });
        }
        safeError(res, error);
    }
};

// ---------------------------------------------------------------------------
// Ký số (Officer tạo PAdES-B-T, nhúng DSS/VRI thành PAdES-LT và phát hành hồ sơ)
// ---------------------------------------------------------------------------

/** Tạo request_id + nonce dùng một lần trước khi ký. */
export const createSigningRequestHandler = async (req, res) => {
    try {
        const signingMethod = String(req.body?.signing_method || "remote").toLowerCase();
        const result = await createSigningRequest({
            documentId: req.params.documentId,
            officerId: req.user?.id ? String(req.user.id) : "officer",
            ipAddress: req.ip,
            signingMethod,
        });

        res.status(201).json({
            message: "Signing request created",
            signingRequest: result,
        });
    } catch (error) {
        if (error instanceof SigningRequestError) {
            return res.status(error.status).json({
                message: error.message,
                code: error.code,
            });
        }
        safeError(res, error);
    }
};

/** Tạo signing request + OTP challenge ràng buộc với ký từ xa. */
export const createRemoteSigningAuthorizationHandler = async (req, res) => {
    try {
        const officerId = req.user?.id ? String(req.user.id) : "officer";
        const identity = await loadOfficerSigningIdentity(officerId, { signingMethod: "remote" });
        const signingRequest = await createSigningRequest({
            documentId: req.params.documentId,
            officerId,
            ipAddress: req.ip,
            signingMethod: "remote",
        });
        const authorization = await createRemoteSigningAuthorization({
            signingRequest,
            documentId: req.params.documentId,
            officerId,
            certificateId: identity.certificateRecord.certificate_id,
            ipAddress: req.ip,
        });
        res.status(201).json({
            message: "Remote signing OTP issued",
            signingRequest,
            authorization,
        });
    } catch (error) {
        if (error instanceof SigningRequestError ||
            error instanceof OfficerCertificateError ||
            error instanceof RemoteSigningAuthorizationError) {
            return res.status(error.status).json({ message: error.message, code: error.code });
        }
        safeError(res, error);
    }
};

/** Xác minh OTP và phát authorization token dùng một lần. */
export const verifyRemoteSigningOtpHandler = async (req, res) => {
    try {
        const result = await verifyRemoteSigningOtp({
            authorizationId: req.body?.authorization_id,
            otp: req.body?.otp,
            documentId: req.params.documentId,
            officerId: req.user?.id ? String(req.user.id) : "officer",
            ipAddress: req.ip,
        });
        res.status(200).json({
            message: "Remote signing OTP verified",
            authorization: result,
        });
    } catch (error) {
        if (error instanceof RemoteSigningAuthorizationError) {
            return res.status(error.status).json({ message: error.message, code: error.code });
        }
        safeError(res, error);
    }
};

/** Cán bộ ký số hồ sơ bằng request_id + nonce dùng một lần. */
export const signDocumentHandler = async (req, res) => {
    try {
        const {
            request_id: requestId,
            nonce,
            signing_method: signingMethod = "remote",
            authorization_id: authorizationId,
            authorization_token: authorizationToken,
        } = req.body || {};

        const result = await signDocument({
            documentId: req.params.documentId,
            officerId: req.user?.id ? String(req.user.id) : "officer",
            ipAddress: req.ip,
            requestId,
            nonce,
            signingMethod,
            authorizationId,
            authorizationToken,
        });

        res.status(201).json({
            message: "Document signed and issued successfully",
            documentInfo: result
        });
    } catch (error) {
        if (error instanceof SigningRequestError ||
            error instanceof OfficerCertificateError ||
            error instanceof RemoteSigningAuthorizationError) {
            return res.status(error.status).json({
                message: error.message,
                code: error.code,
            });
        }
        const status = error.message.includes("not found") ? 404 : 400;
        safeError(res, error, status);
    }
};

// ---------------------------------------------------------------------------
// Danh sách hồ sơ
// ---------------------------------------------------------------------------

/** Liệt kê hồ sơ: citizen thấy của mình, officer thấy tất cả */
export const listDocumentDetails = async (req, res) => {
    try {
        if (canManageAllDocuments(req.user)) {
            return res.json(await getDocuments());
        }
        res.json(await getDocumentsByOwner(req.user.id));
    } catch (error) {
        safeError(res, error);
    }
};

/** Liệt kê hồ sơ chờ ký (status = submitted) */
export const listPendingDocuments = async (req, res) => {
    try {
        const documents = await getDocumentsByStatus("submitted");
        res.json(documents);
    } catch (error) {
        safeError(res, error);
    }
};

/** Liệt kê hồ sơ đã ký (status = issued) */
export const listIssuedDocuments = async (req, res) => {
    try {
        const documents = await getDocumentsByStatus("issued");
        res.json(documents);
    } catch (error) {
        safeError(res, error);
    }
};

/** Liệt kê hồ sơ đã từ chối (status = rejected) */
export const listRejectedDocuments = async (req, res) => {
    try {
        const documents = await getDocumentsByStatus("rejected");
        res.json(documents);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

/** Cán bộ từ chối hồ sơ: yêu cầu lý do, chuyển trạng thái "rejected" */
export const rejectDocumentHandler = async (req, res) => {
    try {
        const { reason } = req.body;
        if (!reason || !reason.trim()) {
            return res.status(400).json({ message: "Lý do từ chối là bắt buộc" });
        }
        const result = await rejectDocument({
            documentId: req.params.documentId,
            officerId: req.user?.id ? String(req.user.id) : "officer",
            reason: reason.trim(),
            ipAddress: req.ip
        });
        res.status(200).json({ message: "Hồ sơ đã bị từ chối", data: result });
    } catch (error) {
        const status = error.message.includes("not found") ? 404 : 400;
        res.status(status).json({ message: error.message });
    }
};

// ---------------------------------------------------------------------------
// Chi tiết hồ sơ
// ---------------------------------------------------------------------------

/** Xem chi tiết một hồ sơ theo documentId */
export const getDocumentDetail = async (req, res) => {
    try {
        const document = await getDocument(req.params.documentId);

        if (!document) {
            return res.status(404).json({ message: "Document not found" });
        }

        if (!canAccessDocument(req.user, document)) {
            return res.status(403).json({ message: "You do not have access to this document" });
        }

        res.json(document);
    } catch (error) {
        safeError(res, error);
    }
};

// ---------------------------------------------------------------------------
// Tải file
// ---------------------------------------------------------------------------

/** Tải PDF gốc của hồ sơ */
export const downloadDocumentFile = async (req, res) => {
    try {
        const document = await getDocument(req.params.documentId);

        if (!document) {
            return res.status(404).json({ message: "Document not found" });
        }

        if (!canAccessDocument(req.user, document)) {
            return res.status(403).json({ message: "You do not have access to this document" });
        }

        const fileInfo = await getDocumentFile(req.params.documentId);
        if (!fileInfo) {
            return res.status(404).json({ message: "File not found" });
        }

        // Validate path to prevent traversal
        let safePath;
        try {
            safePath = validateFilePath(fileInfo.filePath, STORAGE_ROOT);
        } catch {
            return res.status(403).json({ message: "Invalid file path" });
        }

        if (!fs.existsSync(safePath)) {
            return res.status(404).json({ message: "File not found" });
        }

        res.download(safePath, fileInfo.fileName);
    } catch (error) {
        safeError(res, error);
    }
};

/** Tải PDF đã ký: cho phép qua JWT session hoặc verification token */
export const downloadSignedDocument = async (req, res) => {
    try {
        const document = await getDocument(req.params.documentId);

        if (!document) {
            return res.status(404).json({ message: "Document not found" });
        }

        const providedToken = req.query.token;
        const tokenAllowed = typeof providedToken === "string"
            ? (await verifyDocument({
                documentId: req.params.documentId,
                token: providedToken,
                userId: "signed-pdf-download",
                ipAddress: req.ip
            })).valid
            : false;

        if (!tokenAllowed && !canAccessDocument(req.user, document)) {
            return res.status(req.user ? 403 : 401).json({
                message: "A valid login session or verification token is required"
            });
        }

        const signedFile = await getSignedDocumentFile(req.params.documentId);

        if (!signedFile) {
            return res.status(404).json({ message: "Signed PDF not found" });
        }

        // Validate path to prevent traversal
        let safePath;
        try {
            safePath = validateFilePath(signedFile.filePath, STORAGE_ROOT);
        } catch {
            return res.status(403).json({ message: "Invalid file path" });
        }

        if (!fs.existsSync(safePath)) {
            return res.status(404).json({ message: "Signed PDF not found" });
        }

        // Kiểm tra tính toàn vẹn: so sánh hash hiện tại với hash lúc ký
        const currentHash = await hashFile(safePath);
        if (currentHash !== document.file_hash) {
            return res.status(403).json({
                message: "Download denied: PDF was modified after signing. Please contact the authority.",
                tampered: true
            });
        }

        res.download(safePath, signedFile.fileName);
    } catch (error) {
        safeError(res, error);
    }
};

/** Tải file PDF xem trước (chỉ chủ sở hữu hoặc officer) */
export const downloadPreviewDocument = async (req, res) => {
    try {
        const preview = await getPreviewById(req.params.previewId);

        if (!preview) {
            return res.status(404).json({ message: "Preview not found" });
        }

        const previewOwnerId = preview.owner_id ? String(preview.owner_id) : null;
        const isOwner = previewOwnerId && String(req.user?.id) === previewOwnerId;

        if (!isOwner && !canManageAllDocuments(req.user)) {
            return res.status(403).json({ message: "You do not have access to this preview" });
        }

        if (!preview.preview_path) {
            return res.status(404).json({ message: "Preview file not found" });
        }

        // Validate path to prevent traversal attacks
        let safePath;
        try {
            safePath = validateFilePath(preview.preview_path, STORAGE_ROOT);
        } catch {
            return res.status(403).json({ message: "Invalid file path" });
        }

        if (!fs.existsSync(safePath)) {
            return res.status(404).json({ message: "Preview file not found" });
        }

        res.sendFile(safePath);
    } catch (error) {
        safeError(res, error);
    }
};

// ---------------------------------------------------------------------------
// Xác minh tài liệu
// ---------------------------------------------------------------------------

/** Xác minh qua QR: truyền documentId + token trên URL */
export const verifyDocumentByQr = async (req, res) => {
    try {
        const result = await verifyDocument({
            documentId: req.params.documentId,
            token: req.query.token,
            userId: req.user?.id ? String(req.user.id) : null,
            ipAddress: req.ip
        });
        res.status(result.valid ? 200 : 400).json(result);
    } catch (error) {
        safeError(res, error);
    }
};

/** Xác minh qua upload PDF: so sánh hash file upload với hash đã ký */
export const verifyDocumentByUpload = (req, res) => {
    upload.single("file")(req, res, async function (err) {
        if (err) {
            return res.status(400).json({ message: err.message || "Upload error" });
        }
        if (!req.file) {
            return res.status(400).json({ message: "No file uploaded" });
        }
        try {
            const result = await verifyDocument({
                documentId: req.params.documentId,
                token: req.body.token || req.query.token,
                filePath: req.file.path,
                userId: req.user?.id ? String(req.user.id) : null,
                ipAddress: req.ip
            });
            res.status(result.valid ? 200 : 400).json(result);
        } catch (error) {
            safeError(res, error);
        }
    });
};
