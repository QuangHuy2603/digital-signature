/**
 * QR Generator Service
 * --------------------
 * Generates a QR code (PNG) that encodes a small public JSON payload. Keep this
 * payload intentional because most QR scanner apps show it directly to users.
 *
 * Encoded QR payload:
 *   {
 *     "document_id": "HS-2026-A1B2C3D4",
 *     "verify_url": "{base_url}/{document_id}?token={token}",
 *     "status": "issued"
 *   }
 *
 * QR encoding parameters (Requirement 2.1, 2.2, 2.3):
 *   - errorCorrectionLevel: "H"
 *   - version: 5 (qrcode lib auto-promotes to a higher version if data exceeds capacity)
 *   - type: "png"
 *   - width: 300 default, configurable in [180, 500] pixels
 *
 * Storage layout (Requirement 2.4):
 *   storage/{document_id}/qr/qr.png
 *
 * Error handling — all thrown errors are instances of `QrServiceError` with a
 * `code` field. Possible codes:
 *   - INVALID_PAYLOAD          : documentId / verifyUrl / token missing or not a non-empty string
 *   - INVALID_WIDTH            : width outside the [180, 500] range
 *   - STORAGE_OPERATION_FAILED : mkdir/cleanup failure on the storage directory
 *   - QR_GENERATION_FAILED     : QRCode.toFile failed (partial file is removed before re-throw)
 *
 * Public exports:
 *   - generateQR({documentId, verifyUrl, token, width}) -> absolute path to qr.png
 *   - generateQrCode({documentId, verifyUrl, token})    -> thin alias delegating to generateQR
 *     (kept so existing callers like `document.service.js` keep working)
 *   - QrServiceError                                    -> typed error class
 */

import fs from "fs";
import path from "path";
import QRCode from "qrcode";
import { createDocumentFolder } from "../utils/storage.util.js";

const DEFAULT_WIDTH = 300;
const MIN_WIDTH = 180;
const MAX_WIDTH = 500;
const DEFAULT_QR_PAYLOAD_FIELDS = ["document_id", "verify_url", "status"];

/**
 * Typed error for the QR Generator Service.
 * @property {string} code - One of: INVALID_PAYLOAD, INVALID_WIDTH, STORAGE_OPERATION_FAILED, QR_GENERATION_FAILED
 */
export class QrServiceError extends Error {
    constructor(code, message, options = {}) {
        super(message);
        this.name = "QrServiceError";
        this.code = code;
        if (options.cause !== undefined) {
            this.cause = options.cause;
        }
    }
}

const isNonEmptyString = (value) =>
    typeof value === "string" && value.trim().length > 0;

const validatePayload = ({ documentId, verifyUrl, token, status, ownerName }) => {
    if (!isNonEmptyString(documentId)) {
        throw new QrServiceError(
            "INVALID_PAYLOAD",
            "documentId must be a non-empty string"
        );
    }
    if (!isNonEmptyString(verifyUrl)) {
        throw new QrServiceError(
            "INVALID_PAYLOAD",
            "verifyUrl must be a non-empty string"
        );
    }
    if (!isNonEmptyString(token)) {
        throw new QrServiceError(
            "INVALID_PAYLOAD",
            "token must be a non-empty string"
        );
    }
    if (status && !isNonEmptyString(status)) {
        throw new QrServiceError(
            "INVALID_PAYLOAD",
            "status must be a non-empty string when provided"
        );
    }
    if (ownerName && !isNonEmptyString(ownerName)) {
        throw new QrServiceError(
            "INVALID_PAYLOAD",
            "ownerName must be a non-empty string when provided"
        );
    }
};

const validateWidth = (width) => {
    if (width === undefined || width === null) {
        return DEFAULT_WIDTH;
    }
    if (!Number.isFinite(width) || !Number.isInteger(width)) {
        throw new QrServiceError(
            "INVALID_WIDTH",
            `width must be an integer in [${MIN_WIDTH}, ${MAX_WIDTH}], received ${width}`
        );
    }
    if (width < MIN_WIDTH || width > MAX_WIDTH) {
        throw new QrServiceError(
            "INVALID_WIDTH",
            `width must be within [${MIN_WIDTH}, ${MAX_WIDTH}], received ${width}`
        );
    }
    return width;
};

const normalizePayloadFields = () => {
    const allowedFields = new Set([
        "document_id",
        "verify_url",
        "token",
        "status",
        "owner_name"
    ]);

    const configuredFields = (process.env.QR_PAYLOAD_FIELDS || "")
        .split(",")
        .map((field) => field.trim())
        .filter(Boolean)
        .filter((field) => allowedFields.has(field));

    return configuredFields.length > 0 ? configuredFields : DEFAULT_QR_PAYLOAD_FIELDS;
};

const buildQrPayload = ({ documentId, verifyUrl, token, status, ownerName }) => {
    const source = {
        document_id: documentId,
        verify_url: verifyUrl,
        token,
        status: status || "issued",
        owner_name: ownerName || ""
    };

    return normalizePayloadFields().reduce((payload, field) => {
        payload[field] = source[field];
        return payload;
    }, {});
};

const ensureQrFolder = (documentId) => {
    let documentFolder;
    try {
        documentFolder = createDocumentFolder(documentId);
    } catch (err) {
        throw new QrServiceError(
            "STORAGE_OPERATION_FAILED",
            `Failed to create document folder for ${documentId}`,
            { cause: err }
        );
    }

    const qrFolder = path.join(documentFolder, "qr");
    try {
        if (!fs.existsSync(qrFolder)) {
            fs.mkdirSync(qrFolder, { recursive: true });
        }
    } catch (err) {
        throw new QrServiceError(
            "STORAGE_OPERATION_FAILED",
            `Failed to create QR folder at ${qrFolder}`,
            { cause: err }
        );
    }
    return qrFolder;
};

const removePartialFile = (filePath) => {
    try {
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
    } catch (_cleanupErr) {
        // Swallow cleanup errors — the original failure is more informative
        // and we don't want to mask it.
    }
};

/**
 * Generate a QR code PNG for a document and return the absolute file path.
 *
 * @param {Object} input
 * @param {string} input.documentId  - Document identifier, e.g. "HS-2026-A1B2C3D4"
 * @param {string} input.verifyUrl   - Full verification URL with token query param
 * @param {string} input.token       - Verification token (raw, not hashed)
 * @param {string} [input.status]    - Document status, e.g. "issued"
 * @param {string} [input.ownerName] - Owner's full name
 * @param {number} [input.width=300] - QR pixel width, must be in [180, 500]
 * @returns {Promise<string>} Absolute path to the generated qr.png
 * @throws {QrServiceError}
 */
export const generateQR = async ({
    documentId,
    verifyUrl,
    token,
    status,
    ownerName,
    width
} = {}) => {
    validatePayload({ documentId, verifyUrl, token, status, ownerName });
    const resolvedWidth = validateWidth(width);

    const qrFolder = ensureQrFolder(documentId);
    const qrPath = path.resolve(path.join(qrFolder, "qr.png"));

    const qrData = JSON.stringify(buildQrPayload({
        documentId,
        verifyUrl,
        token,
        status,
        ownerName
    }));

    // Pick the smallest version >= 5 that fits the payload at error
    // correction level H. The qrcode lib will not auto-promote when
    // `version` is set, so we probe for the minimum required version and
    // floor it to 5 (Requirement 2.1).
    let resolvedVersion = 5;
    try {
        const probe = QRCode.create(qrData, { errorCorrectionLevel: "H" });
        resolvedVersion = Math.max(5, probe.version);
    } catch (err) {
        throw new QrServiceError(
            "QR_GENERATION_FAILED",
            `Failed to determine QR version for document ${documentId}`,
            { cause: err }
        );
    }

    const options = {
        errorCorrectionLevel: "H",
        version: resolvedVersion,
        type: "png",
        width: resolvedWidth
    };

    try {
        await QRCode.toFile(qrPath, qrData, options);
    } catch (err) {
        removePartialFile(qrPath);
        throw new QrServiceError(
            "QR_GENERATION_FAILED",
            `Failed to encode QR for document ${documentId}`,
            { cause: err }
        );
    }

    return qrPath;
};

/**
 * Backwards-compatible alias of {@link generateQR} using the default width.
 * Existing callers (e.g. `document.service.js`) import this name.
 *
 * @param {Object} input
 * @param {string} input.documentId
 * @param {string} input.verifyUrl
 * @param {string} input.token
 * @param {string} [input.status]
 * @param {string} [input.ownerName]
 * @returns {Promise<string>} Absolute path to the generated qr.png
 */
export const generateQrCode = async ({ documentId, verifyUrl, token, status, ownerName } = {}) =>
    generateQR({ documentId, verifyUrl, token, status, ownerName, width: DEFAULT_WIDTH });
