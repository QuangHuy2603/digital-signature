import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
    PDFArray,
    PDFDict,
    PDFDocument,
    PDFHexString,
    PDFInvalidObject,
    PDFName,
    PDFNumber,
    PDFString,
} from "pdf-lib";
import {
    OPENSSL_BIN,
    PKI_ROOT_CA_CERT_PATH,
    PKI_TSA_CERT_PATH,
    PYTHON_BIN,
} from "../config/env.config.js";
import { createTimestampToken } from "./tsa.service.js";
import { OfficerCertificateError } from "./x509-pki.service.js";
import { resolveCmsSigningProvider } from "./signing-provider.service.js";
import { verifyPadesLtEvidence } from "./pades-lt.service.js";

const BYTE_RANGE_PLACEHOLDER = "**********";
const DEFAULT_SIGNATURE_LENGTH = 32768;
const SUBFILTER_PADES = "ETSI.CAdES.detached";
const FIELD_NAME = "NT219_PAdES_Signature";
const SIGNING_CERTIFICATE_V2_OID = "1.2.840.113549.1.9.16.2.47";
const SIGNATURE_TIMESTAMP_OID = "1.2.840.113549.1.9.16.2.14";

function resolveFromBackend(value) {
    return path.resolve(process.cwd(), value);
}

function projectOpenSslConfig() {
    return path.resolve(process.cwd(), "../pki/config/openssl-base.cnf");
}

function childEnvironment() {
    const environment = { ...process.env };
    const configured = environment.OPENSSL_CONF;
    if (!configured || !fs.existsSync(configured)) {
        environment.OPENSSL_CONF = projectOpenSslConfig();
    }
    return environment;
}

function runCommand(command, args, { binary = false, allowFailure = false, env = {} } = {}) {
    const result = spawnSync(command, args, {
        cwd: process.cwd(),
        encoding: binary ? null : "utf8",
        windowsHide: true,
        stdio: "pipe",
        env: { ...childEnvironment(), ...env },
    });
    if (result.error) {
        if (allowFailure) return result;
        throw new OfficerCertificateError(
            `Unable to run ${command}: ${result.error.message}`,
            "PADES_TOOL_UNAVAILABLE",
            503
        );
    }
    if (result.status !== 0 && !allowFailure) {
        const details = String(result.stderr || result.stdout || "").trim();
        throw new OfficerCertificateError(
            details || `${command} failed with exit ${result.status}`,
            "PADES_OPERATION_FAILED",
            500
        );
    }
    return result;
}

function runOpenSsl(args, options = {}) {
    return runCommand(OPENSSL_BIN, args, options);
}

function runCmsTool(args, options = {}) {
    const tool = path.resolve(process.cwd(), "scripts/cms-timestamp-tool.py");
    return runCommand(PYTHON_BIN, [tool, ...args], options);
}

function annotationFlags() {
    // Print + locked/read-only widget flags.
    return PDFNumber.of(4);
}

async function addPadesPlaceholder(pdfBytes, {
    signerName,
    reason = "Ký số hồ sơ dịch vụ công",
    location = "HCMUTE",
    contactInfo = "",
    signingTime = new Date(),
    signatureLength = DEFAULT_SIGNATURE_LENGTH,
} = {}) {
    const pdfDoc = await PDFDocument.load(pdfBytes, {
        updateMetadata: false,
        ignoreEncryption: false,
    });
    const page = pdfDoc.getPages().at(-1);
    if (!page) {
        throw new OfficerCertificateError("PDF has no pages", "PADES_INVALID_PDF", 400);
    }

    const byteRange = PDFArray.withContext(pdfDoc.context);
    byteRange.push(PDFNumber.of(0));
    byteRange.push(PDFName.of(BYTE_RANGE_PLACEHOLDER));
    byteRange.push(PDFName.of(BYTE_RANGE_PLACEHOLDER));
    byteRange.push(PDFName.of(BYTE_RANGE_PLACEHOLDER));

    const placeholder = PDFHexString.of(String.fromCharCode(0).repeat(signatureLength));
    const signatureDict = pdfDoc.context.obj({
        Type: "Sig",
        Filter: "Adobe.PPKLite",
        SubFilter: SUBFILTER_PADES,
        ByteRange: byteRange,
        Contents: placeholder,
        Reason: PDFString.of(reason),
        M: PDFString.fromDate(signingTime),
        ContactInfo: PDFString.of(contactInfo || ""),
        Name: PDFString.of(signerName || "NT219 Officer"),
        Location: PDFString.of(location),
        Prop_Build: {
            Filter: { Name: "Adobe.PPKLite" },
            App: { Name: "NT219 Citizen Services Portal" },
        },
    });

    const signatureBuffer = new Uint8Array(signatureDict.sizeInBytes());
    signatureDict.copyBytesInto(signatureBuffer, 0);
    const signatureRef = pdfDoc.context.register(PDFInvalidObject.of(signatureBuffer));

    const appearance = pdfDoc.context.formXObject([], {
        BBox: [0, 0, 0, 0],
        Resources: {},
    });
    const widget = pdfDoc.context.obj({
        Type: "Annot",
        Subtype: "Widget",
        FT: "Sig",
        Rect: [0, 0, 0, 0],
        V: signatureRef,
        T: PDFString.of(FIELD_NAME),
        F: annotationFlags(),
        P: page.ref,
        AP: { N: pdfDoc.context.register(appearance) },
    });
    const widgetRef = pdfDoc.context.register(widget);

    let annotations = page.node.lookupMaybe(PDFName.of("Annots"), PDFArray);
    if (!annotations) annotations = pdfDoc.context.obj([]);
    annotations.push(widgetRef);
    page.node.set(PDFName.of("Annots"), annotations);

    let acroForm = pdfDoc.catalog.lookupMaybe(PDFName.of("AcroForm"), PDFDict);
    if (!acroForm) {
        acroForm = pdfDoc.context.obj({ Fields: [] });
        pdfDoc.catalog.set(PDFName.of("AcroForm"), pdfDoc.context.register(acroForm));
    }
    const oldFlags = acroForm.has(PDFName.of("SigFlags"))
        ? acroForm.get(PDFName.of("SigFlags")).asNumber()
        : 0;
    acroForm.set(PDFName.of("SigFlags"), PDFNumber.of(oldFlags | 1 | 2));
    let fields = acroForm.get(PDFName.of("Fields"));
    if (!(fields instanceof PDFArray)) {
        fields = pdfDoc.context.obj([]);
        acroForm.set(PDFName.of("Fields"), fields);
    }
    fields.push(widgetRef);

    return Buffer.from(await pdfDoc.save({
        useObjectStreams: false,
        addDefaultPage: false,
        updateFieldAppearances: false,
    }));
}

function locatePlaceholder(pdfBuffer) {
    const source = pdfBuffer.toString("latin1");
    const match = /\/ByteRange\s*\[\s*0\s+\/\*{10}\s+\/\*{10}\s+\/\*{10}\s*\]/.exec(source);
    const marker = match?.[0] || "";
    const markerPosition = match?.index ?? -1;
    if (markerPosition < 0) {
        throw new OfficerCertificateError(
            "PAdES ByteRange placeholder was not found",
            "PADES_PLACEHOLDER_NOT_FOUND",
            500
        );
    }
    const markerEnd = markerPosition + marker.length;
    const contentsPosition = pdfBuffer.indexOf("/Contents ", markerEnd);
    const placeholderStart = pdfBuffer.indexOf("<", contentsPosition);
    const placeholderEnd = pdfBuffer.indexOf(">", placeholderStart);
    if (contentsPosition < 0 || placeholderStart < 0 || placeholderEnd < 0) {
        throw new OfficerCertificateError(
            "PAdES Contents placeholder was not found",
            "PADES_PLACEHOLDER_NOT_FOUND",
            500
        );
    }
    return { marker, markerPosition, markerEnd, placeholderStart, placeholderEnd };
}

function prepareByteRange(pdfBuffer) {
    const located = locatePlaceholder(pdfBuffer);
    const byteRange = [
        0,
        located.placeholderStart,
        located.placeholderEnd + 1,
        pdfBuffer.length - (located.placeholderEnd + 1),
    ];
    let actual = `/ByteRange [${byteRange.join(" ")}]`;
    if (actual.length > located.marker.length) {
        throw new OfficerCertificateError(
            "PAdES ByteRange placeholder is too short",
            "PADES_BYTE_RANGE_OVERFLOW",
            500
        );
    }
    actual += " ".repeat(located.marker.length - actual.length);
    const withByteRange = Buffer.concat([
        pdfBuffer.subarray(0, located.markerPosition),
        Buffer.from(actual, "ascii"),
        pdfBuffer.subarray(located.markerEnd),
    ]);
    const signedContent = Buffer.concat([
        withByteRange.subarray(0, byteRange[1]),
        withByteRange.subarray(byteRange[2], byteRange[2] + byteRange[3]),
    ]);
    return {
        withByteRange,
        signedContent,
        byteRange,
        placeholderHexLength: located.placeholderEnd - located.placeholderStart - 1,
    };
}

function embedCms(withByteRange, byteRange, placeholderHexLength, cmsDer) {
    const cmsHex = cmsDer.toString("hex").toUpperCase();
    if (cmsHex.length > placeholderHexLength) {
        throw new OfficerCertificateError(
            `CMS signature exceeds PDF placeholder (${cmsHex.length} > ${placeholderHexLength})`,
            "PADES_SIGNATURE_TOO_LARGE",
            500
        );
    }
    const padded = cmsHex + "0".repeat(placeholderHexLength - cmsHex.length);
    return Buffer.concat([
        withByteRange.subarray(0, byteRange[1]),
        Buffer.from(`<${padded}>`, "ascii"),
        withByteRange.subarray(byteRange[2]),
    ]);
}

function parseDerTotalLength(buffer) {
    if (buffer.length < 2 || buffer[0] !== 0x30) {
        throw new OfficerCertificateError("CMS is not a DER SEQUENCE", "PADES_CMS_INVALID", 400);
    }
    const first = buffer[1];
    if ((first & 0x80) === 0) return 2 + first;
    const octets = first & 0x7f;
    if (octets === 0 || octets > 6 || buffer.length < 2 + octets) {
        throw new OfficerCertificateError("CMS DER length is invalid", "PADES_CMS_INVALID", 400);
    }
    let length = 0;
    for (let index = 0; index < octets; index += 1) {
        length = (length * 256) + buffer[2 + index];
    }
    return 2 + octets + length;
}

export function extractPadesContainer(pdfBuffer) {
    const matches = [...pdfBuffer.toString("latin1").matchAll(
        /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g
    )];
    if (matches.length === 0) {
        throw new OfficerCertificateError(
            "The PDF does not contain a digital signature field",
            "PADES_SIGNATURE_NOT_FOUND",
            400
        );
    }
    const match = matches[0];
    const byteRange = match.slice(1, 5).map((value) => Number(value));
    const [offset1, length1, offset2, length2] = byteRange;
    const signedRevisionLength = offset2 + length2;
    const validRange = offset1 === 0 && length1 > 0 && offset2 > length1 &&
        length2 >= 0 && signedRevisionLength <= pdfBuffer.length;
    if (!validRange) {
        throw new OfficerCertificateError("Invalid PDF ByteRange", "PADES_BYTE_RANGE_INVALID", 400);
    }
    const contentsSlice = pdfBuffer.subarray(length1, offset2).toString("ascii");
    const contentMatch = contentsSlice.match(/^<([0-9A-Fa-f]+)>$/);
    if (!contentMatch) {
        throw new OfficerCertificateError("Invalid PDF signature Contents", "PADES_CONTENTS_INVALID", 400);
    }
    const paddedCms = Buffer.from(contentMatch[1], "hex");
    const totalLength = parseDerTotalLength(paddedCms);
    if (totalLength > paddedCms.length) {
        throw new OfficerCertificateError("Truncated CMS signature", "PADES_CMS_INVALID", 400);
    }
    const cmsDer = paddedCms.subarray(0, totalLength);
    const signedContent = Buffer.concat([
        pdfBuffer.subarray(offset1, offset1 + length1),
        pdfBuffer.subarray(offset2, offset2 + length2),
    ]);
    return {
        byteRange,
        cmsDer,
        signedContent,
        signedRevisionLength,
        incrementalUpdatePresent: signedRevisionLength < pdfBuffer.length,
    };
}

function certificatePems(pemBundle) {
    return [...String(pemBundle).matchAll(
        /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g
    )].map((match) => `${match[0]}\n`);
}

function normalizeFingerprint(value) {
    return String(value || "").replace(/:/g, "").trim().toUpperCase();
}

function parseTimestampText(text = "") {
    const value = String(text);
    const timestampText = value.match(/Time stamp:\s*(.+)/i)?.[1]?.trim() || null;
    const parsedTime = timestampText ? new Date(timestampText) : null;
    return {
        policy_oid: value.match(/Policy OID:\s*([^\r\n]+)/i)?.[1]?.trim() || null,
        serial_number: value.match(/Serial number:\s*([^\r\n]+)/i)?.[1]?.trim() || null,
        timestamp: parsedTime && !Number.isNaN(parsedTime.getTime())
            ? parsedTime.toISOString()
            : timestampText,
    };
}

function verifyEmbeddedTimestamp({ cmsPath, signaturePath, timestampTokenPath, temp }) {
    const extractResult = runCmsTool([
        "extract-signature", "--cms", cmsPath, "--output", signaturePath,
    ], { allowFailure: true });
    if (extractResult.status !== 0) {
        return { valid: false, reason: "PADES_TIMESTAMP_SIGNATURE_VALUE_UNAVAILABLE" };
    }
    const tokenResult = runCmsTool([
        "extract-timestamp", "--cms", cmsPath, "--output", timestampTokenPath,
    ], { allowFailure: true });
    if (tokenResult.status !== 0) {
        return { valid: false, reason: "PADES_TIMESTAMP_NOT_FOUND" };
    }
    const rootCert = resolveFromBackend(PKI_ROOT_CA_CERT_PATH);
    const tsaCert = resolveFromBackend(PKI_TSA_CERT_PATH);
    const verification = runOpenSsl([
        "ts", "-verify", "-token_in",
        "-data", signaturePath,
        "-in", timestampTokenPath,
        "-CAfile", rootCert,
        "-untrusted", tsaCert,
    ], { allowFailure: true });
    if (verification.status !== 0) {
        return {
            valid: false,
            reason: "PADES_TIMESTAMP_INVALID",
            error: String(verification.stderr || verification.stdout || "").trim(),
        };
    }
    const text = runOpenSsl([
        "ts", "-reply", "-token_in", "-in", timestampTokenPath, "-text",
    ]);
    return {
        valid: true,
        reason: "TIMESTAMP_VALID",
        ...parseTimestampText(text.stdout || text.stderr || ""),
    };
}

export async function createPadesBtSignature({
    inputPdfPath,
    outputPdfPath,
    certificateRecord,
    signer,
    issuedAt = new Date().toISOString(),
    evidenceDirectory,
} = {}) {
    if (!inputPdfPath || !outputPdfPath || !certificateRecord) {
        throw new OfficerCertificateError("PAdES signing input is incomplete", "PADES_INPUT_REQUIRED", 400);
    }
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-pades-sign-"));
    try {
        const source = fs.readFileSync(inputPdfPath);
        const placeholderPdf = await addPadesPlaceholder(source, {
            signerName: signer?.full_name || certificateRecord.full_name || "NT219 Officer",
            contactInfo: signer?.email || certificateRecord.email || "",
            signingTime: new Date(issuedAt),
        });
        const prepared = prepareByteRange(placeholderPdf);
        const contentPath = path.join(temp, "signed-content.bin");
        const cmsBbPath = path.join(temp, "pades-bb.cms.der");
        const signatureValuePath = path.join(temp, "signer-signature.bin");
        const cmsBtPath = path.join(temp, "pades-bt.cms.der");
        fs.writeFileSync(contentPath, prepared.signedContent);

        const certificatePath = resolveFromBackend(certificateRecord.certificate_path);
        const signingProvider = resolveCmsSigningProvider(certificateRecord);
        const rootCertPath = resolveFromBackend(
            certificateRecord.root_ca_certificate_path || PKI_ROOT_CA_CERT_PATH
        );
        runOpenSsl([
            "cms", "-sign", "-binary", "-cades", "-nosmimecap",
            "-md", "sha256",
            "-in", contentPath,
            "-signer", certificatePath,
            ...signingProvider.openssl_args,
            "-certfile", rootCertPath,
            "-outform", "DER",
            "-out", cmsBbPath,
        ], { env: signingProvider.env });

        runCmsTool([
            "extract-signature", "--cms", cmsBbPath, "--output", signatureValuePath,
        ]);
        const timestampDirectory = evidenceDirectory || path.join(temp, "timestamps");
        const timestampEvidence = createTimestampToken({
            dataBuffer: fs.readFileSync(signatureValuePath),
            outputDirectory: timestampDirectory,
            baseName: "pades-signature-timestamp",
        });
        runCmsTool([
            "attach-timestamp",
            "--cms", cmsBbPath,
            "--tsr", timestampEvidence.response_path,
            "--output", cmsBtPath,
        ]);

        const cmsDer = fs.readFileSync(cmsBtPath);
        const signedPdf = embedCms(
            prepared.withByteRange,
            prepared.byteRange,
            prepared.placeholderHexLength,
            cmsDer
        );
        fs.mkdirSync(path.dirname(outputPdfPath), { recursive: true });
        fs.writeFileSync(outputPdfPath, signedPdf);

        let savedCmsBbPath = null;
        let savedCmsBtPath = null;
        if (evidenceDirectory) {
            fs.mkdirSync(evidenceDirectory, { recursive: true });
            savedCmsBbPath = path.join(evidenceDirectory, "pades-bb.cms.der");
            savedCmsBtPath = path.join(evidenceDirectory, "pades-bt.cms.der");
            fs.copyFileSync(cmsBbPath, savedCmsBbPath);
            fs.copyFileSync(cmsBtPath, savedCmsBtPath);
        }

        const verification = verifyPadesPdf({
            pdfBuffer: signedPdf,
            expectedFingerprint: certificateRecord.fingerprint_sha256,
        });
        if (!verification.valid) {
            throw new OfficerCertificateError(
                `Created PAdES PDF failed self-verification: ${verification.reason}`,
                "PADES_SELF_VERIFICATION_FAILED",
                500
            );
        }
        return {
            format: "PAdES",
            baseline_level: "PAdES-B-T",
            subfilter: SUBFILTER_PADES,
            digest_algorithm: "SHA-256",
            signature_algorithm: "ECDSA-P256-SHA256",
            key_provider: signingProvider.provider,
            key_reference: signingProvider.key_reference,
            key_exportable: signingProvider.key_exportable,
            signature_field_name: FIELD_NAME,
            byte_range: prepared.byteRange,
            cms_sha256: crypto.createHash("sha256").update(cmsDer).digest("hex").toUpperCase(),
            cms_der_path: savedCmsBtPath,
            cms_bb_der_path: savedCmsBbPath,
            timestamp_evidence: timestampEvidence,
            verification,
        };
    } finally {
        fs.rmSync(temp, { recursive: true, force: true });
    }
}

export function verifyPadesPdf({ pdfPath, pdfBuffer, expectedFingerprint = "" } = {}) {
    const source = pdfBuffer || (pdfPath ? fs.readFileSync(pdfPath) : null);
    if (!source) {
        return { valid: false, reason: "PADES_INPUT_REQUIRED", format: "PAdES" };
    }
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-pades-verify-"));
    try {
        let extracted;
        try {
            extracted = extractPadesContainer(Buffer.from(source));
        } catch (error) {
            return {
                valid: false,
                reason: error.code || "PADES_SIGNATURE_NOT_FOUND",
                format: "PAdES",
                byte_range_valid: false,
                cms_signature_valid: false,
                timestamp_valid: false,
            };
        }
        const contentPath = path.join(temp, "signed-content.bin");
        const cmsPath = path.join(temp, "signature.cms.der");
        const verifiedContentPath = path.join(temp, "verified-content.bin");
        const certificatesPath = path.join(temp, "certificates.pem");
        const signaturePath = path.join(temp, "signature-value.bin");
        const timestampTokenPath = path.join(temp, "timestamp-token.der");
        fs.writeFileSync(contentPath, extracted.signedContent);
        fs.writeFileSync(cmsPath, extracted.cmsDer);

        const rootCert = resolveFromBackend(PKI_ROOT_CA_CERT_PATH);
        const cmsVerification = runOpenSsl([
            "cms", "-verify", "-binary", "-inform", "DER",
            "-in", cmsPath,
            "-content", contentPath,
            "-CAfile", rootCert,
            "-purpose", "any",
            "-out", verifiedContentPath,
        ], { allowFailure: true });
        if (cmsVerification.status !== 0) {
            return {
                valid: false,
                reason: "PADES_CMS_SIGNATURE_INVALID",
                format: "PAdES",
                baseline_level: null,
                subfilter: SUBFILTER_PADES,
                byte_range_valid: true,
                byte_range: extracted.byteRange,
                cms_signature_valid: false,
                timestamp_valid: false,
                cms_error: String(cmsVerification.stderr || cmsVerification.stdout || "").trim(),
            };
        }

        const inspect = runCmsTool(["inspect", "--cms", cmsPath], { allowFailure: true });
        let cmsInspection = {};
        try { cmsInspection = JSON.parse(String(inspect.stdout || "{}")); } catch (_) { /* ignored */ }
        const hasSigningCertificate = cmsInspection.has_signing_certificate_v2 === true ||
            (cmsInspection.signed_attribute_oids || []).includes(SIGNING_CERTIFICATE_V2_OID);
        const hasTimestamp = cmsInspection.has_signature_timestamp === true ||
            (cmsInspection.unsigned_attribute_oids || []).includes(SIGNATURE_TIMESTAMP_OID);

        const certExtraction = runOpenSsl([
            "pkcs7", "-inform", "DER", "-in", cmsPath, "-print_certs", "-out", certificatesPath,
        ], { allowFailure: true });
        if (certExtraction.status !== 0) {
            return {
                valid: false,
                reason: "PADES_SIGNER_CERTIFICATE_NOT_FOUND",
                format: "PAdES",
                byte_range_valid: true,
                cms_signature_valid: true,
                timestamp_valid: false,
            };
        }
        const certificates = certificatePems(fs.readFileSync(certificatesPath, "utf8"));
        if (certificates.length === 0) {
            return {
                valid: false,
                reason: "PADES_SIGNER_CERTIFICATE_NOT_FOUND",
                format: "PAdES",
                byte_range_valid: true,
                cms_signature_valid: true,
                timestamp_valid: false,
            };
        }
        const parsedCertificates = certificates.map((pem) => new crypto.X509Certificate(pem));
        const expectedNormalized = normalizeFingerprint(expectedFingerprint);
        let signerCertificate = expectedNormalized
            ? parsedCertificates.find((certificate) =>
                normalizeFingerprint(certificate.fingerprint256) === expectedNormalized)
            : parsedCertificates.find((certificate) => certificate.ca === false) || parsedCertificates[0];
        if (!signerCertificate && expectedNormalized) {
            const observed = parsedCertificates.map((certificate) =>
                normalizeFingerprint(certificate.fingerprint256));
            return {
                valid: false,
                reason: "PADES_SIGNER_CERTIFICATE_MISMATCH",
                format: "PAdES",
                byte_range_valid: true,
                byte_range: extracted.byteRange,
                cms_signature_valid: true,
                cades_signing_certificate_attribute: hasSigningCertificate,
                timestamp_valid: false,
                signer_fingerprint_sha256: observed[0] || null,
            };
        }
        signerCertificate ||= parsedCertificates[0];
        const signerFingerprint = normalizeFingerprint(signerCertificate.fingerprint256);

        const timestamp = hasTimestamp
            ? verifyEmbeddedTimestamp({ cmsPath, signaturePath, timestampTokenPath, temp })
            : { valid: false, reason: "PADES_TIMESTAMP_NOT_FOUND" };
        const baselineLevel = timestamp.valid ? "PAdES-B-T" : "PAdES-B-B";
        const baseValid = hasSigningCertificate && timestamp.valid;
        const baseResult = {
            valid: baseValid,
            reason: baseValid ? "VALID_PADES_B_T" :
                !hasSigningCertificate ? "PADES_CADES_SIGNING_CERTIFICATE_ATTRIBUTE_MISSING" :
                    timestamp.reason,
            format: "PAdES",
            baseline_level: baselineLevel,
            subfilter: SUBFILTER_PADES,
            byte_range_valid: true,
            byte_range: extracted.byteRange,
            signed_revision_length: extracted.signedRevisionLength,
            incremental_update_present: extracted.incrementalUpdatePresent,
            cms_signature_valid: true,
            cades_signing_certificate_attribute: hasSigningCertificate,
            timestamp_valid: timestamp.valid,
            timestamp_reason: timestamp.reason,
            timestamp: timestamp.timestamp || null,
            timestamp_policy_oid: timestamp.policy_oid || null,
            timestamp_serial_number: timestamp.serial_number || null,
            signer_subject: signerCertificate.subject,
            signer_issuer: signerCertificate.issuer,
            signer_serial_number: signerCertificate.serialNumber,
            signer_fingerprint_sha256: signerFingerprint,
            signer_valid_from: signerCertificate.validFrom,
            signer_valid_to: signerCertificate.validTo,
            cms_sha256: crypto.createHash("sha256").update(extracted.cmsDer).digest("hex").toUpperCase(),
        };
        if (!baseValid) return baseResult;
        if (!extracted.incrementalUpdatePresent) return baseResult;

        const ltEvidence = verifyPadesLtEvidence({
            pdfBuffer: Buffer.from(source),
            cmsDer: extracted.cmsDer,
            signedRevisionLength: extracted.signedRevisionLength,
            expectedFingerprint: signerFingerprint,
            signatureTimestamp: timestamp.timestamp || null,
        });
        if (!ltEvidence.valid) {
            return {
                ...baseResult,
                valid: false,
                reason: ltEvidence.reason,
                baseline_level: null,
                pades_lt: ltEvidence,
            };
        }
        return {
            ...baseResult,
            valid: true,
            reason: "VALID_PADES_LT",
            baseline_level: "PAdES-LT",
            dss_present: true,
            vri_present: true,
            offline_verification_ready: true,
            pades_lt: ltEvidence,
        };
    } catch (error) {
        return {
            valid: false,
            reason: error.code || "PADES_VERIFICATION_FAILED",
            error: error.message,
            format: "PAdES",
        };
    } finally {
        fs.rmSync(temp, { recursive: true, force: true });
    }
}

export function getPadesStatus() {
    return {
        ready: fs.existsSync(projectOpenSslConfig()) &&
            fs.existsSync(resolveFromBackend(PKI_ROOT_CA_CERT_PATH)) &&
            fs.existsSync(resolveFromBackend(PKI_TSA_CERT_PATH)),
        format: "PAdES",
        supported_levels: ["PAdES-B-B", "PAdES-B-T", "PAdES-LT"],
        default_level: "PAdES-LT",
        lt_profile: {
            dss: true,
            vri: true,
            embedded_certificates: true,
            embedded_ocsp: true,
            embedded_crl: true,
            incremental_update: true,
            offline_revocation_evidence: true,
        },
        subfilter: SUBFILTER_PADES,
        signature_algorithm: "ECDSA-P256-SHA256",
        digest_algorithm: "SHA-256",
        timestamp_protocol: "RFC 3161",
        lab_only: true,
    };
}
