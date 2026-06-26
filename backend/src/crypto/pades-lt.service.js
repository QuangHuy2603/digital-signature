import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { PDFDocument } from "pdf-lib";
import {
    OPENSSL_BIN,
    PKI_CRL_PATH,
    PKI_OCSP_RESPONDER_CERT_PATH,
    PKI_ROOT_CA_CERT_PATH,
    PKI_TSA_CERT_PATH,
} from "../config/env.config.js";
import { OfficerCertificateError } from "./x509-pki.service.js";

const PDF_WHITESPACE = /\s+/g;
const DSS_TYPE = "DSS";

function resolveFromBackend(value) {
    return path.resolve(process.cwd(), value);
}

function projectOpenSslConfig() {
    return path.resolve(process.cwd(), "../pki/config/openssl-base.cnf");
}

function childEnvironment() {
    const environment = { ...process.env };
    if (!environment.OPENSSL_CONF || !fs.existsSync(environment.OPENSSL_CONF)) {
        environment.OPENSSL_CONF = projectOpenSslConfig();
    }
    return environment;
}

function runOpenSsl(args, { allowFailure = false, binary = false } = {}) {
    const result = spawnSync(OPENSSL_BIN, args, {
        cwd: process.cwd(),
        encoding: binary ? null : "utf8",
        windowsHide: true,
        stdio: "pipe",
        env: childEnvironment(),
    });
    if ((result.error || result.status !== 0) && !allowFailure) {
        throw new OfficerCertificateError(
            String(result.stderr || result.stdout || result.error?.message || "PAdES-LT OpenSSL operation failed").trim(),
            "PADES_LT_OPENSSL_OPERATION_FAILED",
            500
        );
    }
    return result;
}

function normalizeFingerprint(value) {
    return String(value || "").replace(/:/g, "").trim().toUpperCase();
}

function sha256(buffer) {
    return crypto.createHash("sha256").update(buffer).digest("hex").toUpperCase();
}

function sha1(buffer) {
    return crypto.createHash("sha1").update(buffer).digest("hex").toUpperCase();
}

function pdfDate(value = new Date()) {
    const date = new Date(value);
    const pad = (number) => String(number).padStart(2, "0");
    return `D:${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
        `${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
}

function lastStartXref(buffer, limit = buffer.length) {
    const text = buffer.subarray(0, limit).toString("latin1");
    const matches = [...text.matchAll(/startxref\s+(\d+)\s+%%EOF/g)];
    if (!matches.length) {
        throw new OfficerCertificateError("PDF startxref was not found", "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
    }
    return Number(matches.at(-1)[1]);
}

function extractCmsAndRevision(pdfBuffer) {
    const matches = [...pdfBuffer.toString("latin1").matchAll(
        /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g
    )];
    if (!matches.length) {
        throw new OfficerCertificateError("PAdES signature was not found", "PADES_SIGNATURE_NOT_FOUND", 400);
    }
    const byteRange = matches[0].slice(1, 5).map(Number);
    const [offset1, length1, offset2, length2] = byteRange;
    const signedRevisionLength = offset2 + length2;
    if (offset1 !== 0 || length1 <= 0 || offset2 <= length1 || length2 < 0 || signedRevisionLength > pdfBuffer.length) {
        throw new OfficerCertificateError("Invalid PDF ByteRange", "PADES_BYTE_RANGE_INVALID", 400);
    }
    const contentsSlice = pdfBuffer.subarray(length1, offset2).toString("ascii");
    const match = contentsSlice.match(/^<([0-9A-Fa-f]+)>$/);
    if (!match) {
        throw new OfficerCertificateError("Invalid PDF signature Contents", "PADES_CONTENTS_INVALID", 400);
    }
    const padded = Buffer.from(match[1], "hex");
    if (padded.length < 2 || padded[0] !== 0x30) {
        throw new OfficerCertificateError("Invalid CMS DER", "PADES_CMS_INVALID", 400);
    }
    const first = padded[1];
    let header = 2;
    let length = 0;
    if ((first & 0x80) === 0) {
        length = first;
    } else {
        const octets = first & 0x7f;
        if (!octets || octets > 6 || padded.length < 2 + octets) {
            throw new OfficerCertificateError("Invalid CMS DER length", "PADES_CMS_INVALID", 400);
        }
        header += octets;
        for (let index = 0; index < octets; index += 1) length = length * 256 + padded[2 + index];
    }
    const total = header + length;
    if (total > padded.length) {
        throw new OfficerCertificateError("Truncated CMS DER", "PADES_CMS_INVALID", 400);
    }
    return { cmsDer: padded.subarray(0, total), byteRange, signedRevisionLength };
}

function readCertificateDer(filePath) {
    const pem = fs.readFileSync(filePath, "utf8");
    return Buffer.from(new crypto.X509Certificate(pem).raw);
}

function convertCrlToDer(crlPath, tempDirectory) {
    const output = path.join(tempDirectory, "embedded-root-ca.crl.der");
    runOpenSsl(["crl", "-in", crlPath, "-outform", "DER", "-out", output]);
    return fs.readFileSync(output);
}

function deduplicateBuffers(buffers) {
    const seen = new Set();
    const output = [];
    for (const buffer of buffers) {
        const digest = sha256(buffer);
        if (seen.has(digest)) continue;
        seen.add(digest);
        output.push(buffer);
    }
    return output;
}

function buildIndirectObject(number, generation, body) {
    const header = Buffer.from(`${number} ${generation} obj\n`, "ascii");
    const footer = Buffer.from("\nendobj\n", "ascii");
    return Buffer.concat([header, Buffer.isBuffer(body) ? body : Buffer.from(body, "latin1"), footer]);
}

function buildStreamBody(data) {
    return Buffer.concat([
        Buffer.from(`<< /Length ${data.length} >>\nstream\n`, "ascii"),
        data,
        Buffer.from("\nendstream", "ascii"),
    ]);
}

function appendDssToCatalog(catalogText, dssReference) {
    if (/\/DSS\s+\d+\s+\d+\s+R/.test(catalogText)) {
        throw new OfficerCertificateError("PDF already contains DSS", "PADES_DSS_ALREADY_PRESENT", 409);
    }
    const closing = catalogText.lastIndexOf(">>");
    if (closing < 0) {
        throw new OfficerCertificateError("PDF catalog is invalid", "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
    }
    return `${catalogText.slice(0, closing)}\n/DSS ${dssReference}\n${catalogText.slice(closing)}`;
}

function refText(ref) {
    return `${ref.objectNumber} ${ref.generationNumber} R`;
}

function trailerText({ size, root, info, encrypt, id, prev }) {
    const entries = [`/Size ${size}`, `/Root ${refText(root)}`, `/Prev ${prev}`];
    if (info) entries.push(`/Info ${refText(info)}`);
    if (encrypt) entries.push(`/Encrypt ${refText(encrypt)}`);
    if (id) entries.push(`/ID ${id.toString()}`);
    return `trailer\n<<\n${entries.join("\n")}\n>>\n`;
}

function buildXref(entries) {
    const sorted = [...entries].sort((left, right) => left.number - right.number);
    const groups = [];
    for (const entry of sorted) {
        const current = groups.at(-1);
        if (!current || current.at(-1).number + 1 !== entry.number) groups.push([entry]);
        else current.push(entry);
    }
    let text = "xref\n";
    for (const group of groups) {
        text += `${group[0].number} ${group.length}\n`;
        for (const item of group) {
            text += `${String(item.offset).padStart(10, "0")} ${String(item.generation).padStart(5, "0")} n \n`;
        }
    }
    return text;
}

function parseXrefAt(buffer, offset) {
    const source = buffer.toString("latin1", offset);
    if (!source.startsWith("xref")) {
        throw new OfficerCertificateError("Final incremental xref is missing", "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
    }
    const trailerIndex = source.indexOf("trailer");
    if (trailerIndex < 0) {
        throw new OfficerCertificateError("Final incremental trailer is missing", "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
    }
    const xrefText = source.slice(4, trailerIndex).trim();
    const lines = xrefText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const entries = new Map();
    let index = 0;
    while (index < lines.length) {
        const header = lines[index++].match(/^(\d+)\s+(\d+)$/);
        if (!header) throw new OfficerCertificateError("Invalid incremental xref subsection", "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
        const start = Number(header[1]);
        const count = Number(header[2]);
        for (let item = 0; item < count; item += 1) {
            const row = lines[index++]?.match(/^(\d{10})\s+(\d{5})\s+([nf])$/);
            if (!row) throw new OfficerCertificateError("Invalid incremental xref entry", "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
            if (row[3] === "n") entries.set(start + item, { offset: Number(row[1]), generation: Number(row[2]) });
        }
    }
    const trailerSource = source.slice(trailerIndex);
    const trailerMatch = trailerSource.match(/^trailer\s*(<<[\s\S]*?>>)\s*startxref\s+(\d+)\s+%%EOF/);
    if (!trailerMatch) {
        throw new OfficerCertificateError("Invalid final incremental trailer", "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
    }
    const trailer = trailerMatch[1];
    return {
        entries,
        trailer,
        size: Number(trailer.match(/\/Size\s+(\d+)/)?.[1] || 0),
        prev: Number(trailer.match(/\/Prev\s+(\d+)/)?.[1] || -1),
        rootNumber: Number(trailer.match(/\/Root\s+(\d+)\s+(\d+)\s+R/)?.[1] || -1),
        rootGeneration: Number(trailer.match(/\/Root\s+(\d+)\s+(\d+)\s+R/)?.[2] || -1),
        matchedLength: trailerIndex + trailerMatch[0].length,
    };
}

function readObjectAt(buffer, number, entry) {
    const start = entry.offset;
    const header = `${number} ${entry.generation} obj`;
    if (buffer.toString("latin1", start, start + header.length) !== header) {
        throw new OfficerCertificateError(`Object ${number} xref mismatch`, "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
    }
    const objectStart = start + header.length;
    const end = buffer.indexOf(Buffer.from("\nendobj", "ascii"), objectStart);
    if (end < 0) throw new OfficerCertificateError(`Object ${number} is not terminated`, "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
    return buffer.subarray(objectStart, end).toString("latin1").trim();
}

function readStreamAt(buffer, number, entry) {
    const start = entry.offset;
    const header = `${number} ${entry.generation} obj`;
    if (buffer.toString("latin1", start, start + header.length) !== header) {
        throw new OfficerCertificateError(`Object ${number} xref mismatch`, "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
    }
    const streamMarker = buffer.indexOf(Buffer.from("stream\n", "ascii"), start + header.length);
    if (streamMarker < 0) throw new OfficerCertificateError(`Object ${number} is not a stream`, "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
    const dictionary = buffer.subarray(start + header.length, streamMarker).toString("latin1");
    const length = Number(dictionary.match(/\/Length\s+(\d+)/)?.[1] || -1);
    if (length < 0) throw new OfficerCertificateError(`Object ${number} stream length is invalid`, "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
    const dataStart = streamMarker + Buffer.byteLength("stream\n", "ascii");
    const dataEnd = dataStart + length;
    if (dataEnd > buffer.length) throw new OfficerCertificateError(`Object ${number} stream is truncated`, "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
    return buffer.subarray(dataStart, dataEnd);
}

function parseReferenceArray(dictionary, key) {
    const match = dictionary.match(new RegExp(`/${key}\\s*\\[([^\\]]*)\\]`));
    if (!match) return [];
    return [...match[1].matchAll(/(\d+)\s+(\d+)\s+R/g)].map((item) => ({
        number: Number(item[1]), generation: Number(item[2]),
    }));
}

function normalizedDictionary(value) {
    return String(value || "").replace(PDF_WHITESPACE, " ").trim();
}

function parseOpenSslTime(text, label) {
    const value = text.match(new RegExp(`${label}:\\s*(.+)`))?.[1]?.trim();
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
}

function verifyEmbeddedEvidence({ certificates, ocsp, crl, expectedFingerprint, signatureTimestamp }) {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-pades-lt-verify-"));
    try {
        const parsed = certificates.map((buffer) => new crypto.X509Certificate(buffer));
        const signer = parsed.find((certificate) => normalizeFingerprint(certificate.fingerprint256) === normalizeFingerprint(expectedFingerprint)) ||
            parsed.find((certificate) => certificate.ca === false && !/OCSP Responder|Time Stamping/i.test(certificate.subject));
        const root = parsed.find((certificate) => certificate.ca === true && certificate.subject === certificate.issuer);
        const responder = parsed.find((certificate) => /OCSP Responder/i.test(certificate.subject));
        const tsa = parsed.find((certificate) => /Time Stamp|TSA/i.test(certificate.subject));
        if (!signer) return { valid: false, reason: "PADES_EMBEDDED_CERTIFICATE_MISSING" };
        if (!root) return { valid: false, reason: "PADES_EMBEDDED_ROOT_CERTIFICATE_MISSING" };
        if (!responder) return { valid: false, reason: "PADES_EMBEDDED_OCSP_RESPONDER_CERTIFICATE_MISSING" };
        if (!tsa) return { valid: false, reason: "PADES_EMBEDDED_TSA_CERTIFICATE_MISSING" };

        const configuredRoot = new crypto.X509Certificate(fs.readFileSync(resolveFromBackend(PKI_ROOT_CA_CERT_PATH)));
        if (normalizeFingerprint(configuredRoot.fingerprint256) !== normalizeFingerprint(root.fingerprint256)) {
            return { valid: false, reason: "PADES_EMBEDDED_ROOT_CERTIFICATE_UNTRUSTED" };
        }

        const rootPath = path.join(temp, "root.pem");
        const signerPath = path.join(temp, "signer.pem");
        const responderPath = path.join(temp, "ocsp.pem");
        const tsaPath = path.join(temp, "tsa.pem");
        const ocspPath = path.join(temp, "ocsp.der");
        const crlPath = path.join(temp, "crl.der");
        fs.writeFileSync(rootPath, root.toString());
        fs.writeFileSync(signerPath, signer.toString());
        fs.writeFileSync(responderPath, responder.toString());
        fs.writeFileSync(tsaPath, tsa.toString());
        fs.writeFileSync(ocspPath, ocsp);
        fs.writeFileSync(crlPath, crl);

        const signerChain = runOpenSsl(["verify", "-CAfile", rootPath, signerPath], { allowFailure: true });
        if (signerChain.status !== 0) return { valid: false, reason: "PADES_EMBEDDED_CERTIFICATE_CHAIN_INVALID" };
        const responderChain = runOpenSsl(["verify", "-CAfile", rootPath, responderPath], { allowFailure: true });
        if (responderChain.status !== 0) return { valid: false, reason: "PADES_EMBEDDED_OCSP_RESPONDER_UNTRUSTED" };
        const tsaChain = runOpenSsl(["verify", "-CAfile", rootPath, tsaPath], { allowFailure: true });
        if (tsaChain.status !== 0) return { valid: false, reason: "PADES_EMBEDDED_TSA_CERTIFICATE_UNTRUSTED" };

        const ocspVerify = runOpenSsl([
            "ocsp", "-respin", ocspPath, "-CAfile", rootPath,
            "-verify_other", responderPath, "-trust_other",
        ], { allowFailure: true });
        if (ocspVerify.status !== 0) return { valid: false, reason: "PADES_EMBEDDED_OCSP_INVALID" };
        const ocspTextResult = runOpenSsl(["ocsp", "-respin", ocspPath, "-text", "-noverify"], { allowFailure: true });
        if (ocspTextResult.status !== 0) return { valid: false, reason: "PADES_EMBEDDED_OCSP_INVALID" };
        const ocspText = String(ocspTextResult.stdout || ocspTextResult.stderr || "");
        const ocspSerial = normalizeFingerprint(ocspText.match(/Serial Number:\s*([0-9A-Fa-f]+)/)?.[1]);
        const signerSerial = normalizeFingerprint(signer.serialNumber);
        const ocspStatus = ocspText.match(/Cert Status:\s*(\w+)/i)?.[1]?.toLowerCase() || null;
        if (ocspSerial !== signerSerial || ocspStatus !== "good") {
            return { valid: false, reason: "PADES_EMBEDDED_OCSP_CERTIFICATE_BINDING_INVALID" };
        }

        const crlVerify = runOpenSsl([
            "crl", "-inform", "DER", "-in", crlPath,
            "-CAfile", rootPath, "-verify", "-noout",
        ], { allowFailure: true });
        if (crlVerify.status !== 0) return { valid: false, reason: "PADES_EMBEDDED_CRL_INVALID" };
        const crlTextResult = runOpenSsl(["crl", "-inform", "DER", "-in", crlPath, "-text", "-noout"], { allowFailure: true });
        if (crlTextResult.status !== 0) return { valid: false, reason: "PADES_EMBEDDED_CRL_INVALID" };
        const revokedSerials = [...String(crlTextResult.stdout || "").matchAll(/Serial Number:\s*([0-9A-Fa-f]+)/g)]
            .map((match) => normalizeFingerprint(match[1]));
        if (revokedSerials.includes(signerSerial)) return { valid: false, reason: "PADES_EMBEDDED_CRL_SIGNER_REVOKED" };

        const timestamp = signatureTimestamp ? new Date(signatureTimestamp) : null;
        const thisUpdate = parseOpenSslTime(ocspText, "This Update");
        const nextUpdate = parseOpenSslTime(ocspText, "Next Update");
        if (timestamp && !Number.isNaN(timestamp.getTime())) {
            const maximumCollectionDelayMs = 10 * 60 * 1000;
            const collectedTooLate = thisUpdate && thisUpdate.getTime() - timestamp.getTime() > maximumCollectionDelayMs;
            const timestampAfterValidity = nextUpdate && timestamp > nextUpdate;
            const invalidWindow = thisUpdate && nextUpdate && thisUpdate >= nextUpdate;
            if (collectedTooLate || timestampAfterValidity || invalidWindow) {
                return { valid: false, reason: "PADES_LT_EVIDENCE_TIME_INVALID" };
            }
        }

        return {
            valid: true,
            reason: "PADES_LT_EMBEDDED_EVIDENCE_VALID",
            signer_fingerprint_sha256: normalizeFingerprint(signer.fingerprint256),
            root_fingerprint_sha256: normalizeFingerprint(root.fingerprint256),
            ocsp_status: ocspStatus,
            ocsp_this_update: thisUpdate?.toISOString() || null,
            ocsp_next_update: nextUpdate?.toISOString() || null,
            crl_signer_revoked: false,
            certificate_count: certificates.length,
        };
    } catch (error) {
        return { valid: false, reason: error.code || "PADES_LT_EMBEDDED_EVIDENCE_INVALID", error: error.message };
    } finally {
        fs.rmSync(temp, { recursive: true, force: true });
    }
}

export async function upgradePadesBtToLt({
    inputPdfPath,
    outputPdfPath,
    certificateRecord,
    ocspEvidence,
    crlPath = PKI_CRL_PATH,
    embeddedAt = new Date().toISOString(),
} = {}) {
    if (!inputPdfPath || !outputPdfPath || !certificateRecord || !ocspEvidence?.response_der_base64) {
        throw new OfficerCertificateError("PAdES-LT evidence input is incomplete", "PADES_LT_INPUT_REQUIRED", 400);
    }
    const source = fs.readFileSync(inputPdfPath);
    const extracted = extractCmsAndRevision(source);
    if (extracted.signedRevisionLength !== source.length) {
        throw new OfficerCertificateError("Input must be a final PAdES-B-T revision", "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
    }

    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "nt219-pades-lt-create-"));
    try {
        const pdfDoc = await PDFDocument.load(source, { updateMetadata: false, ignoreEncryption: false });
        const rootRef = pdfDoc.context.trailerInfo.Root;
        if (!rootRef) throw new OfficerCertificateError("PDF root catalog is missing", "PADES_LT_INCREMENTAL_UPDATE_INVALID", 400);
        const originalSize = pdfDoc.context.largestObjectNumber + 1;
        const previousXref = lastStartXref(source);

        const certificateBuffers = deduplicateBuffers([
            readCertificateDer(resolveFromBackend(certificateRecord.certificate_path)),
            readCertificateDer(resolveFromBackend(certificateRecord.root_ca_certificate_path || PKI_ROOT_CA_CERT_PATH)),
            readCertificateDer(resolveFromBackend(PKI_OCSP_RESPONDER_CERT_PATH)),
            readCertificateDer(resolveFromBackend(PKI_TSA_CERT_PATH)),
        ]);
        const ocspBuffer = Buffer.from(ocspEvidence.response_der_base64, "base64");
        const crlBuffer = convertCrlToDer(resolveFromBackend(crlPath), temp);
        const vriKey = sha1(extracted.cmsDer);

        let nextObject = originalSize;
        const dssObject = nextObject++;
        const certificateObjects = certificateBuffers.map(() => nextObject++);
        const ocspObject = nextObject++;
        const crlObject = nextObject++;
        const vriObject = nextObject++;
        const objectDefinitions = [];

        const certRefs = certificateObjects.map((number) => `${number} 0 R`).join(" ");
        const dssDictionary = `<<\n/Type /${DSS_TYPE}\n/Certs [ ${certRefs} ]\n/OCSPs [ ${ocspObject} 0 R ]\n` +
            `/CRLs [ ${crlObject} 0 R ]\n/VRI << /${vriKey} ${vriObject} 0 R >>\n>>`;
        const vriDictionary = `<<\n/Type /VRI\n/Cert [ ${certRefs} ]\n/OCSP [ ${ocspObject} 0 R ]\n` +
            `/CRL [ ${crlObject} 0 R ]\n/TU (${pdfDate(embeddedAt)})\n>>`;
        const updatedCatalog = appendDssToCatalog(pdfDoc.catalog.toString(), `${dssObject} 0 R`);

        objectDefinitions.push({ number: rootRef.objectNumber, generation: rootRef.generationNumber, body: updatedCatalog });
        objectDefinitions.push({ number: dssObject, generation: 0, body: dssDictionary });
        certificateBuffers.forEach((buffer, index) => objectDefinitions.push({
            number: certificateObjects[index], generation: 0, body: buildStreamBody(buffer),
        }));
        objectDefinitions.push({ number: ocspObject, generation: 0, body: buildStreamBody(ocspBuffer) });
        objectDefinitions.push({ number: crlObject, generation: 0, body: buildStreamBody(crlBuffer) });
        objectDefinitions.push({ number: vriObject, generation: 0, body: vriDictionary });

        const chunks = [source, Buffer.from(source.at(-1) === 0x0a ? "" : "\n", "ascii")];
        let offset = chunks.reduce((total, chunk) => total + chunk.length, 0);
        const xrefEntries = [];
        for (const definition of objectDefinitions) {
            const objectBuffer = buildIndirectObject(definition.number, definition.generation, definition.body);
            xrefEntries.push({ number: definition.number, generation: definition.generation, offset });
            chunks.push(objectBuffer);
            offset += objectBuffer.length;
        }
        const xrefOffset = offset;
        const xref = buildXref(xrefEntries);
        const trailer = trailerText({
            size: nextObject,
            root: rootRef,
            info: pdfDoc.context.trailerInfo.Info,
            encrypt: pdfDoc.context.trailerInfo.Encrypt,
            id: pdfDoc.context.trailerInfo.ID,
            prev: previousXref,
        });
        chunks.push(Buffer.from(`${xref}${trailer}startxref\n${xrefOffset}\n%%EOF\n`, "latin1"));
        const output = Buffer.concat(chunks);
        fs.mkdirSync(path.dirname(outputPdfPath), { recursive: true });
        fs.writeFileSync(outputPdfPath, output);

        return {
            format: "PAdES",
            baseline_level: "PAdES-LT",
            dss_present: true,
            vri_present: true,
            vri_key_sha1: vriKey,
            embedded_certificate_count: certificateBuffers.length,
            embedded_ocsp_count: 1,
            embedded_crl_count: 1,
            incremental_update: true,
            signed_revision_length: source.length,
            final_pdf_length: output.length,
            dss_object_number: dssObject,
            vri_object_number: vriObject,
            evidence_sha256: {
                certificates: certificateBuffers.map(sha256),
                ocsp: sha256(ocspBuffer),
                crl: sha256(crlBuffer),
            },
        };
    } finally {
        fs.rmSync(temp, { recursive: true, force: true });
    }
}

export function verifyPadesLtEvidence({
    pdfBuffer,
    cmsDer,
    signedRevisionLength,
    expectedFingerprint = "",
    signatureTimestamp = null,
} = {}) {
    const source = Buffer.from(pdfBuffer || []);
    if (!source.length || !cmsDer || !signedRevisionLength) {
        return { valid: false, reason: "PADES_LT_INPUT_REQUIRED" };
    }
    if (source.length <= signedRevisionLength) {
        return { valid: false, reason: "PADES_DSS_MISSING", dss_present: false, vri_present: false };
    }
    try {
        const trailing = source.subarray(source.lastIndexOf(Buffer.from("%%EOF", "ascii")) + 5);
        if (trailing.toString("latin1").trim() !== "") {
            return { valid: false, reason: "PADES_LT_INCREMENTAL_UPDATE_INVALID" };
        }
        const originalRevision = source.subarray(0, signedRevisionLength);
        const originalXref = lastStartXref(originalRevision);
        const originalParsed = parseXrefAt(originalRevision, originalXref);
        const rootRef = {
            objectNumber: originalParsed.rootNumber,
            generationNumber: originalParsed.rootGeneration,
        };
        const originalSize = originalParsed.size;
        const originalRootEntry = originalParsed.entries.get(rootRef.objectNumber);
        if (!originalRootEntry) {
            return { valid: false, reason: "PADES_LT_INCREMENTAL_UPDATE_INVALID" };
        }
        const originalCatalogDictionary = readObjectAt(
            originalRevision,
            rootRef.objectNumber,
            originalRootEntry
        );
        const finalXrefOffset = lastStartXref(source);
        if (finalXrefOffset <= signedRevisionLength) {
            return { valid: false, reason: "PADES_LT_INCREMENTAL_UPDATE_INVALID" };
        }
        const parsed = parseXrefAt(source, finalXrefOffset);
        if (parsed.prev !== originalXref || parsed.rootNumber !== rootRef.objectNumber || parsed.rootGeneration !== rootRef.generationNumber) {
            return { valid: false, reason: "PADES_LT_INCREMENTAL_UPDATE_INVALID" };
        }
        const allowedNumbers = [...parsed.entries.keys()];
        if (!allowedNumbers.includes(rootRef.objectNumber) || allowedNumbers.some((number) => number < originalSize && number !== rootRef.objectNumber)) {
            return { valid: false, reason: "PADES_LT_INCREMENTAL_UPDATE_INVALID" };
        }
        const rootEntry = parsed.entries.get(rootRef.objectNumber);
        const rootDictionary = readObjectAt(source, rootRef.objectNumber, rootEntry);
        const dssMatch = rootDictionary.match(/\/DSS\s+(\d+)\s+(\d+)\s+R/);
        if (!dssMatch) return { valid: false, reason: "PADES_DSS_MISSING", dss_present: false, vri_present: false };
        const dssNumber = Number(dssMatch[1]);
        const dssEntry = parsed.entries.get(dssNumber);
        if (!dssEntry) return { valid: false, reason: "PADES_DSS_MISSING", dss_present: false, vri_present: false };

        const originalCatalog = normalizedDictionary(originalCatalogDictionary);
        const rootWithoutDss = normalizedDictionary(rootDictionary.replace(/\/DSS\s+\d+\s+\d+\s+R/, ""));
        if (rootWithoutDss !== originalCatalog) {
            return { valid: false, reason: "PADES_LT_INCREMENTAL_UPDATE_INVALID", dss_present: true, vri_present: false };
        }

        const dssDictionary = readObjectAt(source, dssNumber, dssEntry);
        if (!/\/Type\s+\/DSS/.test(dssDictionary)) return { valid: false, reason: "PADES_DSS_MISSING" };
        const certificateRefs = parseReferenceArray(dssDictionary, "Certs");
        const ocspRefs = parseReferenceArray(dssDictionary, "OCSPs");
        const crlRefs = parseReferenceArray(dssDictionary, "CRLs");
        if (!certificateRefs.length) return { valid: false, reason: "PADES_EMBEDDED_CERTIFICATE_MISSING", dss_present: true };
        if (!ocspRefs.length) return { valid: false, reason: "PADES_EMBEDDED_OCSP_INVALID", dss_present: true };
        if (!crlRefs.length) return { valid: false, reason: "PADES_EMBEDDED_CRL_INVALID", dss_present: true };

        const expectedVriKey = sha1(Buffer.from(cmsDer));
        const vriMatch = dssDictionary.match(new RegExp(`/VRI\\s*<<[\\s\\S]*?/${expectedVriKey}\\s+(\\d+)\\s+(\\d+)\\s+R[\\s\\S]*?>>`));
        if (!vriMatch) return { valid: false, reason: "PADES_VRI_BINDING_INVALID", dss_present: true, vri_present: false };
        const vriNumber = Number(vriMatch[1]);
        const vriEntry = parsed.entries.get(vriNumber);
        if (!vriEntry) return { valid: false, reason: "PADES_VRI_MISSING", dss_present: true, vri_present: false };
        const vriDictionary = readObjectAt(source, vriNumber, vriEntry);
        const vriCertificateRefs = parseReferenceArray(vriDictionary, "Cert");
        const vriOcspRefs = parseReferenceArray(vriDictionary, "OCSP");
        const vriCrlRefs = parseReferenceArray(vriDictionary, "CRL");
        const sameRefs = (left, right) => left.length === right.length && left.every((item, index) =>
            item.number === right[index].number && item.generation === right[index].generation);
        if (!sameRefs(vriCertificateRefs, certificateRefs) || !sameRefs(vriOcspRefs, ocspRefs) || !sameRefs(vriCrlRefs, crlRefs)) {
            return { valid: false, reason: "PADES_VRI_BINDING_INVALID", dss_present: true, vri_present: true };
        }

        const referenced = new Set([
            dssNumber, vriNumber,
            ...certificateRefs.map((item) => item.number),
            ...ocspRefs.map((item) => item.number),
            ...crlRefs.map((item) => item.number),
        ]);
        if (allowedNumbers.some((number) => number !== rootRef.objectNumber && !referenced.has(number))) {
            return { valid: false, reason: "PADES_LT_INCREMENTAL_UPDATE_INVALID", dss_present: true, vri_present: true };
        }

        const certificates = certificateRefs.map((reference) => {
            const entry = parsed.entries.get(reference.number);
            if (!entry) throw new OfficerCertificateError("Embedded certificate stream is missing", "PADES_EMBEDDED_CERTIFICATE_MISSING", 400);
            return readStreamAt(source, reference.number, entry);
        });
        const ocsp = readStreamAt(source, ocspRefs[0].number, parsed.entries.get(ocspRefs[0].number));
        const crl = readStreamAt(source, crlRefs[0].number, parsed.entries.get(crlRefs[0].number));
        const evidence = verifyEmbeddedEvidence({ certificates, ocsp, crl, expectedFingerprint, signatureTimestamp });
        if (!evidence.valid) return {
            ...evidence,
            dss_present: true,
            vri_present: true,
            vri_key_sha1: expectedVriKey,
        };
        return {
            valid: true,
            reason: "VALID_PADES_LT_EVIDENCE",
            dss_present: true,
            vri_present: true,
            vri_binding_valid: true,
            incremental_update_valid: true,
            vri_key_sha1: expectedVriKey,
            embedded_certificate_count: certificates.length,
            embedded_ocsp_count: ocspRefs.length,
            embedded_crl_count: crlRefs.length,
            offline_verification_ready: true,
            signed_revision_length: signedRevisionLength,
            final_pdf_length: source.length,
            evidence,
        };
    } catch (error) {
        return {
            valid: false,
            reason: error.code || "PADES_LT_INCREMENTAL_UPDATE_INVALID",
            error: error.message,
        };
    }
}
