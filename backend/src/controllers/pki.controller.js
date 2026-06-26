import { getMultiOfficerPkiStatus } from "../crypto/officer-pki.service.js";
import {
    findActiveCertificateByOfficerId,
    findCertificatesByOfficerId,
} from "../services/certificate.repository.js";
import { findOfficerByOfficerId } from "../services/officer-account.service.js";
import {
    loadOfficerCertificateIdentity,
    OfficerCertificateError,
} from "../crypto/x509-pki.service.js";
import { checkCertificateRevocation } from "../crypto/crl.service.js";

export const getOfficerCertificateStatus = async (_req, res) => {
    try {
        const result = getMultiOfficerPkiStatus();
        res.status(200).json({
            message: "NT219 multi-officer Test PKI and CRL status",
            ...result,
            lab_only: true,
            note: "These are test certificates for the NT219 PoC, not production or qualified certificates.",
        });
    } catch (error) {
        res.status(500).json({
            status: "error",
            code: error.code || "PKI_STATUS_ERROR",
            message: error.message,
            lab_only: true,
        });
    }
};

export const getOfficerCertificateByOfficerId = async (req, res) => {
    try {
        const officerId = String(req.params.officerId || "").trim().toUpperCase();
        const officer = findOfficerByOfficerId(officerId);
        if (!officer) {
            return res.status(404).json({
                code: "OFFICER_NOT_FOUND",
                message: "Officer account not found",
            });
        }

        const certificates = findCertificatesByOfficerId(officerId)
            .sort((a, b) => Number(b.version || 0) - Number(a.version || 0));
        const active = findActiveCertificateByOfficerId(officerId);
        const record = active || certificates[0] || null;
        if (!record) {
            return res.status(404).json({
                code: "OFFICER_CERTIFICATE_NOT_ASSIGNED",
                message: "Officer does not have a certificate",
            });
        }

        const identity = loadOfficerCertificateIdentity({
            officerCertPath: record.certificate_path,
            rootCertPath: record.root_ca_certificate_path,
            expectedFingerprint: record.fingerprint_sha256,
            expectedOfficerId: officerId,
            expectedEmail: officer.email,
        });
        const revocation = checkCertificateRevocation({
            certificateRecord: record,
            serialNumber: identity.metadata.serial_number,
        });

        return res.status(200).json({
            status: active ? "ready" : record.status,
            officer: {
                user_id: officer.id,
                officer_id: officer.officer_id,
                full_name: officer.full_name,
                email: officer.email,
                active_certificate_id: officer.active_certificate_id || null,
                certificate_status: officer.certificate_status || null,
            },
            certificate: {
                certificate_id: record.certificate_id,
                status: record.status,
                revoked_at: record.revoked_at || null,
                revocation_reason: record.revocation_reason || null,
                ...identity.metadata,
            },
            revocation: {
                checked: revocation.checked,
                trusted: revocation.trusted,
                revoked: revocation.revoked,
                reason: revocation.reason,
                crl_signature_valid: revocation.crl?.signature_valid || false,
                crl_number: revocation.crl?.crl_number ?? null,
                crl_last_update: revocation.crl?.last_update || null,
                crl_next_update: revocation.crl?.next_update || null,
            },
            certificate_history: certificates.map((item) => ({
                certificate_id: item.certificate_id,
                version: item.version,
                status: item.status,
                serial_number: item.serial_number,
                valid_from: item.valid_from,
                valid_to: item.valid_to,
                revoked_at: item.revoked_at || null,
                revocation_reason: item.revocation_reason || null,
                superseded_by_certificate_id:
                    item.superseded_by_certificate_id ||
                    item.replaced_by_certificate_id ||
                    null,
            })),
            lab_only: true,
        });
    } catch (error) {
        const status = error instanceof OfficerCertificateError
            ? error.status
            : 500;
        return res.status(status).json({
            status: "error",
            code: error.code || "PKI_STATUS_ERROR",
            message: error.message,
            lab_only: true,
        });
    }
};

import {
    generateOcspResponse,
    getOcspResponderStatus,
} from "../crypto/ocsp.service.js";
import { getTsaStatus } from "../crypto/tsa.service.js";
import { getPadesStatus } from "../crypto/pades.service.js";
import { findCertificateById } from "../services/certificate.repository.js";

export const getOcspResponderInfo = async (_req, res) => {
    try {
        res.status(200).json({
            status: "ready",
            ...getOcspResponderStatus(),
        });
    } catch (error) {
        res.status(error.status || 500).json({
            status: "error",
            code: error.code || "OCSP_STATUS_ERROR",
            message: error.message,
        });
    }
};

export const getOcspResponseByCertificateId = async (req, res) => {
    try {
        const certificateId = String(req.params.certificateId || "").trim();
        const record = findCertificateById(certificateId);
        if (!record) {
            return res.status(404).json({
                code: "CERTIFICATE_NOT_FOUND",
                message: "Certificate not found",
            });
        }
        const response = generateOcspResponse({
            serialNumber: record.serial_number,
            certificateId: record.certificate_id,
            includeDer: true,
        });
        if (String(req.query.format || "").toLowerCase() === "der") {
            res.setHeader("Content-Type", "application/ocsp-response");
            res.setHeader("Content-Disposition", `inline; filename="${record.certificate_id}.ocsp.der"`);
            return res.send(Buffer.from(response.response_der_base64, "base64"));
        }
        return res.status(200).json({
            message: "RFC 6960 OCSP response generated by NT219 Test OCSP Responder",
            ...response,
            lab_only: true,
        });
    } catch (error) {
        return res.status(error.status || 500).json({
            code: error.code || "OCSP_RESPONSE_ERROR",
            message: error.message,
        });
    }
};

export const getOcspResponseBySerial = async (req, res) => {
    try {
        const serialNumber = String(req.params.serialNumber || "").trim();
        const response = generateOcspResponse({ serialNumber, includeDer: true });
        return res.status(200).json({
            message: "RFC 6960 OCSP response generated by serial number",
            ...response,
            lab_only: true,
        });
    } catch (error) {
        return res.status(error.status || 500).json({
            code: error.code || "OCSP_RESPONSE_ERROR",
            message: error.message,
        });
    }
};

export const getTsaServiceInfo = async (_req, res) => {
    try {
        res.status(200).json({
            status: "ready",
            ...getTsaStatus(),
        });
    } catch (error) {
        res.status(error.status || 500).json({
            status: "error",
            code: error.code || "TSA_STATUS_ERROR",
            message: error.message,
        });
    }
};

export const getPadesServiceInfo = async (_req, res) => {
    try {
        res.status(200).json({ status: "ready", ...getPadesStatus() });
    } catch (error) {
        res.status(error.status || 500).json({
            status: "error",
            code: error.code || "PADES_STATUS_ERROR",
            message: error.message,
        });
    }
};

import { getTspClientStatus } from "../services/tsp-client.service.js";
import { getSigningProviderStatus } from "../crypto/signing-provider.service.js";
import { getArchiveStatus, listArchives, verifyLtvArchive } from "../services/archive.service.js";
import { getClientAgentClientStatus } from "../services/client-agent-client.service.js";

export const getTspServiceInfo = async (_req, res) => {
    try { res.status(200).json({ status: "ready", ...getTspClientStatus() }); }
    catch (error) { res.status(500).json({ status: "error", code: error.code || "TSP_STATUS_ERROR", message: error.message }); }
};

export const getSigningProviderInfo = async (_req, res) => {
    try { res.status(200).json({ status: "ready", ...getSigningProviderStatus() }); }
    catch (error) { res.status(500).json({ status: "error", code: error.code || "SIGNING_PROVIDER_STATUS_ERROR", message: error.message }); }
};

export const getArchiveServiceInfo = async (_req, res) => {
    try { res.status(200).json({ status: "ready", ...getArchiveStatus(), archives: listArchives() }); }
    catch (error) { res.status(500).json({ status: "error", code: error.code || "ARCHIVE_STATUS_ERROR", message: error.message }); }
};

export const verifyArchiveById = async (req, res) => {
    const result = verifyLtvArchive(req.params.archiveId);
    res.status(result.valid ? 200 : 422).json(result);
};

export const getClientAgentServiceInfo = async (_req, res) => {
    try {
        const client = getClientAgentClientStatus();
        let agent = null;
        try {
            const response = await fetch(`${client.endpoint}/health`);
            agent = await response.json();
        } catch (error) {
            agent = { ready: false, code: "CLIENT_AGENT_UNAVAILABLE", message: error.message };
        }
        res.status(200).json({ status: agent?.ready ? "ready" : "unavailable", ...client, agent });
    } catch (error) {
        res.status(500).json({ status: "error", code: error.code || "CLIENT_AGENT_STATUS_ERROR", message: error.message });
    }
};
