import { listCertificates } from "../services/certificate.repository.js";
import { getUserById } from "../services/auth.service.js";
import { certificateLifecycleManager, CertificateLifecycleError } from "../services/certificate-admin.service.js";

function sendError(res, error) {
    const status = error instanceof CertificateLifecycleError ? error.status : 500;
    res.status(status).json({ message: error.message, code: error.code || "CERTIFICATE_LIFECYCLE_ERROR" });
}

export async function listMyCertificatesHandler(req, res) {
    try {
        const currentUser = await getUserById(req.user.id);
        if (!currentUser) {
            return res.status(404).json({ message: "User not found", code: "USER_NOT_FOUND" });
        }

        const roles = Array.isArray(currentUser.roles) ? currentUser.roles : [];
        const role = roles.includes("officer")
            ? "officer"
            : roles.includes("citizen")
                ? "citizen"
                : null;

        if (!role) {
            return res.status(403).json({
                message: "Citizen or officer role is required",
                code: "CERTIFICATE_ROLE_REQUIRED",
            });
        }

        const subjectId = role === "officer"
            ? currentUser.officer_id
            : currentUser.citizen_id;

        if (!subjectId) {
            return res.status(409).json({
                message: "Certificate subject ID is missing",
                code: "CERTIFICATE_SUBJECT_ID_MISSING",
            });
        }

        const data = listCertificates().filter((item) => {
            const ownerMatches = role === "officer"
                ? String(item.officer_id || "") === String(subjectId)
                : String(item.citizen_id || "") === String(subjectId);
            const userMatches = item.user_id == null || String(item.user_id) === String(currentUser.id);
            return ownerMatches && userMatches;
        });

        return res.json({ data });
    } catch (error) {
        return sendError(res, error);
    }
}

export function listMyCertificateRequestsHandler(req, res) {
    res.json({ data: certificateLifecycleManager.listForUser(req.user) });
}

export async function createCertificateRequestHandler(req, res) {
    try {
        const data = await certificateLifecycleManager.create({
            user: req.user,
            requestType: req.body.request_type,
            certificateRole: req.body.certificate_role,
            provider: req.body.provider,
            targetCertificateId: req.body.target_certificate_id,
            csrPem: req.body.csr_pem,
            publicKeyPem: req.body.public_key_pem,
            revocationReason: req.body.revocation_reason,
        });
        res.status(201).json({ message: "Certificate request created", data });
    } catch (error) { sendError(res, error); }
}

export function adminOverviewHandler(req, res) {
    try { res.json({ data: certificateLifecycleManager.getOverview(req.user) }); }
    catch (error) { sendError(res, error); }
}

export function adminListRequestsHandler(req, res) {
    try { res.json({ data: certificateLifecycleManager.listAll(req.user) }); }
    catch (error) { sendError(res, error); }
}

export function adminListCertificatesHandler(_req, res) {
    res.json({ data: listCertificates() });
}

export function adminListEventsHandler(req, res) {
    try { res.json({ data: certificateLifecycleManager.listEvents(req.user) }); }
    catch (error) { sendError(res, error); }
}

export async function adminApproveRequestHandler(req, res) {
    try { res.json({ message: "Certificate request approved", data: await certificateLifecycleManager.approve({ admin: req.user, requestId: req.params.requestId }) }); }
    catch (error) { sendError(res, error); }
}

export async function adminRejectRequestHandler(req, res) {
    try { res.json({ message: "Certificate request rejected", data: await certificateLifecycleManager.reject({ admin: req.user, requestId: req.params.requestId, reason: req.body.reason }) }); }
    catch (error) { sendError(res, error); }
}

export async function adminIssueRequestHandler(req, res) {
    try { res.json({ message: "Certificate lifecycle action completed", data: await certificateLifecycleManager.issue({ admin: req.user, requestId: req.params.requestId }) }); }
    catch (error) { sendError(res, error); }
}

export async function adminDirectRevokeCertificateHandler(req, res) {
    try {
        const data = await certificateLifecycleManager.revokeDirect({
            admin: req.user,
            certificateId: req.params.certificateId,
            reason: req.body.reason,
            confirmation: req.body.confirmation,
        });
        return res.json({ message: "Certificate revoked directly by administrator", data });
    } catch (error) {
        return sendError(res, error);
    }
}
