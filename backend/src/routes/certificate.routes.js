import express from "express";
import { authenticate } from "../middlewares/auth.middleware.js";
import { requireRole } from "../middlewares/role.middleware.js";
import {
    listMyCertificatesHandler,
    listMyCertificateRequestsHandler,
    createCertificateRequestHandler,
    adminOverviewHandler,
    adminListRequestsHandler,
    adminListCertificatesHandler,
    adminListEventsHandler,
    adminApproveRequestHandler,
    adminRejectRequestHandler,
    adminIssueRequestHandler,
    adminDirectRevokeCertificateHandler,
} from "../controllers/certificate-admin.controller.js";

const router = express.Router();
router.use(authenticate);
router.get("/me", requireRole("citizen", "officer"), listMyCertificatesHandler);
router.get("/requests/my", requireRole("citizen", "officer"), listMyCertificateRequestsHandler);
router.post("/requests", requireRole("citizen", "officer"), createCertificateRequestHandler);
router.get("/admin/overview", requireRole("admin"), adminOverviewHandler);
router.get("/admin/requests", requireRole("admin"), adminListRequestsHandler);
router.get("/admin/certificates", requireRole("admin"), adminListCertificatesHandler);
router.get("/admin/events", requireRole("admin"), adminListEventsHandler);
router.post("/admin/requests/:requestId/approve", requireRole("admin"), adminApproveRequestHandler);
router.post("/admin/requests/:requestId/reject", requireRole("admin"), adminRejectRequestHandler);
router.post("/admin/requests/:requestId/issue", requireRole("admin"), adminIssueRequestHandler);
router.post("/admin/certificates/:certificateId/revoke", requireRole("admin"), adminDirectRevokeCertificateHandler);
export default router;
