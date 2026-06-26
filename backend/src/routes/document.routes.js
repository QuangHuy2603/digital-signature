
import express from "express";

import {
    downloadSignedDocument,
    downloadDocumentFile,
    getDocumentDetail,
    listDocumentDetails,
    listPendingDocuments,
    listIssuedDocuments,
    listRejectedDocuments,
    verifyDocumentByQr,
    verifyDocumentByUpload,
    previewDocument,
    downloadPreviewDocument,
    submitDocumentHandler,
    createSigningRequestHandler,
    signDocumentHandler,
    rejectDocumentHandler,
    listCitizenSigningCertificatesHandler,
    createCitizenSigningRequestHandler,
    citizenSignDocumentHandler,
    createRemoteSigningAuthorizationHandler,
    verifyRemoteSigningOtpHandler
} from "../controllers/document.controller.js";

import { authenticate, optionalAuthenticate } from "../middlewares/auth.middleware.js";
import { requireRole } from "../middlewares/role.middleware.js";

const router = express.Router();

// Public verification/download endpoints. Keep these before dynamic detail routes.
router.get("/verify/:documentId", verifyDocumentByQr);
router.post("/verify/:documentId", verifyDocumentByUpload);
router.get("/:documentId/signed-pdf", optionalAuthenticate, downloadSignedDocument);

// Citizen (authenticated)
router.get("/", authenticate, listDocumentDetails);
router.post("/preview", authenticate, previewDocument);
router.get("/previews/:previewId/file", authenticate, downloadPreviewDocument);
router.post("/submit", authenticate, requireRole("citizen"), submitDocumentHandler);
router.get("/citizen-signing/certificates", authenticate, requireRole("citizen"), listCitizenSigningCertificatesHandler);
router.post("/:documentId/citizen-signing-request", authenticate, requireRole("citizen"), createCitizenSigningRequestHandler);
router.post("/:documentId/citizen-sign", authenticate, requireRole("citizen"), citizenSignDocumentHandler);
router.get("/:documentId/download", authenticate, downloadDocumentFile);

// Officer (authenticated + role)
router.get("/pending", authenticate, requireRole("officer"), listPendingDocuments);
router.get("/issued", authenticate, requireRole("officer"), listIssuedDocuments);
router.get("/rejected", authenticate, requireRole("officer"), listRejectedDocuments);
router.post("/:documentId/signing-request", authenticate, requireRole("officer"), createSigningRequestHandler);
router.post("/:documentId/remote-signing-authorization", authenticate, requireRole("officer"), createRemoteSigningAuthorizationHandler);
router.post("/:documentId/remote-signing-authorization/verify", authenticate, requireRole("officer"), verifyRemoteSigningOtpHandler);
router.post("/:documentId/sign", authenticate, requireRole("officer"), signDocumentHandler);
router.post("/:documentId/reject", authenticate, requireRole("officer"), rejectDocumentHandler);

// Authenticated detail route must stay after fixed routes such as /pending.
router.get("/:documentId", authenticate, getDocumentDetail);


export default router;
