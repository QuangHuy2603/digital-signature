import express from "express";

import {
    verifyDocumentByQr,
    verifyDocumentByUpload
} from "../controllers/document.controller.js";
import { getNetworkModel } from "../controllers/network.controller.js";
import {
    getOfficerCertificateStatus,
    getOfficerCertificateByOfficerId,
    getOcspResponderInfo,
    getOcspResponseByCertificateId,
    getOcspResponseBySerial,
    getTsaServiceInfo,
    getPadesServiceInfo,
    getTspServiceInfo,
    getSigningProviderInfo,
    getArchiveServiceInfo,
    verifyArchiveById,
    getClientAgentServiceInfo,
} from "../controllers/pki.controller.js";

const router = express.Router();

router.get("/network-model", getNetworkModel);
router.get("/pki/officer-certificate", getOfficerCertificateStatus);
router.get("/pki/officers/:officerId", getOfficerCertificateByOfficerId);
router.get("/pki/ocsp", getOcspResponderInfo);
router.get("/pki/ocsp/certificate/:certificateId", getOcspResponseByCertificateId);
router.get("/pki/ocsp/serial/:serialNumber", getOcspResponseBySerial);
router.get("/pki/tsa", getTsaServiceInfo);
router.get("/pki/pades", getPadesServiceInfo);
router.get("/trust/tsp", getTspServiceInfo);
router.get("/trust/signing-provider", getSigningProviderInfo);
router.get("/archive", getArchiveServiceInfo);
router.get("/trust/client-agent", getClientAgentServiceInfo);
router.get("/archive/:archiveId/verify", verifyArchiveById);
router.get("/documents/verify/:documentId", verifyDocumentByQr);
router.post("/documents/verify/:documentId", verifyDocumentByUpload);

export default router;
