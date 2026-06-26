import path from "node:path";
import {
    atomicWriteJsonSync,
    readJsonFileSync,
} from "../utils/atomic-file.util.js";

const dataFilePath = path.resolve("src/data/certificates.json");

function readCertificates() {
    const certificates = readJsonFileSync(dataFilePath, []);
    if (!Array.isArray(certificates)) {
        throw new Error("certificates.json must contain a JSON array");
    }
    return certificates;
}

function writeCertificates(certificates) {
    atomicWriteJsonSync(dataFilePath, certificates, { backup: true });
}

export function listCertificates() {
    return readCertificates();
}

export function findCertificateById(certificateId) {
    return readCertificates().find(
        (certificate) => certificate.certificate_id === certificateId
    ) || null;
}


export function findCertificatesByCitizenId(citizenId) {
    return readCertificates().filter(
        (certificate) => String(certificate.citizen_id || "") === String(citizenId || "")
    );
}

export function findActiveCitizenCertificate(citizenId, provider = null) {
    return readCertificates().find((certificate) =>
        String(certificate.citizen_id || "") === String(citizenId || "") &&
        certificate.status === "active" &&
        (certificate.signer_type === "citizen" || certificate.purpose === "citizen-signing") &&
        (!provider || String(certificate.key_provider || certificate.provider || "software").toLowerCase() === String(provider).toLowerCase())
    ) || null;
}

export function findCertificatesByOfficerId(officerId) {
    return readCertificates().filter(
        (certificate) => certificate.officer_id === officerId
    );
}

export function findActiveCertificateByOfficerId(officerId) {
    return readCertificates().find(
        (certificate) =>
            certificate.officer_id === officerId &&
            certificate.status === "active"
    ) || null;
}

export function saveCertificate(certificate) {
    const certificates = readCertificates();
    if (certificates.some(
        (item) => item.certificate_id === certificate.certificate_id
    )) {
        throw new Error(
            `Certificate ${certificate.certificate_id} already exists`
        );
    }

    certificates.push(certificate);
    writeCertificates(certificates);
    return certificate;
}

export function updateCertificate(certificateId, patch) {
    const certificates = readCertificates();
    const index = certificates.findIndex(
        (certificate) => certificate.certificate_id === certificateId
    );

    if (index === -1) return null;

    certificates[index] = {
        ...certificates[index],
        ...patch,
    };

    writeCertificates(certificates);
    return certificates[index];
}

export function replaceCertificates(certificates) {
    if (!Array.isArray(certificates)) {
        throw new Error("certificates must be an array");
    }
    writeCertificates(certificates);
    return certificates;
}
