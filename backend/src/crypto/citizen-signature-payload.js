export function buildCitizenSignaturePayload({
    requestId,
    documentId,
    citizenId,
    userId,
    certificateId,
    documentDigestSha256,
    createdAt,
} = {}) {
    const digest = String(documentDigestSha256 || "").replace(/[^0-9a-f]/gi, "").toUpperCase();
    if (!requestId || !documentId || !citizenId || !userId || !certificateId || digest.length !== 64) {
        const error = new Error("Citizen signature payload is incomplete");
        error.code = "CITIZEN_SIGNATURE_PAYLOAD_INVALID";
        error.status = 400;
        throw error;
    }
    return [
        "NT219-CITIZEN-SIGNATURE-V1",
        `request_id=${requestId}`,
        `document_id=${documentId}`,
        `citizen_id=${citizenId}`,
        `user_id=${userId}`,
        `certificate_id=${certificateId}`,
        "digest_algorithm=SHA-256",
        `document_digest_sha256=${digest}`,
        `created_at=${createdAt || ""}`,
    ].join("\n");
}
