import path from "node:path";
import {
    atomicWriteJsonSync,
    readJsonFileSync,
} from "../utils/atomic-file.util.js";

const jsonFilePath = path.resolve("src/data/audit_logs.json");

function readLogs() {
    const logs = readJsonFileSync(jsonFilePath, []);
    if (!Array.isArray(logs)) {
        throw new Error("audit_logs.json must contain a JSON array");
    }
    return logs;
}

const VALID_ACTIONS = new Set([
    "submit", "sign", "verify", "download", "login", "logout", "key_access", "reject",
    "SIGNING_REQUEST_CREATED", "SIGNING_REQUEST_USED", "SIGNING_REQUEST_FAILED",
    "SIGNING_REQUEST_FORBIDDEN", "SIGNING_REPLAY_BLOCKED", "SIGNING_NONCE_INVALID",
    "SIGNING_REQUEST_EXPIRED", "DOCUMENT_HASH_CHANGED", "OFFICER_CERTIFICATE_VALIDATED",
    "OFFICER_CERTIFICATE_REJECTED", "CERTIFICATE_ISSUED", "CERTIFICATE_RENEWED",
    "CERTIFICATE_REVOKED", "CRL_GENERATED", "CRL_VERIFIED",
    "REVOKED_CERTIFICATE_SIGNING_BLOCKED", "CERTIFICATE_STATUS_CHECKED",
    "CERTIFICATE_REQUEST_CREATED", "CERTIFICATE_REQUEST_APPROVED",
    "CERTIFICATE_REQUEST_REJECTED", "CERTIFICATE_REQUEST_REVOKED",
    "ADMIN_DIRECT_CERTIFICATE_REVOKED",
]);

export async function writeAuditLog({
    action,
    documentId = null,
    result,
    userId = null,
    ipAddress = null,
    requestId = null,
    details = null,
}) {
    const entry = {
        user_id: userId,
        action: VALID_ACTIONS.has(action) ? action : "key_access",
        document_id: documentId,
        ip_address: ipAddress,
        request_id: requestId,
        result,
        details,
        created_at: new Date().toISOString(),
    };

    try {
        const logs = readLogs();
        logs.push(entry);
        atomicWriteJsonSync(jsonFilePath, logs, { backup: true });
        return entry;
    } catch (error) {
        console.warn("[audit] Failed to write audit log:", error.message);
        return null;
    }
}

export async function listAuditLogs() {
    return readLogs();
}

export async function logKeyAccess({ userId, ipAddress, result }) {
    return writeAuditLog({
        action: "key_access",
        documentId: null,
        result,
        userId,
        ipAddress,
    });
}
