import crypto from "node:crypto";

function secureEqualHex(leftValue, rightValue) {
    try {
        const left = Buffer.from(String(leftValue || ""), "hex");
        const right = Buffer.from(String(rightValue || ""), "hex");
        return left.length > 0 && left.length === right.length && crypto.timingSafeEqual(left, right);
    } catch {
        return false;
    }
}

export function createClientAgentSignature({ timestamp, nonce, rawBody, secret }) {
    return crypto.createHmac("sha256", secret)
        .update(`${timestamp}.${nonce}.${rawBody}`)
        .digest("hex");
}

export function verifyClientAgentAuthentication({
    headers = {},
    rawBody = "",
    expectedClientId = "portal-api",
    secret,
    allowedClockSkewSeconds = 300,
    usedNonces = [],
    nowMs = Date.now(),
} = {}) {
    const suppliedClient = String(headers["x-client-agent-client-id"] || "");
    const timestamp = String(headers["x-client-agent-timestamp"] || "");
    const nonce = String(headers["x-client-agent-nonce"] || "");
    const signature = String(headers["x-client-agent-signature"] || "");
    const parsedTimestamp = Number(timestamp);

    if (suppliedClient !== expectedClientId || !nonce || !Number.isFinite(parsedTimestamp)) {
        return { ok: false, status: 401, code: "CLIENT_AGENT_AUTH_INVALID", message: "Invalid client-agent authentication metadata" };
    }
    if (Math.abs(nowMs - parsedTimestamp) > allowedClockSkewSeconds * 1000) {
        return { ok: false, status: 401, code: "CLIENT_AGENT_REQUEST_EXPIRED", message: "Client-agent request timestamp is outside the allowed window" };
    }
    const expected = createClientAgentSignature({ timestamp, nonce, rawBody, secret });
    if (!secureEqualHex(signature, expected)) {
        return { ok: false, status: 401, code: "CLIENT_AGENT_AUTH_INVALID", message: "Invalid client-agent request signature" };
    }
    if (usedNonces.some((item) => item.nonce === nonce)) {
        return { ok: false, status: 409, code: "CLIENT_AGENT_REPLAY_DETECTED", message: "Client-agent nonce has already been used" };
    }
    return { ok: true, nonce, client_id: suppliedClient, used_at_ms: nowMs };
}

export function cleanupClientAgentNonces(nonces = [], nowMs = Date.now(), allowedClockSkewSeconds = 300) {
    const cutoff = nowMs - allowedClockSkewSeconds * 2 * 1000;
    return nonces.filter((item) => Number(item.used_at_ms) >= cutoff);
}
