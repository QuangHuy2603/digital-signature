import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "../..");
const backendRoot = path.join(projectRoot, "backend");

function loadEnvFile(filePath) {
    if (!fs.existsSync(filePath)) return;
    for (const line of fs.readFileSync(filePath, "utf8").split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const index = trimmed.indexOf("=");
        if (index < 1) continue;
        const key = trimmed.slice(0, index).trim();
        let value = trimmed.slice(index + 1).trim();
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
        if (process.env[key] === undefined) process.env[key] = value;
    }
}
loadEnvFile(path.join(backendRoot, ".env"));
process.chdir(backendRoot);

const { executeTspSigningJob } = await import("../../backend/src/services/tsp-signing.service.js");
const { atomicWriteJsonSync, readJsonFileSync } = await import("../../backend/src/utils/atomic-file.util.js");
const { getSigningProviderStatus } = await import("../../backend/src/crypto/signing-provider.service.js");

const port = Number(process.env.TSP_PORT || 3400);
const host = process.env.TSP_HOST || "127.0.0.1";
const clientId = process.env.TSP_CLIENT_ID || "portal-api";
const sharedSecret = process.env.TSP_SHARED_SECRET || "nt219-demo-tsp-secret-2026-change-me";
const allowedSkew = Number(process.env.TSP_ALLOWED_CLOCK_SKEW_SECONDS || 300);
const storageRoot = path.resolve(projectRoot, process.env.TSP_STORAGE_PATH || "tsp-service/storage");
const jobsFile = path.join(storageRoot, "jobs.json");
const noncesFile = path.join(storageRoot, "nonces.json");
fs.mkdirSync(storageRoot, { recursive: true });

function sendJson(res, status, payload) {
    const body = Buffer.from(JSON.stringify(payload));
    res.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": body.length });
    res.end(body);
}
function secureEqual(a, b) {
    try {
        const left = Buffer.from(String(a || ""), "hex");
        const right = Buffer.from(String(b || ""), "hex");
        return left.length > 0 && left.length === right.length && crypto.timingSafeEqual(left, right);
    } catch { return false; }
}
function expectedSignature(timestamp, nonce, rawBody) {
    return crypto.createHmac("sha256", sharedSecret).update(`${timestamp}.${nonce}.${rawBody}`).digest("hex");
}
function cleanupNonces(nonces, now) {
    const cutoff = now - (allowedSkew * 2 * 1000);
    return nonces.filter((item) => Number(item.used_at_ms) >= cutoff);
}
function authenticate(headers, rawBody) {
    const suppliedClient = String(headers["x-tsp-client-id"] || "");
    const timestamp = String(headers["x-tsp-timestamp"] || "");
    const nonce = String(headers["x-tsp-nonce"] || "");
    const signature = String(headers["x-tsp-signature"] || "");
    const parsed = Number(timestamp);
    const now = Date.now();
    if (suppliedClient !== clientId || !nonce || !Number.isFinite(parsed) || Math.abs(now - parsed) > allowedSkew * 1000) {
        return { ok: false, status: 401, code: "TSP_AUTH_INVALID", message: "Invalid TSP authentication metadata" };
    }
    if (!secureEqual(signature, expectedSignature(timestamp, nonce, rawBody))) {
        return { ok: false, status: 401, code: "TSP_AUTH_INVALID", message: "Invalid TSP request signature" };
    }
    let nonces = cleanupNonces(readJsonFileSync(noncesFile, []), now);
    if (nonces.some((item) => item.nonce === nonce)) {
        return { ok: false, status: 409, code: "TSP_REPLAY_DETECTED", message: "TSP nonce has already been used" };
    }
    nonces.push({ nonce, used_at_ms: now, client_id: suppliedClient });
    atomicWriteJsonSync(noncesFile, nonces, { backup: false });
    return { ok: true };
}
async function readBody(req, maxBytes = 25 * 1024 * 1024) {
    const chunks = [];
    let total = 0;
    for await (const chunk of req) {
        total += chunk.length;
        if (total > maxBytes) throw Object.assign(new Error("Request body too large"), { status: 413, code: "TSP_BODY_TOO_LARGE" });
        chunks.push(chunk);
    }
    return Buffer.concat(chunks).toString("utf8");
}

const server = http.createServer(async (req, res) => {
    try {
        const url = new URL(req.url, `http://${req.headers.host || `${host}:${port}`}`);
        if (req.method === "GET" && url.pathname === "/health") {
            return sendJson(res, 200, { status: "ready", service: "nt219-tsp-service", version: "1.0.0", provider: getSigningProviderStatus(), time: new Date().toISOString() });
        }
        if (req.method === "GET" && url.pathname === "/v1/providers/status") {
            return sendJson(res, 200, getSigningProviderStatus());
        }
        if (req.method !== "POST" || url.pathname !== "/v1/sign/pades-bt") {
            return sendJson(res, 404, { code: "NOT_FOUND", message: "Route not found" });
        }
        const rawBody = await readBody(req);
        const auth = authenticate(req.headers, rawBody);
        if (!auth.ok) return sendJson(res, auth.status, { code: auth.code, message: auth.message });
        let payload;
        try { payload = JSON.parse(rawBody || "{}"); }
        catch { return sendJson(res, 400, { code: "TSP_JSON_INVALID", message: "Invalid JSON body" }); }
        const requestId = String(payload.request_id || "");
        if (!requestId) return sendJson(res, 400, { code: "TSP_REQUEST_ID_REQUIRED", message: "request_id is required" });
        const jobs = readJsonFileSync(jobsFile, []);
        const existing = jobs.find((item) => item.request_id === requestId);
        if (existing?.status === "signed" && existing.response) return sendJson(res, 200, { ...existing.response, idempotent_replay: true });
        if (existing?.status === "processing") return sendJson(res, 409, { code: "TSP_REQUEST_IN_PROGRESS", message: "Request is already being processed" });
        jobs.push({ request_id: requestId, status: "processing", created_at: new Date().toISOString() });
        atomicWriteJsonSync(jobsFile, jobs, { backup: false });
        try {
            const response = await executeTspSigningJob(payload);
            const latest = readJsonFileSync(jobsFile, []);
            const index = latest.findIndex((item) => item.request_id === requestId);
            latest[index] = { request_id: requestId, status: "signed", completed_at: new Date().toISOString(), response };
            atomicWriteJsonSync(jobsFile, latest, { backup: false });
            return sendJson(res, 201, response);
        } catch (error) {
            const latest = readJsonFileSync(jobsFile, []);
            const index = latest.findIndex((item) => item.request_id === requestId);
            if (index >= 0) latest[index] = { request_id: requestId, status: "failed", failed_at: new Date().toISOString(), code: error.code || "TSP_SIGNING_FAILED" };
            atomicWriteJsonSync(jobsFile, latest, { backup: false });
            return sendJson(res, error.status || 500, { code: error.code || "TSP_SIGNING_FAILED", message: error.message });
        }
    } catch (error) {
        return sendJson(res, error.status || 500, { code: error.code || "TSP_INTERNAL_ERROR", message: error.message });
    }
});
server.listen(port, host, () => console.log(`TSP service running on http://${host}:${port}`));
