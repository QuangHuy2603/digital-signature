import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { atomicWriteJsonSync, readJsonFileSync } from "../../backend/src/utils/atomic-file.util.js";
import { executeCitizenDigestSigningJob, executeClientAgentSigningJob, getClientAgentStatus, listClientAgentCertificates } from "./agent-core.js";
import { cleanupClientAgentNonces, verifyClientAgentAuthentication } from "./security.js";

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
process.env.SIGNING_PROVIDER = "file";

const host = process.env.CLIENT_AGENT_HOST || "127.0.0.1";
const port = Number(process.env.CLIENT_AGENT_PORT || 3500);
const expectedClientId = process.env.CLIENT_AGENT_CLIENT_ID || "portal-api";
const sharedSecret = process.env.CLIENT_AGENT_SHARED_SECRET || "nt219-demo-client-agent-secret-2026-change-me";
const allowedClockSkewSeconds = Number(process.env.CLIENT_AGENT_ALLOWED_CLOCK_SKEW_SECONDS || 300);
const allowedOrigins = String(process.env.CLIENT_AGENT_ALLOWED_ORIGINS || "http://localhost:3000,http://127.0.0.1:3000")
    .split(",").map((item) => item.trim()).filter(Boolean);
const storageRoot = path.join(projectRoot, "client-agent/storage");
const jobsFile = path.join(storageRoot, "jobs.json");
const noncesFile = path.join(storageRoot, "nonces.json");
fs.mkdirSync(storageRoot, { recursive: true });

function corsHeaders(req) {
    const origin = String(req.headers.origin || "");
    if (origin && allowedOrigins.includes(origin)) {
        return {
            "access-control-allow-origin": origin,
            "access-control-allow-methods": "GET,POST,OPTIONS",
            "access-control-allow-headers": "content-type,x-client-agent-client-id,x-client-agent-timestamp,x-client-agent-nonce,x-client-agent-signature",
            "access-control-max-age": "600",
            vary: "Origin",
        };
    }
    return {};
}

function sendJson(req, res, status, payload) {
    const body = Buffer.from(JSON.stringify(payload));
    res.writeHead(status, {
        ...corsHeaders(req),
        "content-type": "application/json; charset=utf-8",
        "content-length": body.length,
    });
    res.end(body);
}

async function readBody(req, maxBytes = 25 * 1024 * 1024) {
    const chunks = [];
    let total = 0;
    for await (const chunk of req) {
        total += chunk.length;
        if (total > maxBytes) {
            const error = new Error("Client-agent request body too large");
            error.status = 413;
            error.code = "CLIENT_AGENT_BODY_TOO_LARGE";
            throw error;
        }
        chunks.push(chunk);
    }
    return Buffer.concat(chunks).toString("utf8");
}

function browserOriginAllowed(req) {
    const origin = String(req.headers.origin || "");
    return !origin || allowedOrigins.includes(origin);
}

const server = http.createServer(async (req, res) => {
    try {
        if (req.method === "OPTIONS") {
            if (!browserOriginAllowed(req)) return sendJson(req, res, 403, { code: "CLIENT_AGENT_ORIGIN_NOT_ALLOWED", message: "Origin is not allowed" });
            res.writeHead(204, corsHeaders(req));
            return res.end();
        }
        const url = new URL(req.url, `http://${req.headers.host || `${host}:${port}`}`);
        if (req.method === "GET" && url.pathname === "/health") {
            if (!browserOriginAllowed(req)) return sendJson(req, res, 403, { code: "CLIENT_AGENT_ORIGIN_NOT_ALLOWED", message: "Origin is not allowed" });
            return sendJson(req, res, 200, { status: "ready", ...getClientAgentStatus(), time: new Date().toISOString() });
        }
        if (req.method === "GET" && url.pathname === "/v1/providers/status") {
            if (!browserOriginAllowed(req)) return sendJson(req, res, 403, { code: "CLIENT_AGENT_ORIGIN_NOT_ALLOWED", message: "Origin is not allowed" });
            return sendJson(req, res, 200, getClientAgentStatus());
        }
        if (req.method === "GET" && url.pathname === "/v1/certificates") {
            if (!browserOriginAllowed(req)) return sendJson(req, res, 403, { code: "CLIENT_AGENT_ORIGIN_NOT_ALLOWED", message: "Origin is not allowed" });
            return sendJson(req, res, 200, {
                certificates: listClientAgentCertificates({
                    signerType: url.searchParams.get("signer_type") || null,
                    userId: url.searchParams.get("user_id") || null,
                }),
            });
        }
        const signingRoutes = new Set(["/v1/sign/pades-bt", "/v1/sign/digest"]);
        if (req.method !== "POST" || !signingRoutes.has(url.pathname)) {
            return sendJson(req, res, 404, { code: "NOT_FOUND", message: "Route not found" });
        }

        const rawBody = await readBody(req);
        let nonces = cleanupClientAgentNonces(readJsonFileSync(noncesFile, []), Date.now(), allowedClockSkewSeconds);
        const auth = verifyClientAgentAuthentication({
            headers: req.headers,
            rawBody,
            expectedClientId,
            secret: sharedSecret,
            allowedClockSkewSeconds,
            usedNonces: nonces,
        });
        if (!auth.ok) return sendJson(req, res, auth.status, { code: auth.code, message: auth.message });
        nonces.push({ nonce: auth.nonce, client_id: auth.client_id, used_at_ms: auth.used_at_ms });
        atomicWriteJsonSync(noncesFile, nonces, { backup: false });

        let payload;
        try { payload = JSON.parse(rawBody || "{}"); }
        catch { return sendJson(req, res, 400, { code: "CLIENT_AGENT_JSON_INVALID", message: "Invalid JSON body" }); }
        const requestId = String(payload.request_id || "");
        if (!requestId) return sendJson(req, res, 400, { code: "CLIENT_AGENT_REQUEST_ID_REQUIRED", message: "request_id is required" });

        const jobs = readJsonFileSync(jobsFile, []);
        const existing = jobs.find((item) => item.request_id === requestId);
        if (existing?.status === "signed" && existing.response) {
            return sendJson(req, res, 200, { ...existing.response, idempotent_replay: true });
        }
        if (existing?.status === "processing") {
            return sendJson(req, res, 409, { code: "CLIENT_AGENT_REQUEST_IN_PROGRESS", message: "Request is already being processed" });
        }
        jobs.push({ request_id: requestId, status: "processing", created_at: new Date().toISOString() });
        atomicWriteJsonSync(jobsFile, jobs, { backup: false });
        try {
            const response = url.pathname === "/v1/sign/digest"
                ? await executeCitizenDigestSigningJob(payload)
                : await executeClientAgentSigningJob(payload);
            const latest = readJsonFileSync(jobsFile, []);
            const index = latest.findIndex((item) => item.request_id === requestId);
            latest[index] = { request_id: requestId, status: "signed", completed_at: new Date().toISOString(), response };
            atomicWriteJsonSync(jobsFile, latest, { backup: false });
            return sendJson(req, res, 201, response);
        } catch (error) {
            const latest = readJsonFileSync(jobsFile, []);
            const index = latest.findIndex((item) => item.request_id === requestId);
            if (index >= 0) latest[index] = { request_id: requestId, status: "failed", failed_at: new Date().toISOString(), code: error.code || "CLIENT_AGENT_SIGNING_FAILED" };
            atomicWriteJsonSync(jobsFile, latest, { backup: false });
            return sendJson(req, res, error.status || 500, { code: error.code || "CLIENT_AGENT_SIGNING_FAILED", message: error.message });
        }
    } catch (error) {
        return sendJson(req, res, error.status || 500, { code: error.code || "CLIENT_AGENT_INTERNAL_ERROR", message: error.message });
    }
});
server.listen(port, host, () => console.log(`Client Agent running on http://${host}:${port} (software + PKCS#11 providers)`));
