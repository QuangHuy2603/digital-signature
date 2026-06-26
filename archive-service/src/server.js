import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "../..");
const backendRoot = path.join(projectRoot, "backend");
function loadEnv(filePath) {
    if (!fs.existsSync(filePath)) return;
    for (const line of fs.readFileSync(filePath, "utf8").split(/\r?\n/)) {
        const value = line.trim(); if (!value || value.startsWith("#")) continue;
        const index = value.indexOf("="); if (index < 1) continue;
        const key = value.slice(0, index).trim(); let item = value.slice(index + 1).trim();
        if ((item.startsWith('"') && item.endsWith('"')) || (item.startsWith("'") && item.endsWith("'"))) item = item.slice(1, -1);
        if (process.env[key] === undefined) process.env[key] = item;
    }
}
loadEnv(path.join(backendRoot, ".env"));
process.chdir(backendRoot);
const { getArchiveStatus, listArchives, verifyLtvArchive } = await import("../../backend/src/services/archive.service.js");
const port = Number(process.env.ARCHIVE_SERVICE_PORT || 3600);
const host = process.env.ARCHIVE_SERVICE_HOST || "127.0.0.1";
function sendJson(res, status, payload) { const body = Buffer.from(JSON.stringify(payload)); res.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": body.length }); res.end(body); }
const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || `${host}:${port}`}`);
    if (req.method === "GET" && url.pathname === "/health") return sendJson(res, 200, { status: "ready", ...getArchiveStatus() });
    if (req.method === "GET" && url.pathname === "/v1/archives") return sendJson(res, 200, { archives: listArchives() });
    const match = url.pathname.match(/^\/v1\/archives\/([^/]+)\/verify$/);
    if (req.method === "GET" && match) { const result = verifyLtvArchive(decodeURIComponent(match[1])); return sendJson(res, result.valid ? 200 : 422, result); }
    return sendJson(res, 404, { code: "NOT_FOUND", message: "Route not found" });
});
server.listen(port, host, () => console.log(`Archive service running on http://${host}:${port}`));
