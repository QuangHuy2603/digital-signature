import crypto from "node:crypto";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ATTACK_SECRET = "nt219-attack-tsp-secret";
export const ATTACK_PORT = 3499;

export async function startTspAttackServer() {
    const storagePath = path.resolve(__dirname, `../../tsp-service/storage-attack-${process.pid}`);
    const child = spawn(process.execPath, [path.resolve(__dirname, "../../tsp-service/src/server.js")], {
        cwd: path.resolve(__dirname, ".."),
        env: {
            ...process.env,
            TSP_PORT: String(ATTACK_PORT),
            TSP_HOST: "127.0.0.1",
            TSP_SHARED_SECRET: ATTACK_SECRET,
            TSP_CLIENT_ID: "portal-api",
            TSP_STORAGE_PATH: path.relative(path.resolve(__dirname, "../.."), storagePath).replaceAll("\\", "/"),
            SIGNING_PROVIDER: "file",
        },
        stdio: ["ignore", "pipe", "pipe"],
    });
    let logs = "";
    child.stdout.on("data", (chunk) => { logs += chunk; });
    child.stderr.on("data", (chunk) => { logs += chunk; });
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
        if (child.exitCode !== null) throw new Error(`TSP attack server exited: ${logs}`);
        try {
            const response = await fetch(`http://127.0.0.1:${ATTACK_PORT}/health`);
            if (response.ok) return { child, storagePath, logs: () => logs };
        } catch {}
        await new Promise((resolve) => setTimeout(resolve, 150));
    }
    child.kill("SIGTERM");
    throw new Error(`TSP attack server did not start: ${logs}`);
}

export function signedHeaders(rawBody, { nonce = crypto.randomBytes(16).toString("hex"), timestamp = String(Date.now()) } = {}) {
    const signature = crypto.createHmac("sha256", ATTACK_SECRET)
        .update(`${timestamp}.${nonce}.${rawBody}`)
        .digest("hex");
    return {
        "content-type": "application/json",
        "x-tsp-client-id": "portal-api",
        "x-tsp-timestamp": timestamp,
        "x-tsp-nonce": nonce,
        "x-tsp-signature": signature,
    };
}

export async function stopTspAttackServer(server) {
    if (server?.child && server.child.exitCode === null) {
        server.child.kill("SIGTERM");
        await Promise.race([
            new Promise((resolve) => server.child.once("exit", resolve)),
            new Promise((resolve) => setTimeout(resolve, 2000)),
        ]);
    }
    if (server?.storagePath) {
        const fs = await import("node:fs");
        fs.rmSync(server.storagePath, { recursive: true, force: true });
    }
}
