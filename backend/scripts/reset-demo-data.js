import fs from "node:fs";
import path from "node:path";
import { atomicWriteJsonSync } from "../src/utils/atomic-file.util.js";

const backendRoot = path.resolve(process.cwd());
const projectRoot = path.resolve(backendRoot, "..");
const dataDirectory = path.join(backendRoot, "src", "data");

for (const name of [
    "documents.json",
    "previews.json",
    "signing_requests.json",
    "citizen_signing_requests.json",
    "remote_signing_authorizations.json",
    "certificate_requests.json",
    "certificate_events.json",
    "audit_logs.json",
    "household_members.json",
]) {
    atomicWriteJsonSync(path.join(dataDirectory, name), [], { backup: false });
    fs.rmSync(path.join(dataDirectory, `${name}.bak`), { force: true });
}

for (const relative of ["backend/storage/documents", "backend/storage/archive", "evidence", "results"]) {
    const directory = path.join(projectRoot, relative);
    fs.rmSync(directory, { recursive: true, force: true });
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(path.join(directory, ".gitkeep"), "", "utf8");
}

for (const relative of [
    "tsp-service/storage/jobs.json",
    "tsp-service/storage/nonces.json",
    "client-agent/storage/jobs.json",
    "client-agent/storage/nonces.json",
]) {
    atomicWriteJsonSync(path.join(projectRoot, relative), [], { backup: false });
}

console.log("DEMO DATA RESET: PASS");
console.log("Users, certificate registries, PKI material and SoftHSM token objects were preserved.");
