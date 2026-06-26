import fs from "node:fs";
import path from "node:path";
import { atomicWriteJsonSync } from "../src/utils/atomic-file.util.js";

const backendRoot = path.resolve(process.cwd());
const projectRoot = path.resolve(backendRoot, "..");
const dataDirectory = path.join(backendRoot, "src", "data");
const arrayFiles = [
    "users.json",
    "certificates.json",
    "documents.json",
    "previews.json",
    "signing_requests.json",
    "citizen_signing_requests.json",
    "remote_signing_authorizations.json",
    "certificate_requests.json",
    "certificate_events.json",
    "audit_logs.json",
    "household_members.json",
];

fs.mkdirSync(dataDirectory, { recursive: true });
for (const name of arrayFiles) {
    const filePath = path.join(dataDirectory, name);
    if (!fs.existsSync(filePath)) atomicWriteJsonSync(filePath, [], { backup: false });
}

for (const [relative, defaultValue] of [
    ["client-agent/storage/certificates.json", []],
    ["client-agent/storage/jobs.json", []],
    ["client-agent/storage/nonces.json", []],
    ["tsp-service/storage/jobs.json", []],
    ["tsp-service/storage/nonces.json", []],
]) {
    const filePath = path.join(projectRoot, relative);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    if (!fs.existsSync(filePath)) atomicWriteJsonSync(filePath, defaultValue, { backup: false });
}

for (const relative of [
    "backend/storage/documents",
    "backend/storage/archive",
    "evidence",
    "results",
    "infrastructure/softhsm/tokens",
]) {
    fs.mkdirSync(path.join(projectRoot, relative), { recursive: true });
}

console.log("JSON STORAGE INITIALIZATION: PASS");
