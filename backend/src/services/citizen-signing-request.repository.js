import path from "node:path";
import { atomicWriteJsonSync, readJsonFileSync } from "../utils/atomic-file.util.js";

const dataFilePath = path.resolve("src/data/citizen_signing_requests.json");

function readAll() {
    const value = readJsonFileSync(dataFilePath, []);
    if (!Array.isArray(value)) throw new Error("citizen_signing_requests.json must contain an array");
    return value;
}

function writeAll(records) {
    atomicWriteJsonSync(dataFilePath, records, { backup: true });
}

export function createCitizenSigningRequestRecord(record) {
    const records = readAll();
    if (records.some((item) => item.request_id === record.request_id)) {
        throw new Error(`Citizen signing request ${record.request_id} already exists`);
    }
    records.push(record);
    writeAll(records);
    return record;
}

export function findCitizenSigningRequestById(requestId) {
    return readAll().find((item) => item.request_id === requestId) || null;
}

export function updateCitizenSigningRequestRecord(requestId, patch) {
    const records = readAll();
    const index = records.findIndex((item) => item.request_id === requestId);
    if (index < 0) return null;
    records[index] = { ...records[index], ...patch };
    writeAll(records);
    return records[index];
}

export function replaceCitizenSigningRequests(records) {
    if (!Array.isArray(records)) throw new Error("records must be an array");
    writeAll(records);
}
