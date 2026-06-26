import path from "node:path";
import { atomicWriteJsonSync, readJsonFileSync } from "../utils/atomic-file.util.js";

const dataFilePath = path.resolve("src/data/certificate_requests.json");
const eventsFilePath = path.resolve("src/data/certificate_events.json");

function readArray(filePath) {
    const value = readJsonFileSync(filePath, []);
    if (!Array.isArray(value)) throw new Error(`${path.basename(filePath)} must contain a JSON array`);
    return value;
}

function writeArray(filePath, value) {
    atomicWriteJsonSync(filePath, value, { backup: true });
}

export function listCertificateRequests() {
    return readArray(dataFilePath);
}

export function findCertificateRequestById(requestId) {
    return listCertificateRequests().find((item) => item.request_id === requestId) || null;
}

export function saveCertificateRequest(record) {
    const records = listCertificateRequests();
    if (records.some((item) => item.request_id === record.request_id)) {
        throw new Error(`Certificate request already exists: ${record.request_id}`);
    }
    records.push(record);
    writeArray(dataFilePath, records);
    return record;
}

export function updateCertificateRequest(requestId, patch) {
    const records = listCertificateRequests();
    const index = records.findIndex((item) => item.request_id === requestId);
    if (index < 0) return null;
    records[index] = { ...records[index], ...patch };
    writeArray(dataFilePath, records);
    return records[index];
}

export function replaceCertificateRequests(records) {
    if (!Array.isArray(records)) throw new Error("records must be an array");
    writeArray(dataFilePath, records);
    return records;
}

export function listCertificateEvents() {
    return readArray(eventsFilePath);
}

export function appendCertificateEvent(event) {
    const events = listCertificateEvents();
    events.push(event);
    writeArray(eventsFilePath, events);
    return event;
}

export function createMemoryCertificateRequestRepository(initial = []) {
    let records = structuredClone(initial);
    let events = [];
    return {
        list: () => structuredClone(records),
        findById: (id) => structuredClone(records.find((item) => item.request_id === id) || null),
        save: (record) => {
            records.push(structuredClone(record));
            return structuredClone(record);
        },
        update: (id, patch) => {
            const index = records.findIndex((item) => item.request_id === id);
            if (index < 0) return null;
            records[index] = { ...records[index], ...structuredClone(patch) };
            return structuredClone(records[index]);
        },
        replace: (next) => { records = structuredClone(next); return structuredClone(records); },
        appendEvent: (event) => { events.push(structuredClone(event)); return structuredClone(event); },
        listEvents: () => structuredClone(events),
    };
}

export const fileCertificateRequestRepository = {
    list: listCertificateRequests,
    findById: findCertificateRequestById,
    save: saveCertificateRequest,
    update: updateCertificateRequest,
    replace: replaceCertificateRequests,
    appendEvent: appendCertificateEvent,
    listEvents: listCertificateEvents,
};
