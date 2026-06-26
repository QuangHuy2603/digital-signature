import path from "node:path";
import {
    atomicWriteJsonSync,
    readJsonFileSync,
} from "../utils/atomic-file.util.js";

export const DEFAULT_SIGNING_REQUESTS_FILE = path.resolve(
    "src/data/signing_requests.json"
);

const clone = (value) => structuredClone(value);

/**
 * File-backed repository for one-time remote-signing requests.
 * All writes use temp-file + fsync + rename through atomicWriteJsonSync.
 */
export function createFileSigningRequestRepository(
    filePath = DEFAULT_SIGNING_REQUESTS_FILE
) {
    const readAll = () => {
        const requests = readJsonFileSync(filePath, []);
        if (!Array.isArray(requests)) {
            throw new Error("signing_requests.json must contain a JSON array");
        }
        return requests;
    };

    const writeAll = (requests) => {
        atomicWriteJsonSync(filePath, requests, { backup: true });
    };

    return {
        create(request) {
            const requests = readAll();
            if (requests.some((item) => item.request_id === request.request_id)) {
                throw new Error(`Signing request ${request.request_id} already exists`);
            }
            requests.push(clone(request));
            writeAll(requests);
            return clone(request);
        },

        findById(requestId) {
            const request = readAll().find(
                (item) => item.request_id === requestId
            );
            return request ? clone(request) : null;
        },

        update(requestId, changes) {
            const requests = readAll();
            const index = requests.findIndex(
                (item) => item.request_id === requestId
            );
            if (index === -1) return null;

            requests[index] = {
                ...requests[index],
                ...clone(changes),
            };
            writeAll(requests);
            return clone(requests[index]);
        },

        list() {
            return clone(readAll());
        },
    };
}

/** In-memory repository used by unit tests and attack demonstrations. */
export function createMemorySigningRequestRepository(initialRequests = []) {
    let requests = clone(initialRequests);

    return {
        create(request) {
            if (requests.some((item) => item.request_id === request.request_id)) {
                throw new Error(`Signing request ${request.request_id} already exists`);
            }
            requests.push(clone(request));
            return clone(request);
        },

        findById(requestId) {
            const request = requests.find(
                (item) => item.request_id === requestId
            );
            return request ? clone(request) : null;
        },

        update(requestId, changes) {
            const index = requests.findIndex(
                (item) => item.request_id === requestId
            );
            if (index === -1) return null;
            requests[index] = {
                ...requests[index],
                ...clone(changes),
            };
            return clone(requests[index]);
        },

        list() {
            return clone(requests);
        },
    };
}

const defaultRepository = createFileSigningRequestRepository();

export default defaultRepository;
