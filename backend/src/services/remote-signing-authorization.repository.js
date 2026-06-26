import path from "node:path";
import {
    atomicWriteJsonSync,
    readJsonFileSync,
} from "../utils/atomic-file.util.js";

export const DEFAULT_REMOTE_SIGNING_AUTHORIZATIONS_FILE = path.resolve(
    "src/data/remote_signing_authorizations.json"
);

const clone = (value) => structuredClone(value);

export function createFileRemoteSigningAuthorizationRepository(
    filePath = DEFAULT_REMOTE_SIGNING_AUTHORIZATIONS_FILE
) {
    const readAll = () => {
        const records = readJsonFileSync(filePath, []);
        if (!Array.isArray(records)) {
            throw new Error("remote_signing_authorizations.json must contain a JSON array");
        }
        return records;
    };

    const writeAll = (records) => {
        atomicWriteJsonSync(filePath, records, { backup: true });
    };

    return {
        create(record) {
            const records = readAll();
            if (records.some((item) => item.authorization_id === record.authorization_id)) {
                throw new Error(`Remote signing authorization ${record.authorization_id} already exists`);
            }
            records.push(clone(record));
            writeAll(records);
            return clone(record);
        },

        findById(authorizationId) {
            const record = readAll().find(
                (item) => item.authorization_id === authorizationId
            );
            return record ? clone(record) : null;
        },

        update(authorizationId, changes) {
            const records = readAll();
            const index = records.findIndex(
                (item) => item.authorization_id === authorizationId
            );
            if (index === -1) return null;
            records[index] = {
                ...records[index],
                ...clone(changes),
            };
            writeAll(records);
            return clone(records[index]);
        },

        list() {
            return clone(readAll());
        },
    };
}

export function createMemoryRemoteSigningAuthorizationRepository(initial = []) {
    let records = clone(initial);
    return {
        create(record) {
            if (records.some((item) => item.authorization_id === record.authorization_id)) {
                throw new Error(`Remote signing authorization ${record.authorization_id} already exists`);
            }
            records.push(clone(record));
            return clone(record);
        },
        findById(authorizationId) {
            const record = records.find(
                (item) => item.authorization_id === authorizationId
            );
            return record ? clone(record) : null;
        },
        update(authorizationId, changes) {
            const index = records.findIndex(
                (item) => item.authorization_id === authorizationId
            );
            if (index === -1) return null;
            records[index] = {
                ...records[index],
                ...clone(changes),
            };
            return clone(records[index]);
        },
        list() {
            return clone(records);
        },
    };
}

const defaultRepository = createFileRemoteSigningAuthorizationRepository();
export default defaultRepository;
