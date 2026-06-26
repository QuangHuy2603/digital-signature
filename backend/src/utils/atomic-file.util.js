import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

/**
 * Ensure the parent directory of a file exists.
 * @param {string} filePath
 */
export function ensureParentDirectory(filePath) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

/**
 * Write a file using temp-file + fsync + rename.
 * This prevents readers from seeing a partially written file if the process
 * crashes while persisting JSON, metadata, or the encrypted keystore.
 *
 * @param {string} filePath
 * @param {string | Buffer | Uint8Array} data
 * @param {{ encoding?: BufferEncoding | null, mode?: number, backup?: boolean }} [options]
 */
export function atomicWriteFileSync(filePath, data, options = {}) {
    const {
        encoding = typeof data === "string" ? "utf8" : null,
        mode,
        backup = false,
    } = options;

    ensureParentDirectory(filePath);

    const directory = path.dirname(filePath);
    const baseName = path.basename(filePath);
    const temporaryPath = path.join(
        directory,
        `.${baseName}.${process.pid}.${crypto.randomUUID()}.tmp`
    );
    const backupPath = `${filePath}.bak`;

    let fileDescriptor;

    try {
        if (backup && fs.existsSync(filePath)) {
            fs.copyFileSync(filePath, backupPath);
            try {
                const backupDescriptor = fs.openSync(backupPath, "r");
                fs.fsyncSync(backupDescriptor);
                fs.closeSync(backupDescriptor);
            } catch {
                // Backup fsync is best-effort on filesystems that do not support it.
            }
        }

        fileDescriptor = fs.openSync(temporaryPath, "wx", mode);

        if (encoding) {
            fs.writeFileSync(fileDescriptor, data, { encoding });
        } else {
            fs.writeFileSync(fileDescriptor, data);
        }

        fs.fsyncSync(fileDescriptor);
        fs.closeSync(fileDescriptor);
        fileDescriptor = undefined;

        fs.renameSync(temporaryPath, filePath);

        if (typeof mode === "number") {
            try {
                fs.chmodSync(filePath, mode);
            } catch {
                // Windows and some mounted filesystems may not support chmod.
            }
        }
    } catch (error) {
        if (fileDescriptor !== undefined) {
            try {
                fs.closeSync(fileDescriptor);
            } catch {
                // Ignore cleanup errors and preserve the original failure.
            }
        }

        try {
            fs.rmSync(temporaryPath, { force: true });
        } catch {
            // Ignore cleanup errors and preserve the original failure.
        }

        throw error;
    }
}

/**
 * Atomically serialize and persist JSON.
 * @param {string} filePath
 * @param {unknown} value
 * @param {{ space?: number, mode?: number, backup?: boolean }} [options]
 */
export function atomicWriteJsonSync(filePath, value, options = {}) {
    const { space = 2, mode, backup = true } = options;
    const json = `${JSON.stringify(value, null, space)}\n`;

    atomicWriteFileSync(filePath, json, {
        encoding: "utf8",
        mode,
        backup,
    });
}

/**
 * Read JSON with optional recovery from the most recent .bak copy.
 * A clone of fallbackValue is returned when neither file exists.
 *
 * @template T
 * @param {string} filePath
 * @param {T} fallbackValue
 * @param {{ recoverFromBackup?: boolean }} [options]
 * @returns {T}
 */
export function readJsonFileSync(filePath, fallbackValue, options = {}) {
    const { recoverFromBackup = true } = options;
    const backupPath = `${filePath}.bak`;

    const parseFile = (candidatePath) => {
        const raw = fs.readFileSync(candidatePath, "utf8");
        return JSON.parse(raw || "null");
    };

    if (!fs.existsSync(filePath)) {
        if (recoverFromBackup && fs.existsSync(backupPath)) {
            const recovered = parseFile(backupPath);
            atomicWriteJsonSync(filePath, recovered, { backup: false });
            return recovered;
        }

        return structuredClone(fallbackValue);
    }

    try {
        return parseFile(filePath);
    } catch (primaryError) {
        if (recoverFromBackup && fs.existsSync(backupPath)) {
            try {
                const recovered = parseFile(backupPath);
                atomicWriteJsonSync(filePath, recovered, { backup: false });
                return recovered;
            } catch {
                // Throw the primary error below because it points to the active file.
            }
        }

        const error = new Error(`Invalid JSON storage file: ${filePath}`);
        error.code = "INVALID_JSON_STORAGE";
        error.cause = primaryError;
        throw error;
    }
}
