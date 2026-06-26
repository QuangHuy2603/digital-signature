/**
 * path-validator.util.js - File path validation to prevent path traversal.
 */

import path from "path";
import fs from "fs";

/**
 * Validate that a file path is within the allowed base directory.
 * Prevents path traversal attacks (e.g. ../../etc/passwd).
 *
 * @param {string} filePath - The file path to validate
 * @param {string} baseDir - The allowed base directory
 * @returns {string} The resolved absolute path
 * @throws {Error} If path is outside the base directory
 */
export function validateFilePath(filePath, baseDir) {
    if (!filePath || typeof filePath !== "string") {
        throw new Error("Invalid file path");
    }

    const resolvedPath = path.resolve(filePath);
    const resolvedBase = path.resolve(baseDir);

    if (!resolvedPath.startsWith(resolvedBase + path.sep) && resolvedPath !== resolvedBase) {
        throw new Error("Access denied: path outside allowed directory");
    }

    return resolvedPath;
}

/**
 * Validate that a file exists and is within the storage directory.
 *
 * @param {string} filePath - The file path to validate
 * @param {string} storageDir - The storage base directory
 * @returns {string} The validated absolute path
 * @throws {Error} If path is invalid or file doesn't exist
 */
export function validateStoragePath(filePath, storageDir) {
    const validatedPath = validateFilePath(filePath, storageDir);

    if (!fs.existsSync(validatedPath)) {
        throw new Error("File not found");
    }

    return validatedPath;
}
