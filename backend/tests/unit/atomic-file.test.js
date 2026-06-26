import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
    atomicWriteJsonSync,
    readJsonFileSync,
} from "../../src/utils/atomic-file.util.js";

const temporaryDirectories = [];

function createTempFilePath() {
    const directory = fs.mkdtempSync(
        path.join(os.tmpdir(), "nt219-atomic-json-")
    );
    temporaryDirectories.push(directory);
    return path.join(directory, "data.json");
}

afterEach(() => {
    for (const directory of temporaryDirectories.splice(0)) {
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

describe("atomic JSON storage", () => {
    it("writes complete JSON and leaves no temporary file behind", () => {
        const filePath = createTempFilePath();
        const value = { document_id: "HS-TEST", status: "submitted" };

        atomicWriteJsonSync(filePath, value);

        expect(readJsonFileSync(filePath, null)).toEqual(value);
        const remainingTemporaryFiles = fs.readdirSync(
            path.dirname(filePath)
        ).filter((name) => name.endsWith(".tmp"));
        expect(remainingTemporaryFiles).toEqual([]);
    });

    it("creates a backup before replacing an existing JSON file", () => {
        const filePath = createTempFilePath();
        atomicWriteJsonSync(filePath, { version: 1 });
        atomicWriteJsonSync(filePath, { version: 2 });

        expect(readJsonFileSync(filePath, null)).toEqual({ version: 2 });
        expect(JSON.parse(fs.readFileSync(`${filePath}.bak`, "utf8")))
            .toEqual({ version: 1 });
    });

    it("recovers the active file from the last valid backup", () => {
        const filePath = createTempFilePath();
        atomicWriteJsonSync(filePath, [{ id: 1 }]);
        atomicWriteJsonSync(filePath, [{ id: 1 }, { id: 2 }]);

        fs.writeFileSync(filePath, "{broken-json", "utf8");

        expect(readJsonFileSync(filePath, [])).toEqual([{ id: 1 }]);
        expect(JSON.parse(fs.readFileSync(filePath, "utf8")))
            .toEqual([{ id: 1 }]);
    });
});
