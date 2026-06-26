import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(scriptDirectory, "../..");
const ignored = new Set(["node_modules", ".git"]);

function collect(directory, extension) {
    return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
        if (ignored.has(entry.name)) return [];
        const full = path.join(directory, entry.name);
        if (entry.isDirectory()) return collect(full, extension);
        return entry.isFile() && entry.name.endsWith(extension) ? [full] : [];
    });
}

const jsFiles = collect(projectRoot, ".js");
for (const file of jsFiles) {
    const result = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" });
    if (result.status !== 0) {
        console.error(`JavaScript syntax failed: ${path.relative(projectRoot, file)}`);
        console.error(result.stderr);
        process.exit(1);
    }
}

const jsonFiles = collect(projectRoot, ".json");
for (const file of jsonFiles) {
    try {
        JSON.parse(fs.readFileSync(file, "utf8").replace(/^\uFEFF/, ""));
    } catch (error) {
        console.error(`JSON validation failed: ${path.relative(projectRoot, file)}`);
        console.error(error.message);
        process.exit(1);
    }
}

console.log(`STATIC CHECK: PASS (${jsFiles.length} JavaScript files, ${jsonFiles.length} JSON files)`);
