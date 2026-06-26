import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(__dirname, "..");
const testsRoot = path.join(backendRoot, "tests");

function collect(directory) {
    return fs.readdirSync(directory, { withFileTypes: true })
        .flatMap((entry) => {
            const full = path.join(directory, entry.name);
            if (entry.isDirectory()) return collect(full);
            return entry.isFile() && entry.name.endsWith(".test.js") ? [full] : [];
        })
        .sort();
}

const testFiles = collect(testsRoot);
const declaredTests = testFiles.reduce((total, file) => {
    const source = fs.readFileSync(file, "utf8");
    return total + (source.match(/\bit\s*\(/g) || []).length +
        (source.match(/\btest\s*\(/g) || []).length;
}, 0);
const vitestCli = path.join(
    backendRoot,
    "node_modules",
    "vitest",
    "vitest.mjs",
);

if (!fs.existsSync(vitestCli)) {
    console.error(`Vitest CLI not found: ${vitestCli}`);
    console.error("Run npm.cmd ci before running the test suite.");
    process.exit(2);
}

let passed = 0;

for (const absolute of testFiles) {
    const relative = path.relative(backendRoot, absolute).replaceAll("\\", "/");
    console.log(`\n=== TEST FILE ${passed + 1}/${testFiles.length}: ${relative} ===`);
    const result = spawnSync(process.execPath, [
        vitestCli,
        "run",
        relative,
        "--pool=forks",
        "--maxWorkers=1",
        "--minWorkers=1",
        "--reporter=dot",
    ], {
        cwd: backendRoot,
        env: {
            ...process.env,
            SIGNING_PROVIDER: "file",
            SOFTHSM_RUNTIME_PROBE: "false",
        },
        stdio: "inherit",
        windowsHide: true,
        shell: false,
    });
    if (result.error) {
        console.error(`Unable to launch Vitest: ${result.error.message}`);
        process.exit(2);
    }
    if (result.status !== 0) {
        console.error(`TEST SUITE FAILED at ${relative}`);
        process.exit(result.status || 1);
    }
    passed += 1;
}

console.log(`\nTEST SUITE PASS: ${passed}/${testFiles.length} test files, ${declaredTests} declared tests`);
