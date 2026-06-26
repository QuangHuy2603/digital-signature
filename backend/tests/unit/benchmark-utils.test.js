import { describe, expect, it } from "vitest";
import { percentile, rowsToCsv, summarizeBenchmarkRows } from "../../scripts/benchmark-utils.js";

describe("Signing benchmark benchmark utilities", () => {
    it("computes deterministic summary statistics", () => {
        const rows = [10, 20, 30, 40].map((duration, index) => ({
            operation: "citizen_detached_sign",
            provider: "software",
            result: "PASS",
            duration_ms: duration,
            run: index + 1,
        }));
        const [summary] = summarizeBenchmarkRows(rows);
        expect(summary.mean_ms).toBe(25);
        expect(summary.median_ms).toBe(25);
        expect(summary.p95_ms).toBe(40);
        expect(percentile([1, 2, 3, 4, 5], 95)).toBe(5);
    });

    it("exports stable CSV columns", () => {
        const csv = rowsToCsv([{ operation: "test", signer_type: "citizen", provider: "software", run: 1, duration_ms: 1.5, result: "PASS" }]);
        expect(csv).toContain("operation,signer_type,provider");
        expect(csv).toContain("test,citizen,software");
    });
});
