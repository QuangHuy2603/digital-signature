export function percentile(values, percentileValue) {
    if (!Array.isArray(values) || values.length === 0) return null;
    const sorted = [...values].sort((a, b) => a - b);
    const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((percentileValue / 100) * sorted.length) - 1));
    return sorted[index];
}

export function summarizeBenchmarkRows(rows = []) {
    const groups = new Map();
    for (const row of rows.filter((item) => item.result === "PASS")) {
        const key = `${row.operation}|${row.provider}`;
        const current = groups.get(key) || [];
        current.push(Number(row.duration_ms));
        groups.set(key, current);
    }
    return [...groups.entries()].map(([key, values]) => {
        const [operation, provider] = key.split("|");
        const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
        const sorted = [...values].sort((a, b) => a - b);
        const middle = Math.floor(sorted.length / 2);
        const median = sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
        return {
            operation,
            provider,
            runs: values.length,
            mean_ms: Number(mean.toFixed(3)),
            median_ms: Number(median.toFixed(3)),
            min_ms: Number(Math.min(...values).toFixed(3)),
            max_ms: Number(Math.max(...values).toFixed(3)),
            p95_ms: Number(percentile(values, 95).toFixed(3)),
        };
    });
}

export function rowsToCsv(rows = []) {
    const columns = ["operation", "signer_type", "provider", "run", "duration_ms", "input_bytes", "output_bytes", "certificate_id", "key_exportable", "result", "reason"];
    const escape = (value) => {
        const text = value === null || value === undefined ? "" : String(value);
        return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
    };
    return [columns.join(","), ...rows.map((row) => columns.map((column) => escape(row[column])).join(","))].join("\n") + "\n";
}
