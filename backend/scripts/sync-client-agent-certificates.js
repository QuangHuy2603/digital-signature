import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { findCertificatesByOfficerId } from "../src/services/certificate.repository.js";
import { findOfficerByOfficerId } from "../src/services/officer-account.service.js";
import { atomicWriteJsonSync } from "../src/utils/atomic-file.util.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const backendRoot = path.resolve(__dirname, "..");
const projectRoot = path.resolve(backendRoot, "..");
const users = JSON.parse(fs.readFileSync(path.join(backendRoot, "src/data/users.json"), "utf8"));
const officers = users.filter((user) => Array.isArray(user.roles) && user.roles.includes("officer"));
const output = [];
for (const user of officers) {
    const officer = findOfficerByOfficerId(user.officer_id);
    const localCertificateId = user.local_certificate_id || user.active_certificate_id || null;
    const records = findCertificatesByOfficerId(user.officer_id).filter(
        (item) => item.status === "active" &&
            item.certificate_id === localCertificateId &&
            item.private_key_path
    );
    for (const record of records) {
        const versionDir = `v${record.version || 1}`;
        const relativeBase = path.join("client-agent", "storage", "keys", record.officer_id, versionDir);
        const absoluteBase = path.join(projectRoot, relativeBase);
        fs.mkdirSync(absoluteBase, { recursive: true });
        const mappings = [
            [record.certificate_path, "officer.crt"],
            [record.private_key_path, "officer.key"],
            [record.certificate_chain_path, "officer-chain.pem"],
        ];
        for (const [sourceValue, targetName] of mappings) {
            if (!sourceValue) continue;
            const source = path.resolve(backendRoot, sourceValue);
            if (fs.existsSync(source)) fs.copyFileSync(source, path.join(absoluteBase, targetName));
        }
        output.push({
            certificate_id: record.certificate_id,
            officer_id: record.officer_id,
            full_name: officer?.full_name || record.full_name,
            email: officer?.email || record.email,
            status: record.status,
            certificate_path: path.join(relativeBase, "officer.crt").replaceAll("\\", "/"),
            private_key_path: path.join(relativeBase, "officer.key").replaceAll("\\", "/"),
            certificate_chain_path: path.join(relativeBase, "officer-chain.pem").replaceAll("\\", "/"),
            root_ca_certificate_path: "pki/root-ca/root-ca.crt",
            fingerprint_sha256: record.fingerprint_sha256,
            serial_number: record.serial_number,
            provider: "software",
        });
    }
}
atomicWriteJsonSync(path.join(projectRoot, "client-agent/storage/certificates.json"), output, { backup: true });
console.log(JSON.stringify({ synced: output.length, certificates: output.map((item) => item.certificate_id) }, null, 2));
