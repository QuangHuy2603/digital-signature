import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(scriptDir, "..");
const backendRoot = path.join(projectRoot, "backend");
const envFile = path.join(backendRoot, ".env");
const envExample = path.join(backendRoot, ".env.example");
const configTemplate = path.join(projectRoot, "infrastructure", "softhsm", "softhsm2.conf.example");
const configFile = path.join(projectRoot, "infrastructure", "softhsm", "softhsm2.conf");
const tokenDirectory = path.join(projectRoot, "infrastructure", "softhsm", "tokens");
const crlMetadataFile = path.join(projectRoot, "pki", "root-ca", "root-ca-crl-metadata.json");
const crlFile = path.join(projectRoot, "pki", "root-ca", "root-ca.crl");

function slash(value) {
    return value.replaceAll("\\", "/");
}

function setEnvValue(name, value) {
    if (!fs.existsSync(envFile)) fs.copyFileSync(envExample, envFile);
    let content = fs.readFileSync(envFile, "utf8").replace(/^\uFEFF/, "");
    const line = `${name}=${value}`;
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pattern = new RegExp(`^${escaped}=.*$`, "m");
    content = pattern.test(content)
        ? content.replace(pattern, line)
        : `${content.trimEnd()}\n${line}\n`;
    fs.writeFileSync(envFile, content, "utf8");
}

fs.mkdirSync(tokenDirectory, { recursive: true });
const template = fs.readFileSync(configTemplate, "utf8");
const config = template.replace("./infrastructure/softhsm/tokens", slash(tokenDirectory));
fs.writeFileSync(configFile, config, "utf8");
setEnvValue("SOFTHSM2_CONF", slash(configFile));
setEnvValue("CLIENT_AGENT_SOFTHSM2_CONF", slash(configFile));

if (fs.existsSync(crlMetadataFile)) {
    const metadata = JSON.parse(fs.readFileSync(crlMetadataFile, "utf8").replace(/^\uFEFF/, ""));
    metadata.crl_path = crlFile;
    fs.writeFileSync(crlMetadataFile, `${JSON.stringify(metadata, null, 2)}\n`, "utf8");
}

console.log("LOCAL PATH PREPARATION: PASS");
console.log(`Project root: ${projectRoot}`);
console.log(`SoftHSM config: ${configFile}`);
console.log(`Token directory: ${tokenDirectory}`);
console.log("Existing token and private-key objects were not recreated.");
