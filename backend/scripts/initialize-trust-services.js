import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { parseCliArgs } from "./cli-args.js";

function run(args) {
    const result = spawnSync(process.env.OPENSSL_BIN || "openssl", args, {
        cwd: process.cwd(), encoding: "utf8", stdio: "inherit", windowsHide: true,
    });
    if (result.error || result.status !== 0) {
        throw new Error(result.error?.message || `OpenSSL failed: ${args.join(" ")}`);
    }
}

const args = parseCliArgs();
const force = args.force === true;
const projectRoot = path.resolve(process.cwd(), "..");
const pki = path.join(projectRoot, "pki");
const rootCert = path.join(pki, "root-ca", "root-ca.crt");
const rootKey = path.join(pki, "root-ca", "root-ca.key");
const serial = path.join(pki, "root-ca", "root-ca.srl");
if (!fs.existsSync(rootCert) || !fs.existsSync(rootKey)) throw new Error("ROOT_CA_NOT_FOUND");

const services = [
    {
        dir: path.join(pki, "ocsp"), key: "ocsp-responder.key", csr: "ocsp-responder.csr", cert: "ocsp-responder.crt", chain: "ocsp-chain.pem",
        subject: "/C=VN/O=HCMUTE/OU=NT219 Test PKI/CN=NT219 OCSP Responder",
        ext: path.join(pki, "config", "ocsp-ext.cnf"), section: "v3_ocsp",
    },
    {
        dir: path.join(pki, "tsa"), key: "tsa.key", csr: "tsa.csr", cert: "tsa.crt", chain: "tsa-chain.pem",
        subject: "/C=VN/O=HCMUTE/OU=NT219 Test PKI/CN=NT219 Test TSA",
        ext: path.join(pki, "config", "tsa-ext.cnf"), section: "v3_tsa",
    },
];

for (const service of services) {
    fs.mkdirSync(service.dir, { recursive: true });
    const key = path.join(service.dir, service.key);
    const csr = path.join(service.dir, service.csr);
    const cert = path.join(service.dir, service.cert);
    const chain = path.join(service.dir, service.chain);
    if (fs.existsSync(cert) && !force) {
        console.log(`SKIP: ${cert} already exists (use --force to regenerate)`);
        continue;
    }
    for (const file of [key, csr, cert, chain]) fs.rmSync(file, { force: true });
    run(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", key]);
    run(["req", "-new", "-sha256", "-key", key, "-out", csr, "-subj", service.subject]);
    const signArgs = ["x509", "-req", "-in", csr, "-CA", rootCert, "-CAkey", rootKey];
    signArgs.push(fs.existsSync(serial) ? "-CAserial" : "-CAcreateserial", fs.existsSync(serial) ? serial : undefined);
    const cleanArgs = signArgs.filter(Boolean);
    cleanArgs.push("-out", cert, "-days", "825", "-sha256", "-extfile", service.ext, "-extensions", service.section);
    run(cleanArgs);
    fs.writeFileSync(chain, `${fs.readFileSync(cert, "utf8").trim()}\n${fs.readFileSync(rootCert, "utf8").trim()}\n`, "ascii");
    try { fs.chmodSync(key, 0o600); } catch {}
    console.log(`CREATED: ${cert}`);
}
console.log("TRUST SERVICES INITIALIZATION: PASS");
