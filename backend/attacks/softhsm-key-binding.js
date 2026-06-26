import crypto from "node:crypto";
import "../src/config/env.config.js";
import { validateSoftHsmCertificateBinding } from "../src/crypto/signing-provider.service.js";

const certificateId = "CERT-OFFICER-001-REMOTE-V2";
const base = {
    certificate_id: certificateId,
    version: 2,
    officer_id: "OFFICER-001",
    key_provider: "softhsm",
    pkcs11_binding_scheme: "nt219-deterministic-v1",
    pkcs11_token_label: "NT219-TSP",
    pkcs11_key_label: "NT219-OFFICER-001-REMOTE-V2",
    pkcs11_key_id: crypto.createHash("sha256").update(certificateId).digest("hex").slice(0, 32),
};

function rejectedCode(record) {
    try {
        validateSoftHsmCertificateBinding(record);
        return null;
    } catch (error) {
        return error.code || error.message;
    }
}

console.log("\n=== ATTACK 22 - SOFTHSM KEY BINDING SUBSTITUTION ===");
let validAccepted = false;
try {
    validateSoftHsmCertificateBinding(base);
    validAccepted = true;
} catch {
    validAccepted = false;
}
const ownerReason = rejectedCode({
    ...base,
    pkcs11_key_label: "NT219-OFFICER-002-REMOTE-V2",
});
const idReason = rejectedCode({
    ...base,
    pkcs11_key_id: "00".repeat(16),
});
const passed = validAccepted &&
    ownerReason === "SOFTHSM_KEY_OWNER_MISMATCH" &&
    idReason === "SOFTHSM_KEY_ID_MISMATCH";

console.log(`Valid binding: ${validAccepted ? "ACCEPTED" : "REJECTED"}`);
console.log(`Cross-officer key label: ${ownerReason ? "REJECTED" : "ACCEPTED"}`);
console.log(`Reason: ${ownerReason}`);
console.log(`Substituted key ID: ${idReason ? "REJECTED" : "ACCEPTED"}`);
console.log(`Reason: ${idReason}`);
console.log(`Test result: ${passed ? "PASS" : "FAIL"}`);
process.exitCode = passed ? 0 : 1;
