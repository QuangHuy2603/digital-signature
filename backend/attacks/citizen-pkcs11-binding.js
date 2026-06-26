import crypto from "node:crypto";
import { validateCitizenPkcs11Binding } from "../../client-agent/src/providers.js";
console.log("\n=== ATTACK 28 - CITIZEN PKCS#11 KEY BINDING SUBSTITUTION ===");
const certificateId = "CERT-CITIZEN-001-PKCS11-V2";
const id = crypto.createHash("sha256").update(certificateId).digest("hex").slice(0, 32);
const base = { certificate_id: certificateId, version: 2, signer_type: "citizen", citizen_id: "CITIZEN-001", pkcs11_token_label: "NT219-CITIZEN", pkcs11_key_label: "NT219-CITIZEN-001-SIGNING-V2", pkcs11_key_id: id, pkcs11_binding_scheme: "nt219-citizen-deterministic-v1" };
let labelReason = null, idReason = null;
try { validateCitizenPkcs11Binding({ ...base, pkcs11_key_label: "NT219-CITIZEN-999-SIGNING-V2" }); } catch (error) { labelReason = error.code; }
try { validateCitizenPkcs11Binding({ ...base, pkcs11_key_id: "00".repeat(16) }); } catch (error) { idReason = error.code; }
console.log(`Cross-citizen key label: ${labelReason ? "REJECTED" : "ACCEPTED"}`);
console.log(`Reason: ${labelReason}`);
console.log(`Substituted key ID: ${idReason ? "REJECTED" : "ACCEPTED"}`);
console.log(`Reason: ${idReason}`);
const pass = labelReason === "CITIZEN_PKCS11_KEY_OWNER_MISMATCH" && idReason === "CITIZEN_PKCS11_KEY_ID_MISMATCH";
console.log(`Test result: ${pass ? "PASS" : "FAIL"}`);
if (!pass) process.exitCode = 1;
