import { CitizenSigningError } from "../src/crypto/citizen-signature.service.js";
import { createAttackFixture } from "./citizen-attack-fixture.js";
console.log("\n=== ATTACK 26 - REVOKED CITIZEN CERTIFICATE ===");
const revoked = new CitizenSigningError("Citizen certificate has been revoked", "CITIZEN_CERTIFICATE_REVOKED", 403);
const { manager } = createAttackFixture({ identityError: revoked });
let reason = null;
try { await manager.create({ documentId: "HS-ATTACK-CITIZEN", userId: 4, provider: "software" }); }
catch (error) { reason = error.code; }
console.log(`Revoked certificate: ${reason ? "REJECTED" : "ACCEPTED"}`);
console.log(`Reason: ${reason}`);
console.log(`Test result: ${reason === "CITIZEN_CERTIFICATE_REVOKED" ? "PASS" : "FAIL"}`);
if (reason !== "CITIZEN_CERTIFICATE_REVOKED") process.exitCode = 1;
