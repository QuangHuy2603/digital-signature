import { createAttackFixture } from "./citizen-attack-fixture.js";
console.log("\n=== ATTACK 23 - CITIZEN CERTIFICATE/DOCUMENT OWNER MISMATCH ===");
const { manager } = createAttackFixture();
let reason = null;
try { await manager.create({ documentId: "HS-ATTACK-CITIZEN", userId: 999, provider: "software" }); }
catch (error) { reason = error.code; }
console.log(`Cross-citizen signing: ${reason ? "REJECTED" : "ACCEPTED"}`);
console.log(`Reason: ${reason}`);
console.log(`Test result: ${reason === "CITIZEN_DOCUMENT_OWNER_MISMATCH" ? "PASS" : "FAIL"}`);
if (reason !== "CITIZEN_DOCUMENT_OWNER_MISMATCH") process.exitCode = 1;
