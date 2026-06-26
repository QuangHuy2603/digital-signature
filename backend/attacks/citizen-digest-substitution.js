import { createAttackFixture } from "./citizen-attack-fixture.js";
console.log("\n=== ATTACK 25 - CITIZEN DOCUMENT DIGEST SUBSTITUTION ===");
const { manager } = createAttackFixture({ changingHash: true });
const created = await manager.create({ documentId: "HS-ATTACK-CITIZEN", userId: 4, provider: "software" });
let reason = null;
try { await manager.sign({ documentId: "HS-ATTACK-CITIZEN", userId: 4, requestId: created.request_id, nonce: created.nonce }); }
catch (error) { reason = error.code; }
console.log(`Modified document: ${reason ? "REJECTED" : "ACCEPTED"}`);
console.log(`Reason: ${reason}`);
console.log(`Test result: ${reason === "CITIZEN_DOCUMENT_DIGEST_MISMATCH" ? "PASS" : "FAIL"}`);
if (reason !== "CITIZEN_DOCUMENT_DIGEST_MISMATCH") process.exitCode = 1;
