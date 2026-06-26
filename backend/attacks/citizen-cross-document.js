import { createAttackFixture } from "./citizen-attack-fixture.js";
console.log("\n=== ATTACK 30 - CITIZEN REQUEST USED FOR ANOTHER DOCUMENT ===");
const { manager } = createAttackFixture();
const created = await manager.create({ documentId: "HS-ATTACK-CITIZEN", userId: 4, provider: "software" });
let reason = null;
try { await manager.sign({ documentId: "HS-ANOTHER-DOCUMENT", userId: 4, requestId: created.request_id, nonce: created.nonce }); }
catch (error) { reason = error.code; }
console.log(`Cross-document request: ${reason ? "REJECTED" : "ACCEPTED"}`);
console.log(`Reason: ${reason}`);
console.log(`Test result: ${reason === "CITIZEN_SIGNING_REQUEST_FORBIDDEN" ? "PASS" : "FAIL"}`);
if (reason !== "CITIZEN_SIGNING_REQUEST_FORBIDDEN") process.exitCode = 1;
