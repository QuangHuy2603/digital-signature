import { createAttackFixture } from "./citizen-attack-fixture.js";
console.log("\n=== ATTACK 29 - EXPIRED CITIZEN SIGNING REQUEST ===");
const { manager, advanceTime } = createAttackFixture({ expired: true });
const created = await manager.create({ documentId: "HS-ATTACK-CITIZEN", userId: 4, provider: "software" });
advanceTime(2000);
let reason = null;
try { await manager.sign({ documentId: "HS-ATTACK-CITIZEN", userId: 4, requestId: created.request_id, nonce: created.nonce }); }
catch (error) { reason = error.code; }
console.log(`Expired request: ${reason ? "REJECTED" : "ACCEPTED"}`);
console.log(`Reason: ${reason}`);
console.log(`Test result: ${reason === "CITIZEN_SIGNING_REQUEST_EXPIRED" ? "PASS" : "FAIL"}`);
if (reason !== "CITIZEN_SIGNING_REQUEST_EXPIRED") process.exitCode = 1;
