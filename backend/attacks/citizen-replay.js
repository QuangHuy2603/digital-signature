import { createAttackFixture } from "./citizen-attack-fixture.js";
console.log("\n=== ATTACK 24 - CITIZEN SIGNING REQUEST REPLAY ===");
const { manager } = createAttackFixture();
const created = await manager.create({ documentId: "HS-ATTACK-CITIZEN", userId: 4, provider: "software" });
await manager.sign({ documentId: "HS-ATTACK-CITIZEN", userId: 4, requestId: created.request_id, nonce: created.nonce });
let reason = null;
try { await manager.sign({ documentId: "HS-ATTACK-CITIZEN", userId: 4, requestId: created.request_id, nonce: created.nonce }); }
catch (error) { reason = error.code; }
console.log("First request: ACCEPTED");
console.log(`Replay: ${reason ? "REJECTED" : "ACCEPTED"}`);
console.log(`Reason: ${reason}`);
console.log(`Test result: ${reason === "CITIZEN_SIGNING_REPLAY_DETECTED" ? "PASS" : "FAIL"}`);
if (reason !== "CITIZEN_SIGNING_REPLAY_DETECTED") process.exitCode = 1;
