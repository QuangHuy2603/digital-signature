import { createRemoteOtpAttackFixture } from "./remote-otp-attack-fixture.js";
const f = createRemoteOtpAttackFixture();
const challenge = await f.createChallenge();
const verified = await f.verifyChallenge(challenge);
const input = f.reserveInput(verified);
await f.manager.reserve(input);
await f.manager.complete({ authorizationId: verified.authorization_id, documentId: f.documentId, officerId: f.officerId });
let reason = "NO_ERROR";
try { await f.manager.reserve(input); } catch (error) { reason = error.code || error.message; }
const passed = reason === "OTP_REPLAY_DETECTED";
console.log("\n=== ATTACK 33 - REMOTE OTP REPLAY ===");
console.log("Replayed authorization:", passed ? "REJECTED" : "ACCEPTED");
console.log("Reason:", reason);
console.log("Test result:", passed ? "PASS" : "FAIL");
if (!passed) process.exitCode = 1;
