import { createRemoteOtpAttackFixture } from "./remote-otp-attack-fixture.js";
const f = createRemoteOtpAttackFixture();
const challenge = await f.createChallenge();
let reason = "NO_ERROR";
try {
    await f.manager.verify({ authorizationId: challenge.authorization_id, otp: "123456", documentId: f.documentId, officerId: f.officerId });
} catch (error) { reason = error.code || error.message; }
const passed = reason === "OTP_INVALID";
console.log("\n=== ATTACK 31 - WRONG REMOTE SIGNING OTP ===");
console.log("Wrong OTP:", passed ? "REJECTED" : "ACCEPTED");
console.log("Reason:", reason);
console.log("Test result:", passed ? "PASS" : "FAIL");
if (!passed) process.exitCode = 1;
