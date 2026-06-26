import { createRemoteOtpAttackFixture } from "./remote-otp-attack-fixture.js";
const f = createRemoteOtpAttackFixture({ maxAttempts: 3 });
const challenge = await f.createChallenge();
let reason = "NO_ERROR";
for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
        await f.manager.verify({ authorizationId: challenge.authorization_id, otp: "999999", documentId: f.documentId, officerId: f.officerId });
    } catch (error) { reason = error.code || error.message; }
}
const passed = reason === "OTP_ATTEMPT_LIMIT_EXCEEDED" && f.repository.findById(challenge.authorization_id).status === "locked";
console.log("\n=== ATTACK 36 - OTP ATTEMPT LIMIT ===");
console.log("Excessive attempts:", passed ? "LOCKED" : "NOT_LOCKED");
console.log("Reason:", reason);
console.log("Test result:", passed ? "PASS" : "FAIL");
if (!passed) process.exitCode = 1;
