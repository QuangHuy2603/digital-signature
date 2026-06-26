import { createRemoteOtpAttackFixture } from "./remote-otp-attack-fixture.js";
const f = createRemoteOtpAttackFixture();
const challenge = await f.createChallenge();
f.advance(121000);
let reason = "NO_ERROR";
try { await f.verifyChallenge(challenge); } catch (error) { reason = error.code || error.message; }
const passed = reason === "OTP_EXPIRED";
console.log("\n=== ATTACK 32 - EXPIRED REMOTE SIGNING OTP ===");
console.log("Expired OTP:", passed ? "REJECTED" : "ACCEPTED");
console.log("Reason:", reason);
console.log("Test result:", passed ? "PASS" : "FAIL");
if (!passed) process.exitCode = 1;
