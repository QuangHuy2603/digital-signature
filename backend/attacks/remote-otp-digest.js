import { createRemoteOtpAttackFixture } from "./remote-otp-attack-fixture.js";
const f = createRemoteOtpAttackFixture();
const challenge = await f.createChallenge();
f.changeDigest();
let reason = "NO_ERROR";
try { await f.verifyChallenge(challenge); } catch (error) { reason = error.code || error.message; }
const passed = reason === "OTP_DIGEST_MISMATCH";
console.log("\n=== ATTACK 35 - DOCUMENT DIGEST CHANGED AFTER OTP ===");
console.log("Changed digest:", passed ? "REJECTED" : "ACCEPTED");
console.log("Reason:", reason);
console.log("Test result:", passed ? "PASS" : "FAIL");
if (!passed) process.exitCode = 1;
