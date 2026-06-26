import { createRemoteOtpAttackFixture } from "./remote-otp-attack-fixture.js";
const f = createRemoteOtpAttackFixture();
const challenge = await f.createChallenge();
let reason = "NO_ERROR";
try {
    await f.manager.verify({ authorizationId: challenge.authorization_id, otp: challenge.demo_otp, documentId: "HS-OTHER-DOCUMENT", officerId: f.officerId });
} catch (error) { reason = error.code || error.message; }
const passed = reason === "OTP_DOCUMENT_BINDING_MISMATCH";
console.log("\n=== ATTACK 34 - OTP USED FOR ANOTHER DOCUMENT ===");
console.log("Cross-document OTP:", passed ? "REJECTED" : "ACCEPTED");
console.log("Reason:", reason);
console.log("Test result:", passed ? "PASS" : "FAIL");
if (!passed) process.exitCode = 1;
