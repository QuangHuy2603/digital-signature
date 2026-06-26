import { verifyClientAgentAuthentication } from "../../client-agent/src/security.js";
const result = verifyClientAgentAuthentication({
    headers: {},
    rawBody: JSON.stringify({ request_id: "unauthenticated" }),
    secret: "client-agent-local-secret",
    usedNonces: [],
});
const passed = result.ok === false && result.code === "CLIENT_AGENT_AUTH_INVALID";
console.log("=== ATTACK 19 - UNAUTHENTICATED CLIENT AGENT REQUEST ===");
console.log(`Reason: ${result.code}`);
console.log(`Test result: ${passed ? "PASS" : "FAIL"}`);
process.exitCode = passed ? 0 : 1;
