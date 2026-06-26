import { createClientAgentSignature, verifyClientAgentAuthentication } from "../../client-agent/src/security.js";
const rawBody = JSON.stringify({ request_id: "replayed-local-signing-request" });
const timestamp = String(Date.now());
const nonce = "already-used-client-agent-nonce";
const secret = "client-agent-local-secret";
const headers = {
    "x-client-agent-client-id": "portal-api",
    "x-client-agent-timestamp": timestamp,
    "x-client-agent-nonce": nonce,
    "x-client-agent-signature": createClientAgentSignature({ timestamp, nonce, rawBody, secret }),
};
const result = verifyClientAgentAuthentication({
    headers, rawBody, secret,
    usedNonces: [{ nonce, used_at_ms: Date.now() }],
});
const passed = result.ok === false && result.code === "CLIENT_AGENT_REPLAY_DETECTED";
console.log("=== ATTACK 20 - CLIENT AGENT REPLAY ===");
console.log(`Reason: ${result.code}`);
console.log(`Test result: ${passed ? "PASS" : "FAIL"}`);
process.exitCode = passed ? 0 : 1;
