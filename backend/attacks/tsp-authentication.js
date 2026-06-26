import { startTspAttackServer, stopTspAttackServer, ATTACK_PORT } from "./tsp-attack-utils.js";
let server;
try {
  server = await startTspAttackServer();
  const response = await fetch(`http://127.0.0.1:${ATTACK_PORT}/v1/sign/pades-bt`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request_id: "unauthenticated" }),
  });
  const body = await response.json();
  const passed = response.status === 401 && body.code === "TSP_AUTH_INVALID";
  console.log("=== ATTACK 16 - UNAUTHENTICATED TSP REQUEST ===");
  console.log(`HTTP status: ${response.status}`);
  console.log(`Reason: ${body.code}`);
  console.log(`Test result: ${passed ? "PASS" : "FAIL"}`);
  process.exitCode = passed ? 0 : 1;
} finally { await stopTspAttackServer(server); }
