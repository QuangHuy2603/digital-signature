import crypto from "node:crypto";
import fs from "node:fs";
import { startTspAttackServer, stopTspAttackServer, ATTACK_PORT, signedHeaders } from "./tsp-attack-utils.js";
import { createPadesFixture } from "./pades-attack-utils.js";

let server;
try {
  server = await startTspAttackServer();

  // Use a complete, valid signing payload. The first request must really succeed;
  // otherwise a 400 validation error could incorrectly be counted as replay protection.
  const fixture = await createPadesFixture();
  const inputPdf = fs.readFileSync(fixture.inputPdfPath);
  const payload = {
    request_id: `replay-${crypto.randomUUID()}`,
    document_id: `HS-TSP-REPLAY-${Date.now()}`,
    certificate_id: fixture.certificateRecord.certificate_id,
    signer: {
      officer_id: "OFFICER-001",
      full_name: "Can bo Nguyen",
      email: "officer@test.com",
    },
    issued_at: new Date().toISOString(),
    input_pdf_base64: inputPdf.toString("base64"),
    document_digest_sha256: crypto
      .createHash("sha256")
      .update(inputPdf)
      .digest("hex")
      .toUpperCase(),
  };

  const raw = JSON.stringify(payload);
  const nonce = crypto.randomBytes(16).toString("hex");
  const timestamp = String(Date.now());
  const headers = signedHeaders(raw, { nonce, timestamp });

  const first = await fetch(`http://127.0.0.1:${ATTACK_PORT}/v1/sign/pades-bt`, {
    method: "POST",
    headers,
    body: raw,
  });
  const firstBody = await first.json();

  const second = await fetch(`http://127.0.0.1:${ATTACK_PORT}/v1/sign/pades-bt`, {
    method: "POST",
    headers,
    body: raw,
  });
  const secondBody = await second.json();

  const passed =
    first.status === 201 &&
    firstBody.status === "signed" &&
    second.status === 409 &&
    secondBody.code === "TSP_REPLAY_DETECTED";

  console.log("=== ATTACK 17 - TSP NONCE REPLAY ===");
  console.log(`First request status: ${first.status}`);
  console.log(`First request result: ${firstBody.status || firstBody.code || "UNKNOWN"}`);
  console.log(`Replay request status: ${second.status}`);
  console.log(`Reason: ${secondBody.code}`);
  console.log(`Test result: ${passed ? "PASS" : "FAIL"}`);
  process.exitCode = passed ? 0 : 1;
} finally {
  await stopTspAttackServer(server);
}
