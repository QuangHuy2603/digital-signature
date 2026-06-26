import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import { createPadesFixture } from "../tests/helpers/pades-fixture.js";
import { createLtvArchive, verifyLtvArchive } from "../src/services/archive.service.js";
let fixture;
let archive;
try {
  process.env.SIGNING_PROVIDER = "file";
  fixture = await createPadesFixture({ text: "Archive tampering attack" });
  archive = createLtvArchive({
    documentId: "HS-ATTACK-ARCHIVE",
    originalPdfPath: fixture.inputPdfPath,
    signedPdfPath: fixture.signedPdfPath,
    metadata: { document_id: "HS-ATTACK-ARCHIVE", pades_level: "PAdES-B-T", key_provider: "file" },
    certificateRecord: fixture.certificateRecord,
    ocspEvidence: {},
    padesEvidence: fixture.evidence,
    timestampEvidence: fixture.evidence.timestamp_evidence,
  });
  const original = verifyLtvArchive(archive.archive_id);
  fs.appendFileSync(path.join(archive.archive_path, "documents/signed.pdf"), Buffer.from("ARCHIVE-TAMPER"));
  const modified = verifyLtvArchive(archive.archive_id);
  const passed = original.valid && !modified.valid && modified.reason === "ARCHIVE_FILE_TAMPERED";
  console.log("=== ATTACK 18 - TAMPERED LTV ARCHIVE ===");
  console.log(`Original archive: ${original.valid ? "VALID" : "INVALID"}`);
  console.log(`Tampered archive: ${modified.valid ? "ACCEPTED" : "REJECTED"}`);
  console.log(`Reason: ${modified.reason}`);
  console.log(`Test result: ${passed ? "PASS" : "FAIL"}`);
  process.exitCode = passed ? 0 : 1;
} finally {
  fixture?.cleanup();
  if (archive?.archive_path) fs.rmSync(archive.archive_path, { recursive: true, force: true });
}
