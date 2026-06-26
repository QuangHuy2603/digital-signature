import "dotenv/config";
import { verifyLtvArchive } from "../src/services/archive.service.js";
const idIndex = process.argv.indexOf("--archive-id");
const archiveId = idIndex >= 0 ? process.argv[idIndex + 1] : process.argv[2];
if (!archiveId) { console.error("Usage: npm run archive:verify -- --archive-id ARCH-..."); process.exit(2); }
const result = verifyLtvArchive(archiveId);
console.log(JSON.stringify(result, null, 2));
process.exit(result.valid ? 0 : 1);
