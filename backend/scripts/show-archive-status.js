import "dotenv/config";
import { getArchiveStatus, listArchives } from "../src/services/archive.service.js";
console.log(JSON.stringify({ ...getArchiveStatus(), archives: listArchives() }, null, 2));
