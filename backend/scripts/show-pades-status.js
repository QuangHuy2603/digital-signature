import "dotenv/config";
import { getPadesStatus } from "../src/crypto/pades.service.js";
console.log(JSON.stringify(getPadesStatus(), null, 2));
