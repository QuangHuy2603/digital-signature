import "dotenv/config";
import { getOcspResponderStatus } from "../src/crypto/ocsp.service.js";
import { getTsaStatus } from "../src/crypto/tsa.service.js";
console.log(JSON.stringify({ ocsp: getOcspResponderStatus(), tsa: getTsaStatus() }, null, 2));
