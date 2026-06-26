import "dotenv/config";
import { createTimestampToken, verifyTimestampToken } from "../src/crypto/tsa.service.js";
const data = Buffer.from("RFC 3161 timestamp manual verification", "utf8");
const token = createTimestampToken({ dataBuffer: data });
const verified = verifyTimestampToken({ dataBuffer: data, responseDerBase64: token.response_der_base64 });
console.log(JSON.stringify({ token, verified }, null, 2));
if (!verified.valid) process.exitCode = 1;
else console.log("RFC3161 TSA VERIFICATION: PASS");
