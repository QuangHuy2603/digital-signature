import fs from "node:fs";
import path from "node:path";
import {
    REMOTE_OTP_AUTHORIZATION_TTL_SECONDS,
    REMOTE_OTP_DEMO_EXPOSE,
    REMOTE_OTP_MAX_ATTEMPTS,
    REMOTE_OTP_REQUIRED,
    REMOTE_OTP_TTL_SECONDS,
} from "../src/config/env.config.js";
import repository, {
    DEFAULT_REMOTE_SIGNING_AUTHORIZATIONS_FILE,
} from "../src/services/remote-signing-authorization.repository.js";

const records = repository.list();
const counts = records.reduce((summary, item) => {
    summary[item.status || "unknown"] = (summary[item.status || "unknown"] || 0) + 1;
    return summary;
}, {});

console.log(JSON.stringify({
    version: "1.0.0",
    feature: "remote-signing-step-up-otp",
    ready: REMOTE_OTP_REQUIRED && Boolean(process.env.REMOTE_OTP_SECRET),
    required_for_remote_signing: REMOTE_OTP_REQUIRED,
    otp_digits: 6,
    otp_ttl_seconds: REMOTE_OTP_TTL_SECONDS,
    authorization_ttl_seconds: REMOTE_OTP_AUTHORIZATION_TTL_SECONDS,
    max_attempts: REMOTE_OTP_MAX_ATTEMPTS,
    demo_otp_exposed: REMOTE_OTP_DEMO_EXPOSE,
    otp_storage: {
        path: path.relative(process.cwd(), DEFAULT_REMOTE_SIGNING_AUTHORIZATIONS_FILE),
        exists: fs.existsSync(DEFAULT_REMOTE_SIGNING_AUTHORIZATIONS_FILE),
        records: records.length,
        status_counts: counts,
        plaintext_otp_stored: records.some((item) => Object.prototype.hasOwnProperty.call(item, "otp")),
        otp_hash_algorithm: "HMAC-SHA256",
    },
    bindings: [
        "officer_id",
        "document_id",
        "document_digest_sha256",
        "signing_request_id",
        "signing_nonce",
        "remote_certificate_id",
    ],
}, null, 2));
