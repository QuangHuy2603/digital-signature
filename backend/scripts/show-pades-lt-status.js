import fs from "node:fs";
import path from "node:path";
import { getPadesStatus } from "../src/crypto/pades.service.js";
import {
    PKI_CRL_PATH,
    PKI_OCSP_RESPONDER_CERT_PATH,
    PKI_ROOT_CA_CERT_PATH,
    PKI_TSA_CERT_PATH,
} from "../src/config/env.config.js";

const resolve = (value) => path.resolve(process.cwd(), value);
const status = getPadesStatus();
console.log(JSON.stringify({
    version: "1.0.0",
    ready: status.ready && [
        PKI_ROOT_CA_CERT_PATH,
        PKI_OCSP_RESPONDER_CERT_PATH,
        PKI_TSA_CERT_PATH,
        PKI_CRL_PATH,
    ].every((value) => fs.existsSync(resolve(value))),
    profile: "PAdES-LT",
    subfilter: status.subfilter,
    base_signature: "PAdES-B-T / CMS-CAdES / RFC3161",
    incremental_update: true,
    dss: true,
    vri: true,
    embedded_evidence: {
        signer_certificate: true,
        root_certificate: true,
        ocsp_responder_certificate: true,
        tsa_certificate: true,
        ocsp_response: true,
        crl: true,
    },
    offline_revocation_evidence: true,
    supported_levels: status.supported_levels,
    default_level: status.default_level,
    not_claimed: "PAdES-LTA",
}, null, 2));
