import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createPadesLtFixture } from "../tests/helpers/pades-fixture.js";
import { extractPadesContainer } from "../src/crypto/pades.service.js";
import { verifyPadesLtEvidence } from "../src/crypto/pades-lt.service.js";

process.env.SIGNING_PROVIDER = "file";
process.env.SOFTHSM_RUNTIME_PROBE = "false";

function replaceAscii(buffer, from, to) {
    if (Buffer.byteLength(from, "ascii") !== Buffer.byteLength(to, "ascii")) {
        throw new Error("Attack replacement must preserve byte length");
    }
    const output = Buffer.from(buffer);
    const index = output.indexOf(Buffer.from(from, "ascii"));
    if (index < 0) throw new Error(`Marker not found: ${from}`);
    Buffer.from(to, "ascii").copy(output, index);
    return output;
}

function flipEmbedded(buffer, needle, offset = 16) {
    const output = Buffer.from(buffer);
    const index = output.indexOf(needle);
    if (index < 0) throw new Error("Embedded evidence was not found");
    output[index + Math.min(offset, needle.length - 1)] ^= 0x01;
    return output;
}

function readCrlDer() {
    const result = spawnSync(process.env.OPENSSL_BIN || "openssl", [
        "crl", "-in", path.resolve(process.cwd(), "../pki/root-ca/root-ca.crl"), "-outform", "DER",
    ], { encoding: null, windowsHide: true });
    if (result.status !== 0) throw new Error(String(result.stderr || "Unable to convert CRL"));
    return Buffer.from(result.stdout);
}

let fixture;
try {
    fixture = await createPadesLtFixture();
    const verify = (buffer, timestamp = fixture.verification.timestamp) => {
        const extracted = extractPadesContainer(buffer);
        return verifyPadesLtEvidence({
            pdfBuffer: buffer,
            cmsDer: extracted.cmsDer,
            signedRevisionLength: extracted.signedRevisionLength,
            expectedFingerprint: fixture.certificateRecord.fingerprint_sha256,
            signatureTimestamp: timestamp,
        });
    };
    const signerCertificate = new crypto.X509Certificate(
        fs.readFileSync(path.resolve(process.cwd(), fixture.certificateRecord.certificate_path))
    );
    const ocsp = Buffer.from(fixture.ocspEvidence.response_der_base64, "base64");
    const crl = readCrlDer();
    const key = fixture.ltEvidence.vri_key_sha1;
    const replacementKey = `${key[0] === "A" ? "B" : "A"}${key.slice(1)}`;

    const attacks = [
        {
            number: 37,
            title: "REMOVE DSS FROM PADES-LT",
            result: verify(replaceAscii(fixture.signedPdfBytes, "/DSS", "/DSX")),
            expected: ["PADES_DSS_MISSING"],
        },
        {
            number: 38,
            title: "REMOVE VRI FROM DSS",
            result: verify(replaceAscii(fixture.signedPdfBytes, "/VRI", "/VRX")),
            expected: ["PADES_VRI_BINDING_INVALID", "PADES_VRI_MISSING"],
        },
        {
            number: 39,
            title: "TAMPER EMBEDDED SIGNER CERTIFICATE",
            result: verify(flipEmbedded(fixture.signedPdfBytes, signerCertificate.raw, 24)),
            expectedPrefix: "PADES_EMBEDDED_",
        },
        {
            number: 40,
            title: "TAMPER EMBEDDED OCSP RESPONSE",
            result: verify(flipEmbedded(fixture.signedPdfBytes, ocsp, 32)),
            expected: ["PADES_EMBEDDED_OCSP_INVALID"],
        },
        {
            number: 41,
            title: "TAMPER EMBEDDED CRL",
            result: verify(flipEmbedded(fixture.signedPdfBytes, crl, 24)),
            expected: ["PADES_EMBEDDED_CRL_INVALID"],
        },
        {
            number: 42,
            title: "SUBSTITUTE VRI SIGNATURE BINDING",
            result: verify(replaceAscii(fixture.signedPdfBytes, `/${key}`, `/${replacementKey}`)),
            expected: ["PADES_VRI_BINDING_INVALID"],
        },
        {
            number: 43,
            title: "APPEND UNAUTHORISED PDF REVISION BYTES",
            result: verify(Buffer.concat([fixture.signedPdfBytes, Buffer.from("UNAUTHORISED", "ascii")])),
            expected: ["PADES_LT_INCREMENTAL_UPDATE_INVALID"],
        },
        {
            number: 44,
            title: "USE VALIDATION EVIDENCE OUTSIDE SIGNING-TIME WINDOW",
            result: verify(fixture.signedPdfBytes, "2000-01-01T00:00:00.000Z"),
            expected: ["PADES_LT_EVIDENCE_TIME_INVALID"],
        },
    ];

    let failed = false;
    for (const attack of attacks) {
        const rejected = attack.result.valid === false;
        const reasonMatches = attack.expected
            ? attack.expected.includes(attack.result.reason)
            : String(attack.result.reason || "").startsWith(attack.expectedPrefix || "");
        const passed = rejected && reasonMatches;
        console.log(`\n=== ATTACK ${attack.number} - ${attack.title} ===`);
        console.log(`Result: ${rejected ? "REJECTED" : "ACCEPTED"}`);
        console.log(`Reason: ${attack.result.reason}`);
        console.log(`Test result: ${passed ? "PASS" : "FAIL"}`);
        if (!passed) failed = true;
    }
    if (failed) process.exitCode = 2;
} catch (error) {
    console.error(`[PADES_LT_ATTACKS_FAILED] ${error.message}`);
    process.exitCode = 2;
} finally {
    fixture?.cleanup();
}
