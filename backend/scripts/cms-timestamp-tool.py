#!/usr/bin/env python3
"""Small vendored ASN.1 helper for PAdES-B-T CMS unsigned timestamps."""
import argparse
import json
import pathlib
import sys

VENDOR = pathlib.Path(__file__).resolve().parent / "vendor"
sys.path.insert(0, str(VENDOR))

from asn1crypto import cms, tsp  # noqa: E402

OID_SIGNATURE_TIMESTAMP = "1.2.840.113549.1.9.16.2.14"


def load_cms(path):
    return cms.ContentInfo.load(pathlib.Path(path).read_bytes())


def signer_info(content_info):
    infos = content_info["content"]["signer_infos"]
    if len(infos) != 1:
        raise ValueError(f"Expected one CMS signer, got {len(infos)}")
    return infos[0]


def extract_signature(args):
    ci = load_cms(args.cms)
    pathlib.Path(args.output).write_bytes(signer_info(ci)["signature"].native)


def attach_timestamp(args):
    ci = load_cms(args.cms)
    si = signer_info(ci)
    ts_resp = tsp.TimeStampResp.load(pathlib.Path(args.tsr).read_bytes())
    token = ts_resp["time_stamp_token"]
    if token.native is None:
        raise ValueError("Timestamp response does not contain a TimeStampToken")
    attrs = si["unsigned_attrs"]
    if attrs.native is None:
        attrs = cms.CMSAttributes()
    kept = cms.CMSAttributes([
        attr for attr in attrs if attr["type"].dotted != OID_SIGNATURE_TIMESTAMP
    ])
    kept.append(cms.CMSAttribute({
        "type": OID_SIGNATURE_TIMESTAMP,
        "values": [token],
    }))
    si["unsigned_attrs"] = kept
    pathlib.Path(args.output).write_bytes(ci.dump())


def extract_timestamp(args):
    ci = load_cms(args.cms)
    attrs = signer_info(ci)["unsigned_attrs"]
    if attrs.native is None:
        raise ValueError("CMS has no unsigned attributes")
    for attr in attrs:
        if attr["type"].dotted == OID_SIGNATURE_TIMESTAMP:
            pathlib.Path(args.output).write_bytes(attr["values"][0].dump())
            return
    raise ValueError("signatureTimeStampToken attribute not found")


def inspect(args):
    ci = load_cms(args.cms)
    si = signer_info(ci)
    signed = []
    if si["signed_attrs"].native is not None:
        signed = [a["type"].dotted for a in si["signed_attrs"]]
    unsigned = []
    if si["unsigned_attrs"].native is not None:
        unsigned = [a["type"].dotted for a in si["unsigned_attrs"]]
    result = {
        "signature_length": len(si["signature"].native),
        "signed_attribute_oids": signed,
        "unsigned_attribute_oids": unsigned,
        "has_signing_certificate_v2": "1.2.840.113549.1.9.16.2.47" in signed,
        "has_signature_timestamp": OID_SIGNATURE_TIMESTAMP in unsigned,
    }
    print(json.dumps(result, indent=2))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("extract-signature")
    a.add_argument("--cms", required=True); a.add_argument("--output", required=True)
    a.set_defaults(func=extract_signature)
    a = sub.add_parser("attach-timestamp")
    a.add_argument("--cms", required=True); a.add_argument("--tsr", required=True); a.add_argument("--output", required=True)
    a.set_defaults(func=attach_timestamp)
    a = sub.add_parser("extract-timestamp")
    a.add_argument("--cms", required=True); a.add_argument("--output", required=True)
    a.set_defaults(func=extract_timestamp)
    a = sub.add_parser("inspect")
    a.add_argument("--cms", required=True); a.set_defaults(func=inspect)
    args = p.parse_args(); args.func(args)

if __name__ == "__main__":
    main()
