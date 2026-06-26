import { NETWORK_ZONES } from "../config/network.config.js";

export const getNetworkModel = (req, res) => {
    res.json({
        model: "public-application-pki-data-zones",
        zones: NETWORK_ZONES,
        request_zone: req.networkZone || null,
        rules: [
            "Public Zone exposes verification and Test PKI status entrypoints.",
            "Application Zone handles document business flow and access control.",
            "PKI Zone contains X.509, PAdES, OCSP, CRL and TSA services.",
            "Data Zone is never exposed as a direct HTTP route."
        ]
    });
};
