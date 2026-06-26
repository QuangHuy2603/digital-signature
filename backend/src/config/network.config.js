export const NETWORK_ZONES = {
    PUBLIC: {
        name: "Public Zone",
        code: "public",
        purpose: "External entrypoint for citizens and QR verification pages",
        path_prefixes: ["/api/public"]
    },
    APPLICATION: {
        name: "Application Zone",
        code: "application",
        purpose: "Business APIs behind the public gateway",
        path_prefixes: ["/api/app", "/api/documents"]
    },
    PKI: {
        name: "PKI Zone",
        code: "pki",
        purpose: "X.509, PAdES, OCSP, CRL and TSA trust services",
        path_prefixes: ["/api/public/pki"]
    },
    DATA: {
        name: "Data Zone",
        code: "data",
        purpose: "Document metadata, upload storage and audit records",
        path_prefixes: ["backend/src/data", "backend/src/uploads"]
    }
};
