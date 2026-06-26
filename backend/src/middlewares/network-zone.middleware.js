/** Attach a logical network zone to requests. */
export const attachNetworkZone = (zone) => (req, res, next) => {
    req.networkZone = zone;
    res.setHeader("X-Network-Zone", zone.code);
    next();
};

/** Basic response-hardening headers. */
export const securityHeaders = (_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cache-Control", "no-store");
    next();
};
