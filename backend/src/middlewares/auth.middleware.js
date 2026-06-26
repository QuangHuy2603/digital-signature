/**
 * auth.middleware.js - JWT authentication middleware.
 *
 * Reads JWT from (in order):
 *   1. httpOnly cookie named "token" (preferred, XSS-safe)
 *   2. Authorization: Bearer <token> header (backward compatibility)
 */
import jwt from "jsonwebtoken";
import { JWT_SECRET } from "../config/env.config.js";

/**
 * Extract JWT token from request.
 * Priority: cookie > Authorization header.
 */
function extractToken(req) {
    // 1. httpOnly cookie (preferred)
    if (req.cookies && req.cookies.token) {
        return req.cookies.token;
    }
    // 2. Authorization header (backward compatibility)
    const header = req.headers.authorization;
    if (header && header.startsWith("Bearer ")) {
        return header.slice(7);
    }
    return null;
}

/**
 * Parse and verify JWT, return user object or null.
 */
function verifyToken(token) {
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        return {
            id: payload.id,
            email: payload.email,
            full_name: payload.full_name,
            roles: payload.roles || [],
            officer_id: payload.officer_id || null,
            citizen_id: payload.citizen_id || null,
            citizen_software_certificate_id: payload.citizen_software_certificate_id || null,
            citizen_pkcs11_certificate_id: payload.citizen_pkcs11_certificate_id || null,
            active_citizen_certificate_id: payload.active_citizen_certificate_id || null,
            active_certificate_id: payload.active_certificate_id || null,
            local_certificate_id: payload.local_certificate_id || null,
            remote_certificate_id: payload.remote_certificate_id || null,
        };
    } catch {
        return null;
    }
}

/** Mandatory authentication: returns 401 if token is missing or invalid */
export const authenticate = (req, res, next) => {
    const token = extractToken(req);
    if (!token) {
        return res.status(401).json({ message: "Authentication required" });
    }

    const user = verifyToken(token);
    if (!user) {
        return res.status(401).json({ message: "Invalid or expired token" });
    }

    req.user = user;
    next();
};

/** Optional authentication: attaches user if valid, continues as anonymous otherwise */
export const optionalAuthenticate = (req, _res, next) => {
    const token = extractToken(req);
    if (token) {
        const user = verifyToken(token);
        if (user) {
            req.user = user;
        }
    }
    next();
};
