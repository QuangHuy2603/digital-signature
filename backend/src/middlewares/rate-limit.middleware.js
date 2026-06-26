/**
 * rate-limit.middleware.js - Rate limiting middleware to prevent brute force and DoS.
 *
 * Provides:
 *   - `globalLimiter`: general API rate limit
 *   - `authLimiter`: stricter limit for login/register endpoints
 *   - `verifyLimiter`: limit for public verification endpoints
 */

import rateLimit from "express-rate-limit";

/**
 * General API rate limiter: 100 requests per 15 minutes per IP.
 */
export const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Too many requests, please try again later.",
        retryAfter: "15 minutes"
    }
});

/**
 * Auth rate limiter: 10 login/register attempts per 15 minutes per IP.
 * Prevents brute force attacks on authentication endpoints.
 */
export const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Too many authentication attempts, please try again later.",
        retryAfter: "15 minutes"
    }
});

/**
 * Verification rate limiter: 30 requests per 15 minutes per IP.
 * Prevents abuse of public verification endpoints.
 */
export const verifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Too many verification requests, please try again later.",
        retryAfter: "15 minutes"
    }
});
