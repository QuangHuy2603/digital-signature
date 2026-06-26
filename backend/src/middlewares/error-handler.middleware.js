/**
 * error-handler.middleware.js - Global error handler.
 *
 * In production: returns generic error messages to avoid leaking internals.
 * In development: returns full error details for debugging.
 */

import { IS_DEV } from "../config/env.config.js";

/**
 * Global error handler middleware.
 * Must be registered AFTER all routes.
 */
export function errorHandler(err, req, res, _next) {
    // Log the full error server-side regardless of environment
    console.error(`[error] ${req.method} ${req.path}:`, err);

    // Determine status code
    const statusCode = err.statusCode || err.status || 500;

    // In production, hide internal details for 500 errors
    if (!IS_DEV && statusCode >= 500) {
        return res.status(500).json({
            message: "Internal server error",
            ...(IS_DEV && { stack: err.stack })
        });
    }

    // Client errors (4xx) and dev mode: show the message
    res.status(statusCode).json({
        message: err.message || "An error occurred",
        ...(IS_DEV && { stack: err.stack })
    });
}

/**
 * 404 handler for unmatched routes.
 */
export function notFoundHandler(req, res) {
    res.status(404).json({
        message: `Route not found: ${req.method} ${req.path}`
    });
}
