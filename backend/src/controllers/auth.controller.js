import { register, login, getUserById } from "../services/auth.service.js";
import { IS_DEV } from "../config/env.config.js";

/** Cookie options for JWT */
const COOKIE_OPTIONS = {
    httpOnly: true,        // Not accessible via JavaScript (XSS protection)
    secure: !IS_DEV,       // HTTPS only in production
    sameSite: "strict",    // CSRF protection
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: "/"
};

/**
 * Safe error messages for auth endpoints.
 * Maps internal error strings to user-safe messages.
 */
const SAFE_AUTH_ERRORS = {
    "Email already registered": "Email already registered",
    "Invalid email or password": "Invalid email or password",
    "Account is locked": "Account is locked. Please contact support.",
};

function getSafeAuthError(error) {
    // Return safe message if it's a known error
    if (SAFE_AUTH_ERRORS[error.message]) {
        return SAFE_AUTH_ERRORS[error.message];
    }
    // In dev, return full error; in prod, generic message
    return IS_DEV ? error.message : "An error occurred during authentication";
}

export const registerHandler = async (req, res) => {
    try {
        const { full_name, email, password } = req.body;

        if (!full_name || !email || !password) {
            return res.status(400).json({ message: "full_name, email, password are required" });
        }

        if (password.length < 6) {
            return res.status(400).json({ message: "Password must be at least 6 characters" });
        }

        const result = await register({ full_name, email, password });
        res.status(201).json({ message: "Registered successfully", data: result });
    } catch (error) {
        const status = error.message.includes("already registered") ? 409 : 500;
        res.status(status).json({ message: getSafeAuthError(error) });
    }
};

export const loginHandler = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: "email and password are required" });
        }

        const result = await login({ email, password });

        // Set JWT in httpOnly cookie (not accessible via JS = XSS protection)
        res.cookie("token", result.token, COOKIE_OPTIONS);

        // Also return token in response body for backward compatibility
        res.json({ message: "Login successful", data: result });
    } catch (error) {
        res.status(401).json({ message: getSafeAuthError(error) });
    }
};

export const logoutHandler = (_req, res) => {
    res.clearCookie("token", { path: "/" });
    res.json({ message: "Logged out successfully" });
};

export const meHandler = async (req, res) => {
    try {
        const user = await getUserById(req.user.id);
        if (!user) return res.status(404).json({ message: "User not found" });
        res.json({ data: user });
    } catch (error) {
        res.status(500).json({ message: "Failed to fetch user" });
    }
};
