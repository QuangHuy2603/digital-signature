import path from "node:path";
import { fileURLToPath } from "node:url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import {
    JWT_SECRET,
    JWT_EXPIRES_IN,
    IS_DEV,
} from "../config/env.config.js";
import {
    atomicWriteJsonSync,
    readJsonFileSync,
} from "../utils/atomic-file.util.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDirectory = path.resolve(__dirname, "../data");
const dataFilePath = path.join(dataDirectory, "users.json");
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function normalizeEmail(email) {
    return typeof email === "string" ? email.trim().toLowerCase() : "";
}

function validateRegistrationInput({ full_name, email, password }) {
    if (!full_name || typeof full_name !== "string" || full_name.trim().length < 2) {
        throw new Error("Full name must be at least 2 characters");
    }
    if (!email || !EMAIL_RE.test(email)) {
        throw new Error("Invalid email format");
    }
    if (!password || typeof password !== "string" || password.length < 6) {
        throw new Error("Password must be at least 6 characters");
    }
}

function readUsersFile() {
    const users = readJsonFileSync(dataFilePath, []);
    if (!Array.isArray(users)) {
        throw new Error("users.json must contain a JSON array");
    }
    return users;
}

function writeUsersFile(users) {
    atomicWriteJsonSync(dataFilePath, users, { backup: true });
}

function nextUserId(users) {
    return users.length === 0
        ? 1
        : Math.max(...users.map((user) => Number(user.id) || 0)) + 1;
}

function toSafeUser(user) {
    if (!user) return null;
    const { password_hash: _passwordHash, ...safe } = user;
    return safe;
}

function buildTokenPayload(user) {
    return {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        roles: user.roles,
        officer_id: user.officer_id || null,
        citizen_id: user.citizen_id || null,
        admin_id: user.admin_id || null,
        citizen_software_certificate_id: user.citizen_software_certificate_id || null,
        citizen_pkcs11_certificate_id: user.citizen_pkcs11_certificate_id || null,
        active_citizen_certificate_id: user.active_citizen_certificate_id || null,
        active_certificate_id: user.active_certificate_id || null,
        local_certificate_id: user.local_certificate_id || user.active_certificate_id || null,
        remote_certificate_id: user.remote_certificate_id || null,
    };
}

export async function register({ full_name, email, password }) {
    const cleanName = full_name?.trim();
    const cleanEmail = normalizeEmail(email);
    validateRegistrationInput({ full_name: cleanName, email: cleanEmail, password });

    const passwordHash = await bcrypt.hash(password, 10);
    const users = readUsersFile();
    if (users.some((user) => normalizeEmail(user.email) === cleanEmail)) {
        throw new Error("Email already registered");
    }

    const assignedId = nextUserId(users);
    const newUser = {
        id: assignedId,
        citizen_id: `CITIZEN-${String(assignedId).padStart(3, "0")}`,
        full_name: cleanName,
        email: cleanEmail,
        password_hash: passwordHash,
        roles: ["citizen"],
        status: "active",
        created_at: new Date().toISOString(),
        account_source: "self-registration",
    };

    users.push(newUser);
    writeUsersFile(users);
    return toSafeUser(newUser);
}

export async function login({ email, password }) {
    const cleanEmail = normalizeEmail(email);
    const users = readUsersFile();
    const user = users.find((item) => normalizeEmail(item.email) === cleanEmail);

    if (!user) throw new Error("Invalid email or password");
    if (user.status === "locked" || user.status === "disabled") {
        throw new Error("Account is disabled");
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) throw new Error("Invalid email or password");

    const token = jwt.sign(buildTokenPayload(user), JWT_SECRET, {
        expiresIn: JWT_EXPIRES_IN,
    });

    return {
        token,
        user: {
            ...toSafeUser(user),
            local_certificate_id: user.local_certificate_id || user.active_certificate_id || null,
        },
    };
}

export async function getUserById(id) {
    const user = readUsersFile().find(
        (item) => item.id === Number(id) || String(item.id) === String(id)
    );
    return toSafeUser(user);
}

export async function seedDefaultUsers() {
    if (!IS_DEV) return;
    const initialUsers = readUsersFile();
    if (initialUsers.length > 0) return;

    const passwordHash = await bcrypt.hash("officer123", 10);
    const users = readUsersFile();
    if (users.length > 0) return;

    users.push({
        id: 1,
        officer_id: "OFFICER-001",
        full_name: "Can bo Nguyen",
        email: "officer@test.com",
        password_hash: passwordHash,
        roles: ["officer"],
        active_certificate_id: null,
        local_certificate_id: null,
        remote_certificate_id: null,
        certificate_status: "not_issued",
        status: "active",
        created_at: new Date().toISOString(),
        account_source: "demo-seed",
    });
    writeUsersFile(users);
}

export function listUsers() {
    return readUsersFile().map(toSafeUser);
}

export function updateUser(userId, patch = {}) {
    const users = readUsersFile();
    const index = users.findIndex((user) => String(user.id) === String(userId));
    if (index < 0) return null;
    users[index] = { ...users[index], ...patch };
    writeUsersFile(users);
    return toSafeUser(users[index]);
}

export async function ensureDemoAdminUser() {
    if (!IS_DEV) return null;
    const users = readUsersFile();
    const existing = users.find((item) => normalizeEmail(item.email) === "admin@test.com");
    if (existing) {
        const needsRole = !Array.isArray(existing.roles) || !existing.roles.includes("admin");
        if (needsRole) {
            existing.roles = Array.from(new Set([...(existing.roles || []), "admin"]));
            writeUsersFile(users);
        }
        return toSafeUser(existing);
    }

    const passwordHash = await bcrypt.hash("admin123", 10);
    const refreshed = readUsersFile();
    const duplicate = refreshed.find((item) => normalizeEmail(item.email) === "admin@test.com");
    if (duplicate) return toSafeUser(duplicate);

    const admin = {
        id: nextUserId(refreshed),
        admin_id: "ADMIN-001",
        full_name: "Quan tri PKI",
        email: "admin@test.com",
        password_hash: passwordHash,
        roles: ["admin"],
        status: "active",
        created_at: new Date().toISOString(),
        account_source: "demo-seed",
    };
    refreshed.push(admin);
    writeUsersFile(refreshed);
    return toSafeUser(admin);
}

export function findCitizenByCitizenId(citizenId) {
    const user = readUsersFile().find(
        (item) => String(item.citizen_id || "") === String(citizenId || "")
    );
    return toSafeUser(user);
}
