import path from "node:path";
import bcrypt from "bcryptjs";
import {
    atomicWriteJsonSync,
    readJsonFileSync,
} from "../utils/atomic-file.util.js";

const usersFilePath = path.resolve("src/data/users.json");
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ADMIN_ID_RE = /^ADMIN-[A-Z0-9][A-Z0-9-]{1,38}[A-Z0-9]$/;

function readUsers() {
    const users = readJsonFileSync(usersFilePath, []);
    if (!Array.isArray(users)) throw new Error("users.json must contain a JSON array");
    return users;
}

function writeUsers(users) {
    atomicWriteJsonSync(usersFilePath, users, { backup: true });
}

function normalizeEmail(value) {
    return String(value || "").trim().toLowerCase();
}

function normalizeAdminId(value) {
    return String(value || "").trim().toUpperCase();
}

function nextUserId(users) {
    return users.length === 0
        ? 1
        : Math.max(...users.map((user) => Number(user.id) || 0)) + 1;
}

function toSafeUser(user) {
    const { password_hash: _passwordHash, ...safe } = user;
    return safe;
}

export async function createAdminAccount({ adminId, fullName, email, password }) {
    const normalizedAdminId = normalizeAdminId(adminId);
    const cleanName = String(fullName || "").trim();
    const cleanEmail = normalizeEmail(email);

    if (!ADMIN_ID_RE.test(normalizedAdminId)) {
        throw new Error("admin_id must match ADMIN-XXX using uppercase letters, numbers and hyphens");
    }
    if (cleanName.length < 2) throw new Error("full name must be at least 2 characters");
    if (!EMAIL_RE.test(cleanEmail)) throw new Error("invalid email format");
    if (typeof password !== "string" || password.length < 8) {
        throw new Error("password must be at least 8 characters");
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const users = readUsers();
    if (users.some((user) => normalizeEmail(user.email) === cleanEmail)) {
        throw new Error("EMAIL_ALREADY_EXISTS");
    }
    if (users.some((user) => normalizeAdminId(user.admin_id) === normalizedAdminId)) {
        throw new Error("ADMIN_ID_ALREADY_EXISTS");
    }

    const admin = {
        id: nextUserId(users),
        admin_id: normalizedAdminId,
        full_name: cleanName,
        email: cleanEmail,
        password_hash: passwordHash,
        roles: ["admin"],
        status: "active",
        created_at: new Date().toISOString(),
        account_source: "admin-cli",
    };
    users.push(admin);
    writeUsers(users);
    return toSafeUser(admin);
}

export function listAccounts({ role = null } = {}) {
    return readUsers()
        .filter((user) => !role || (Array.isArray(user.roles) && user.roles.includes(role)))
        .map(toSafeUser);
}

export function setAccountEnabled({ email, enabled }) {
    const cleanEmail = normalizeEmail(email);
    const users = readUsers();
    const index = users.findIndex((user) => normalizeEmail(user.email) === cleanEmail);
    if (index < 0) throw new Error("ACCOUNT_NOT_FOUND");
    users[index] = {
        ...users[index],
        status: enabled ? "active" : "disabled",
        status_updated_at: new Date().toISOString(),
    };
    writeUsers(users);
    return toSafeUser(users[index]);
}
