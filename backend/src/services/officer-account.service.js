import path from "node:path";
import bcrypt from "bcryptjs";
import {
    atomicWriteJsonSync,
    readJsonFileSync,
} from "../utils/atomic-file.util.js";

const usersFilePath = path.resolve("src/data/users.json");
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const OFFICER_ID_RE = /^OFFICER-[A-Z0-9][A-Z0-9-]{1,38}[A-Z0-9]$/;


function normalizeEmail(email) {
    return String(email || "").trim().toLowerCase();
}

export function normalizeOfficerId(officerId) {
    return String(officerId || "").trim().toUpperCase();
}

export function validateOfficerId(officerId) {
    const normalized = normalizeOfficerId(officerId);
    if (!OFFICER_ID_RE.test(normalized)) {
        throw new Error(
            "officer_id must match OFFICER-XXX using uppercase letters, numbers and hyphens"
        );
    }
    return normalized;
}

function readUsers() {
    const users = readJsonFileSync(usersFilePath, []);
    if (!Array.isArray(users)) {
        throw new Error("users.json must contain a JSON array");
    }
    return users;
}

function writeUsers(users) {
    atomicWriteJsonSync(usersFilePath, users, { backup: true });
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

export function listOfficerAccounts() {
    return readUsers()
        .filter((user) => Array.isArray(user.roles) && user.roles.includes("officer"))
        .map(toSafeUser);
}

export function findOfficerByOfficerId(officerId) {
    const normalized = normalizeOfficerId(officerId);
    const user = readUsers().find(
        (item) => normalizeOfficerId(item.officer_id) === normalized
    );
    return toSafeUser(user);
}

export function findOfficerByUserId(userId) {
    const user = readUsers().find(
        (item) => String(item.id) === String(userId) &&
            Array.isArray(item.roles) &&
            item.roles.includes("officer")
    );
    return toSafeUser(user);
}

export async function createOfficerAccount({
    officerId,
    fullName,
    email,
    password,
}) {
    const normalizedOfficerId = validateOfficerId(officerId);
    const cleanName = String(fullName || "").trim();
    const cleanEmail = normalizeEmail(email);

    if (cleanName.length < 2) {
        throw new Error("full name must be at least 2 characters");
    }
    if (!EMAIL_RE.test(cleanEmail)) {
        throw new Error("invalid email format");
    }
    if (typeof password !== "string" || password.length < 8) {
        throw new Error("password must be at least 8 characters");
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const users = readUsers();

    if (users.some((user) => normalizeEmail(user.email) === cleanEmail)) {
        throw new Error("EMAIL_ALREADY_EXISTS");
    }
    if (users.some(
        (user) => normalizeOfficerId(user.officer_id) === normalizedOfficerId
    )) {
        throw new Error("OFFICER_ID_ALREADY_EXISTS");
    }

    const officer = {
        id: nextUserId(users),
        officer_id: normalizedOfficerId,
        full_name: cleanName,
        email: cleanEmail,
        password_hash: passwordHash,
        roles: ["officer"],
        status: "active",
        active_certificate_id: null,
        local_certificate_id: null,
        remote_certificate_id: null,
        certificate_status: "not_issued",
        created_at: new Date().toISOString(),
    };

    users.push(officer);
    writeUsers(users);
    return toSafeUser(officer);
}

export function assignActiveCertificate({
    officerId,
    certificateId,
    certificateStatus = "active",
}) {
    const normalizedOfficerId = validateOfficerId(officerId);
    const users = readUsers();
    const index = users.findIndex(
        (user) => normalizeOfficerId(user.officer_id) === normalizedOfficerId
    );

    if (index === -1) {
        throw new Error("OFFICER_NOT_FOUND");
    }
    if (!Array.isArray(users[index].roles) ||
        !users[index].roles.includes("officer")) {
        throw new Error("USER_IS_NOT_OFFICER");
    }

    users[index] = {
        ...users[index],
        active_certificate_id: certificateId || null,
        local_certificate_id: certificateId || null,
        certificate_status: certificateStatus,
        certificate_updated_at: new Date().toISOString(),
    };

    writeUsers(users);
    return toSafeUser(users[index]);
}


export function assignSigningCertificate({
    officerId,
    certificateId,
    signingMethod,
}) {
    const normalizedOfficerId = validateOfficerId(officerId);
    const method = String(signingMethod || "").trim().toLowerCase();
    if (!new Set(["local", "remote"]).has(method)) {
        throw new Error("signingMethod must be local or remote");
    }
    const users = readUsers();
    const index = users.findIndex(
        (user) => normalizeOfficerId(user.officer_id) === normalizedOfficerId
    );
    if (index === -1) throw new Error("OFFICER_NOT_FOUND");
    if (!Array.isArray(users[index].roles) || !users[index].roles.includes("officer")) {
        throw new Error("USER_IS_NOT_OFFICER");
    }
    const field = method === "remote" ? "remote_certificate_id" : "local_certificate_id";
    users[index] = {
        ...users[index],
        [field]: certificateId || null,
        certificate_updated_at: new Date().toISOString(),
    };
    // Keep active_certificate_id synchronized with the local/default signing identity.
    if (method === "local" && certificateId) {
        users[index].active_certificate_id = certificateId;
        users[index].certificate_status = "active";
    }
    writeUsers(users);
    return toSafeUser(users[index]);
}

export function ensureSigningCertificateBindings() {
    const users = readUsers();
    let changed = false;
    for (let index = 0; index < users.length; index += 1) {
        const user = users[index];
        if (!Array.isArray(user.roles) || !user.roles.includes("officer")) continue;
        if (!("local_certificate_id" in user)) {
            users[index].local_certificate_id = user.active_certificate_id || null;
            changed = true;
        }
        if (!("remote_certificate_id" in user)) {
            users[index].remote_certificate_id = null;
            changed = true;
        }
    }
    if (changed) writeUsers(users);
    return users
        .filter((user) => Array.isArray(user.roles) && user.roles.includes("officer"))
        .map(toSafeUser);
}

export function ensureLegacyOfficerIdentity() {
    const users = readUsers();
    const index = users.findIndex(
        (user) => Array.isArray(user.roles) && user.roles.includes("officer")
    );
    if (index === -1) return null;

    let changed = false;
    if (!users[index].officer_id) {
        users[index].officer_id = "OFFICER-001";
        changed = true;
    }
    if (!("active_certificate_id" in users[index])) {
        users[index].active_certificate_id = null;
        changed = true;
    }
    if (!users[index].certificate_status) {
        users[index].certificate_status = "not_issued";
        changed = true;
    }
    if (!("local_certificate_id" in users[index])) {
        users[index].local_certificate_id = users[index].active_certificate_id || null;
        changed = true;
    }
    if (!("remote_certificate_id" in users[index])) {
        users[index].remote_certificate_id = null;
        changed = true;
    }

    if (changed) writeUsers(users);
    return toSafeUser(users[index]);
}
