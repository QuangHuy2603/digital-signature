import path from "node:path";
import {
    atomicWriteJsonSync,
    readJsonFileSync,
} from "../utils/atomic-file.util.js";

const dataFilePath = path.resolve("src/data/household_members.json");

function readAll() {
    const rows = readJsonFileSync(dataFilePath, []);
    if (!Array.isArray(rows)) {
        throw new Error("household_members.json must contain a JSON array");
    }
    return rows;
}

export async function saveMembersForDocument(documentId, members) {
    if (!Array.isArray(members) || members.length === 0) return [];
    const existing = readAll().filter((item) => item.document_id !== documentId);
    const createdAt = new Date().toISOString();
    const normalized = members.map((member, index) => ({
        id: `${documentId}-${index + 1}`,
        document_id: documentId,
        full_name: member.full_name || "",
        birth_date: member.birth_date || null,
        gender: member.gender || "Nam",
        personal_id: member.personal_id || "",
        relationship_to_head: member.relationship_to_head || null,
        created_at: createdAt,
    }));
    atomicWriteJsonSync(dataFilePath, [...existing, ...normalized], { backup: true });
    return normalized;
}

export async function getMembersForDocument(documentId) {
    return readAll().filter((item) => item.document_id === documentId);
}
