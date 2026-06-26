import path from "node:path";
import {
    atomicWriteJsonSync,
    readJsonFileSync,
} from "../utils/atomic-file.util.js";

const jsonFilePath = path.resolve("src/data/documents.json");

function readDocuments() {
    const documents = readJsonFileSync(jsonFilePath, []);
    if (!Array.isArray(documents)) {
        throw new Error("documents.json must contain a JSON array");
    }
    return documents;
}

function writeDocuments(documents) {
    atomicWriteJsonSync(jsonFilePath, documents, { backup: true });
}

export function findDocumentById(documentId) {
    return readDocuments().find((doc) => doc.document_id === documentId) || null;
}

export function saveDocument(documentData) {
    const documents = readDocuments();
    if (documents.some((doc) => doc.document_id === documentData.document_id)) {
        throw new Error(`Document ${documentData.document_id} already exists`);
    }
    documents.push(documentData);
    writeDocuments(documents);
    return documentData;
}

export function updateDocument(documentId, updatedData) {
    const documents = readDocuments();
    const index = documents.findIndex((doc) => doc.document_id === documentId);
    if (index === -1) return null;
    documents[index] = { ...documents[index], ...updatedData };
    writeDocuments(documents);
    return documents[index];
}

export function listDocuments() {
    return readDocuments();
}
