import path from "node:path";
import { fileURLToPath } from "node:url";
import {
    atomicWriteJsonSync,
    readJsonFileSync,
} from "../utils/atomic-file.util.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataFilePath = path.resolve(__dirname, "../data/previews.json");

function readPreviews() {
    const previews = readJsonFileSync(dataFilePath, []);
    if (!Array.isArray(previews)) {
        throw new Error("previews.json must contain a JSON array");
    }
    return previews;
}

export function savePreview(preview) {
    const previews = readPreviews();
    const index = previews.findIndex((item) => item.preview_id === preview.preview_id);
    if (index >= 0) previews[index] = preview;
    else previews.push(preview);
    atomicWriteJsonSync(dataFilePath, previews, { backup: true });
    return preview;
}

export function findPreviewById(previewId) {
    return readPreviews().find((preview) => preview.preview_id === previewId) || null;
}
