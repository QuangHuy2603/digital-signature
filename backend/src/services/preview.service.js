import crypto from "crypto";
import fs from "fs";
import path from "path";
import { PDFDocument, rgb } from "pdf-lib";
import fontkit from "@pdf-lib/fontkit";
import {
    savePreview,
    findPreviewById
} from "../repositories/preview.repository.js";
import { createDocumentFolder }
from "../utils/storage.util.js";

const TEMPLATE_PATH = path.resolve(
    "src/templates/CT01.pdf"
);

const generateDocumentId = () => {

    return `HS-${new Date().getFullYear()}-${crypto.randomUUID()
        .slice(0, 8)
        .toUpperCase()}`;

};


export const createPreviewDocument = async (data) => {

    const previewId = crypto.randomUUID();

    const documentId = generateDocumentId();

    const documentFolder =
        createDocumentFolder(documentId);

    const previewPath = path.join(
        documentFolder,
        "preview.pdf"
    );

    // LOAD TEMPLATE
    const templateBytes = fs.readFileSync(TEMPLATE_PATH);
    const pdfDoc = await PDFDocument.load(templateBytes);
    
    pdfDoc.registerFontkit(fontkit);
    const fontBytes = fs.readFileSync("src/fonts/Roboto-Regular.ttf");
    const font = await pdfDoc.embedFont(fontBytes);

    const pages = pdfDoc.getPages();
    const page = pages[0];

    // 2. KHỞI TẠO ĐỐI TƯỢNG FORM TƯƠNG TÁC
    const form = pdfDoc.getForm();

    // Cấu hình định dạng chữ mặc định khi người dùng gõ vào ô
    const formFieldConfig = {
        font: font,
        size: 10
    };

    // ===== DRAW DATA =====
    const textConfig = {
        size: 10,
        font: font,
        color: rgb(0, 0, 0) // Màu đen mặc định rõ ràng
    };
  // Kính gửi: (Nằm ngay sau dấu hai chấm của chữ Kính gửi)
    page.drawText(data.office_name || "", { ...textConfig, x: 175, y: 602 });

    // 1. Họ, chữ đệm và tên:
    page.drawText(data.full_name || "", { ...textConfig, x: 181, y: 580 });

    // 2. Ngày, tháng, năm sinh: & 3. Giới tính: )
    const birthStr = `${data.birth_day || ""}/${data.birth_month || ""}/${data.birth_year || ""}`;
    page.drawText(birthStr, { ...textConfig, x: 200, y: 560 });
    // Giới tính (Nằm lùi sang phải, ngay trên dấu chấm của mục Giới tính)
    page.drawText(data.gender || "", { ...textConfig, x: 465, y: 560 });

    // 4. Số định danh cá nhân: (Xếp vào các ô vuông nhỏ)
    // Ô đầu tiên bắt đầu từ X = 142, mỗi ô tiếp theo dịch chuyển đúng 19.6 pixel
    const citizenId = (data.citizen_id || "").slice(0, 12);
    for (let i = 0; i < citizenId.length; i++) {
        page.drawText(citizenId[i], {
            font,
            size: 11,
            color: rgb(0, 0, 0),
            x: 257 + (i * 21.6),
            y: 533 // Tọa độ Y chuẩn bám lọt lòng bên trong các ô vuông
        });
    }

    // 5. Số điện thoại liên hệ: & 6. Email:
    page.drawText(data.phone || "", { ...textConfig, x: 190, y: 510 });
    page.drawText(data.email || "", { ...textConfig, x: 400, y: 510 });

    // 7. Họ, chữ đệm và tên chủ hộ: & 8. Mối quan hệ với chủ hộ: 
    page.drawText(data.householder_name || "", { ...textConfig, x: 219, y: 490 });
    page.drawText(data.relationship || "", { ...textConfig, x: 453, y: 490 });

    // 9. Số định danh cá nhân của chủ hộ: (Xếp vào các ô vuông hàng dưới)
    // Hàng ô vuông của chủ hộ dịch sang phải nhiều hơn, bắt đầu từ X = 180, khoảng cách ô vẫn là 19.6
    const householderId = (data.householder_id || "").slice(0, 12);
    for (let i = 0; i < householderId.length; i++) {
        page.drawText(householderId[i], {
            font,
            size: 11,
            color: rgb(0, 0, 0),
            x: 279 + (i * 20.6),
            y: 460
        });
    }

    // 10. Nội dung đề nghị: (Nằm ngay trên dòng chấm trống đầu tiên dưới tiêu đề mục 10)
    page.drawText(data.request_content || "", {
        ...textConfig,
        x: 200,
        y: 440,
        maxWidth: 500,
        lineHeight: 16
    });

    // 11. Thành viên trong hộ gia đình cùng thay đổi
    // rowStartY: hàng dữ liệu ĐẦU TIÊN (không phải header bảng trong template)
    // Nếu vẫn lệch, điều chỉnh rowStartY: tăng → lên cao, giảm → xuống thấp hơn
    const members = Array.isArray(data.members) ? data.members : [];
    const rowStartY = 313;
    const rowHeight  = 20.2;
    const colX = { stt: 83, full_name: 110, birth_date: 248, gender: 325, personal_id: 372, relationship: 470 };

    // Chuyển yyyy-mm-dd → dd/mm/yyyy để hiển thị trong PDF
    const isoToDisplay = (d) => {
        if (!d) return "";
        const p = d.split("-");
        if (p.length !== 3) return d;
        return `${p[2].padStart(2, "0")}/${p[1].padStart(2, "0")}/${p[0]}`;
    };

    members.slice(0, 8).forEach((m, i) => {
        const y = rowStartY - i * rowHeight;
        page.drawText(String(i + 1), { ...textConfig, x: colX.stt, y });
        page.drawText(m.full_name || "", { ...textConfig, x: colX.full_name, y, maxWidth: 170 });
        page.drawText(isoToDisplay(m.birth_date), { ...textConfig, x: colX.birth_date, y, maxWidth: 84 });
        page.drawText(m.gender || "", { ...textConfig, x: colX.gender, y, maxWidth: 36 });
        page.drawText(m.personal_id || "", { ...textConfig, x: colX.personal_id, y, maxWidth: 86 });
        page.drawText(m.relationship_to_head || "", { ...textConfig, x: colX.relationship, y, maxWidth: 100 });
    });

    //------------------------------------------
    const pdfBytes = await pdfDoc.save();

    fs.writeFileSync(
        previewPath,
        pdfBytes
    );
    const expiredAt = new Date(
    Date.now() + 15 * 60 * 1000
);

await savePreview({

    preview_id: previewId,

    document_id: documentId,

    owner_id: data.owner_id || null,

    preview_path: previewPath,

    form_data: data,

    expired_at: expiredAt

});

    return {

        preview_id: previewId,

        document_id: documentId,

        preview_url:
            `/api/app/documents/previews/${previewId}/file`,

        file_path: previewPath,

        form_data: data

    };
};
export const getPreviewById = async (previewId) => {
     return await findPreviewById(
        previewId
    );

};
