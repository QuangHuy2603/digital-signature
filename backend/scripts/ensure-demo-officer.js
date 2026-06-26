import "dotenv/config";
import {
    createOfficerAccount,
    findOfficerByOfficerId,
} from "../src/services/officer-account.service.js";

let officer = findOfficerByOfficerId("OFFICER-001");
if (!officer) {
    officer = await createOfficerAccount({
        officerId: "OFFICER-001",
        fullName: "Can bo Nguyen",
        email: "officer@test.com",
        password: "officer123",
    });
}
console.log(JSON.stringify({ status: "ready", officer }, null, 2));
