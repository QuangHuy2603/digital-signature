import bcrypt from "bcryptjs";
import { atomicWriteJsonSync, readJsonFileSync } from "../src/utils/atomic-file.util.js";
import path from "node:path";

const file = path.resolve("src/data/users.json");
const users = readJsonFileSync(file, []);
let user = users.find((item) => String(item.email).toLowerCase() === "citizen@test.com");
if (!user) {
    user = {
        id: Math.max(0, ...users.map((item) => Number(item.id) || 0)) + 1,
        citizen_id: "CITIZEN-001",
        full_name: "Cong dan Nguyen",
        email: "citizen@test.com",
        password_hash: await bcrypt.hash("citizen123", 10),
        roles: ["citizen"],
        status: "active",
        created_at: new Date().toISOString(),
        citizen_software_certificate_id: null,
        citizen_pkcs11_certificate_id: null,
        active_citizen_certificate_id: null,
        citizen_certificate_status: "not_issued",
    };
    users.push(user);
    atomicWriteJsonSync(file, users, { backup: true });
} else if (!user.citizen_id) {
    user.citizen_id = "CITIZEN-001";
    atomicWriteJsonSync(file, users, { backup: true });
}
console.log(JSON.stringify({ id: user.id, citizen_id: user.citizen_id, email: user.email, password: "citizen123" }, null, 2));
