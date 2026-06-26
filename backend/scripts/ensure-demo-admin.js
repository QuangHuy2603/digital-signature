import { ensureDemoAdminUser } from "../src/services/auth.service.js";
const admin = await ensureDemoAdminUser();
console.log(JSON.stringify({
    version: "1.0.0",
    status: "ready",
    admin: admin ? { id: admin.id, email: admin.email, roles: admin.roles } : null,
    demo_credentials: { email: "admin@test.com", password: "admin123" },
}, null, 2));
