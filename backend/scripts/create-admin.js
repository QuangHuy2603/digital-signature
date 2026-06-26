import "dotenv/config";
import { parseCliArgs, requireArg } from "./cli-args.js";
import { createAdminAccount } from "../src/services/account-management.service.js";

try {
    const args = parseCliArgs();
    const admin = await createAdminAccount({
        adminId: requireArg(args, "admin-id"),
        fullName: requireArg(args, "name"),
        email: requireArg(args, "email"),
        password: requireArg(args, "password"),
    });
    console.log("\nADMIN ACCOUNT CREATED: PASS");
    console.log(JSON.stringify(admin, null, 2));
} catch (error) {
    console.error("\nADMIN ACCOUNT CREATED: FAIL");
    console.error(error.message);
    process.exitCode = 1;
}
