import "dotenv/config";
import { parseCliArgs, requireArg } from "./cli-args.js";
import { setAccountEnabled } from "../src/services/account-management.service.js";

try {
    const args = parseCliArgs();
    const action = String(requireArg(args, "action")).toLowerCase();
    if (!new Set(["enable", "disable"]).has(action)) {
        throw new Error("--action must be enable or disable");
    }
    const account = setAccountEnabled({
        email: requireArg(args, "email"),
        enabled: action === "enable",
    });
    console.log(`\nACCOUNT ${action.toUpperCase()}: PASS`);
    console.log(JSON.stringify(account, null, 2));
} catch (error) {
    console.error("\nACCOUNT STATUS UPDATE: FAIL");
    console.error(error.message);
    process.exitCode = 1;
}
