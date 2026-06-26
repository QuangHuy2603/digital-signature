import "dotenv/config";
import { parseCliArgs } from "./cli-args.js";
import { listAccounts } from "../src/services/account-management.service.js";

const args = parseCliArgs();
const accounts = listAccounts({ role: args.role || null });
console.log(`Accounts: ${accounts.length}`);
for (const account of accounts) {
    const subjectId = account.admin_id || account.officer_id || account.citizen_id || "NO-SUBJECT-ID";
    console.log(`${subjectId} | ${account.email} | roles=${(account.roles || []).join(",")} | status=${account.status || "active"}`);
}
