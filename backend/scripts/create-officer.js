import "dotenv/config";
import { parseCliArgs, requireArg } from "./cli-args.js";
import { createOfficerAccount } from "../src/services/officer-account.service.js";

try {
    const args = parseCliArgs();
    const officer = await createOfficerAccount({
        officerId: requireArg(args, "officer-id"),
        fullName: requireArg(args, "name"),
        email: requireArg(args, "email"),
        password: requireArg(args, "password"),
    });

    console.log("\nOFFICER ACCOUNT CREATED: PASS");
    console.log(JSON.stringify(officer, null, 2));
    console.log("\nNext step:");
    console.log(
        `npm run pki:issue-officer -- --officer-id ${officer.officer_id}`
    );
} catch (error) {
    console.error("\nOFFICER ACCOUNT CREATED: FAIL");
    console.error(error.message);
    process.exitCode = 1;
}
