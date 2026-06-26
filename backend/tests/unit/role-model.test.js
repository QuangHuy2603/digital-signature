import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const usersPath = path.resolve("src/data/users.json");

describe("Certificate administration three-role authorization model", () => {
    it("stores citizen, officer and admin roles only", () => {
        const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
        const roles = new Set(users.flatMap((user) => user.roles || []));

        expect([...roles].sort()).toEqual(["admin", "citizen", "officer"]);
        expect(roles.has("ra_officer")).toBe(false);
        expect(roles.has("ca_admin")).toBe(false);
    });

    it("keeps separate officer and Certificate administration admin demo accounts", () => {
        const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));

        expect(users.some((user) => user.email === "officer@test.com" && user.roles?.includes("officer"))).toBe(true);
        expect(users.some((user) => user.email === "admin@test.com" && user.roles?.includes("admin"))).toBe(true);
    });
});
