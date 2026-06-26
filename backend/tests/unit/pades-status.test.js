import { describe, expect, it } from "vitest";
import { getPadesStatus } from "../../src/crypto/pades.service.js";

describe("PAdES service status", () => {
    it("reports PAdES-LT as ready", () => {
        const status = getPadesStatus();
        expect(status.ready).toBe(true);
        expect(status.default_level).toBe("PAdES-LT");
        expect(status.supported_levels).toContain("PAdES-LT");
        expect(status.lt_profile.dss).toBe(true);
        expect(status.lt_profile.vri).toBe(true);
        expect(status.subfilter).toBe("ETSI.CAdES.detached");
    });
});
