import { describe, expect, it } from "vitest";
import router from "../../src/routes/document.routes.js";

const routeIndex = (method, path) => {
    return router.stack.findIndex((layer) => {
        const route = layer.route;
        return route?.path === path && route.methods?.[method] === true;
    });
};

describe("document route ordering", () => {
    it("keeps fixed officer routes before the dynamic document detail route", () => {
        const pendingIndex = routeIndex("get", "/pending");
        const issuedIndex = routeIndex("get", "/issued");
        const previewFileIndex = routeIndex("get", "/previews/:previewId/file");
        const signingRequestIndex = routeIndex("post", "/:documentId/signing-request");
        const remoteAuthorizationIndex = routeIndex("post", "/:documentId/remote-signing-authorization");
        const remoteOtpVerifyIndex = routeIndex("post", "/:documentId/remote-signing-authorization/verify");
        const signIndex = routeIndex("post", "/:documentId/sign");
        const detailIndex = routeIndex("get", "/:documentId");

        expect(pendingIndex).toBeGreaterThanOrEqual(0);
        expect(issuedIndex).toBeGreaterThanOrEqual(0);
        expect(previewFileIndex).toBeGreaterThanOrEqual(0);
        expect(signingRequestIndex).toBeGreaterThanOrEqual(0);
        expect(remoteAuthorizationIndex).toBeGreaterThanOrEqual(0);
        expect(remoteOtpVerifyIndex).toBeGreaterThanOrEqual(0);
        expect(signIndex).toBeGreaterThanOrEqual(0);
        expect(detailIndex).toBeGreaterThanOrEqual(0);
        expect(pendingIndex).toBeLessThan(detailIndex);
        expect(issuedIndex).toBeLessThan(detailIndex);
        expect(previewFileIndex).toBeLessThan(detailIndex);
        expect(signingRequestIndex).toBeLessThan(detailIndex);
        expect(remoteAuthorizationIndex).toBeLessThan(detailIndex);
        expect(remoteOtpVerifyIndex).toBeLessThan(detailIndex);
        expect(signIndex).toBeLessThan(detailIndex);
    });
});
