import express from "express";
import { registerHandler, loginHandler, logoutHandler, meHandler } from "../controllers/auth.controller.js";
import { authenticate } from "../middlewares/auth.middleware.js";
import { authLimiter } from "../middlewares/rate-limit.middleware.js";

const router = express.Router();

router.post("/register", authLimiter, registerHandler);
router.post("/login", authLimiter, loginHandler);
router.post("/logout", logoutHandler);
router.get("/me", authenticate, meHandler);

export default router;
