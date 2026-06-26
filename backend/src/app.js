import express from "express";
import cookieParser from "cookie-parser";
import helmet from "helmet";

const app = express();

// Security headers
app.use(helmet({
    contentSecurityPolicy: false, // Disable CSP for now (frontend uses inline scripts)
    crossOriginEmbedderPolicy: false // Allow embedding
}));

app.use(express.json());
app.use(cookieParser());

export default app;