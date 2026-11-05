import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import swaggerUi from "swagger-ui-express";
import { config } from "./config/env.js";
import { openapiSpec } from "./docs/openapi.js";
import { errorHandler, notFound } from "./middleware/errorHandler.js";
import { ensureUploadDir } from "./middleware/upload.js";
import authRoutes from "./routes/auth.routes.js";
import caseRoutes from "./routes/case.routes.js";
import juryRoutes from "./routes/jury.routes.js";
import uploadRoutes from "./routes/upload.routes.js";

export function createApp() {
  ensureUploadDir();

  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", 1);

  // Swagger UI needs inline scripts/styles, so relax CSP for /docs only.
  const strictHelmet = helmet();
  const docsHelmet = helmet({ contentSecurityPolicy: false });
  app.use((req, res, next) =>
    req.path.startsWith("/docs") ? docsHelmet(req, res, next) : strictHelmet(req, res, next),
  );
  app.use(cors({ origin: config.corsOrigin }));
  app.use(express.json({ limit: "1mb" }));
  if (!config.isTest) app.use(morgan(config.nodeEnv === "production" ? "combined" : "dev"));

  const skip = () => config.isTest;
  app.use(
    rateLimit({
      windowMs: 60_000,
      limit: 120,
      standardHeaders: "draft-7",
      legacyHeaders: false,
      skip,
    }),
  );
  const authLimiter = rateLimit({
    windowMs: 15 * 60_000,
    limit: 20,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    skip,
  });

  app.use(
    "/docs",
    swaggerUi.serve,
    swaggerUi.setup(openapiSpec, { customSiteTitle: "Chef's Court API" }),
  );
  app.get("/openapi.json", (_req, res) => res.json(openapiSpec));

  app.get("/health", (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

  app.use("/auth", authLimiter, authRoutes);
  app.use("/case", caseRoutes);
  app.use("/jury", juryRoutes);
  app.use("/uploads", uploadRoutes);

  app.use(notFound);
  app.use(errorHandler);

  return app;
}
