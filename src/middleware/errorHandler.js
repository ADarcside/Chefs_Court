import mongoose from "mongoose";
import multer from "multer";
import { config } from "../config/env.js";
import { HttpError } from "../utils/http.js";

export function notFound(_req, res) {
  res.status(404).json({ error: "Not found" });
}

// eslint-disable-next-line no-unused-vars -- Express needs the 4-argument signature.
export function errorHandler(err, _req, res, _next) {
  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: err.message });
  }

  if (err instanceof multer.MulterError) {
    const status = err.code === "LIMIT_FILE_SIZE" ? 413 : 400;
    return res.status(status).json({ error: err.message });
  }

  if (err instanceof mongoose.Error.ValidationError) {
    const details = Object.values(err.errors).map((e) => e.message);
    return res.status(400).json({ error: "Validation failed", details });
  }

  if (err instanceof mongoose.Error.CastError) {
    return res.status(400).json({ error: `Invalid ${err.path}` });
  }

  if (err?.code === 11000) {
    return res.status(409).json({ error: "Duplicate resource" });
  }

  if (err?.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Malformed JSON body" });
  }

  if (!config.isTest) console.error(err);
  return res.status(500).json({ error: "Internal server error" });
}
