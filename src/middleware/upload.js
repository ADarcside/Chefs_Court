import fs from "node:fs";
import path from "node:path";
import multer from "multer";
import { config } from "../config/env.js";
import { UPLOAD } from "../constants.js";
import { HttpError } from "../utils/http.js";

export function ensureUploadDir() {
  fs.mkdirSync(config.uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, config.uploadDir),
  filename: (_req, file, cb) => {
    const safeBase = path.basename(file.originalname).replace(/[^a-z0-9.\-_]/gi, "_");
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}-${safeBase}`);
  },
});

function fileFilter(_req, file, cb) {
  if (UPLOAD.ALLOWED_MIME_TYPES.includes(file.mimetype)) return cb(null, true);
  return cb(new HttpError(400, `Unsupported file type: ${file.mimetype}`));
}

export const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: UPLOAD.MAX_FILE_SIZE, files: UPLOAD.MAX_FILES },
});

/** Public path stored on the case for an uploaded file. */
export const toPublicPath = (file) => `/uploads/${path.basename(file.path)}`;

/** Best-effort removal of evidence files (by public path). */
export async function removeUploads(publicPaths = []) {
  await Promise.all(
    publicPaths.map((publicPath) =>
      fs.promises.rm(path.join(config.uploadDir, path.basename(publicPath)), { force: true }),
    ),
  );
}
