import path from "node:path";
import { Router } from "express";
import { config } from "../config/env.js";
import { authenticate } from "../middleware/auth.js";

const router = Router();

// GET /uploads/:filename — evidence files are only served to signed-in users.
router.get("/:filename", authenticate(), (req, res, next) => {
  const filename = path.basename(req.params.filename);
  res.sendFile(filename, { root: path.resolve(config.uploadDir), dotfiles: "deny" }, (err) => {
    if (!err) return;
    if (err.status === 404 || err.code === "ENOENT") {
      return res.status(404).json({ error: "File not found" });
    }
    return next(err);
  });
});

export default router;
