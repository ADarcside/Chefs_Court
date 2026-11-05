import crypto from "node:crypto";
import { Router } from "express";
import bcrypt from "bcryptjs";
import validator from "validator";
import { config } from "../config/env.js";
import { MIN_PASSWORD_LENGTH, ROLES } from "../constants.js";
import { signToken } from "../middleware/auth.js";
import { User } from "../models/User.js";
import { asyncHandler } from "../utils/http.js";

const router = Router();

function inviteCodeMatches(provided) {
  const expected = config.judgeInviteCode;
  if (!expected || typeof provided !== "string") return false;
  const a = crypto.createHash("sha256").update(provided).digest();
  const b = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

router.post(
  "/signup",
  asyncHandler(async (req, res) => {
    const { name, email, password, role, inviteCode } = req.body || {};

    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: "name, email, password, role are required" });
    }
    if (!Object.values(ROLES).includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }
    if (typeof email !== "string" || !validator.isEmail(email)) {
      return res.status(400).json({ error: "Invalid email" });
    }
    if (typeof password !== "string" || password.length < MIN_PASSWORD_LENGTH) {
      return res
        .status(400)
        .json({ error: `password must be at least ${MIN_PASSWORD_LENGTH} characters` });
    }
    if (role === ROLES.JUDGE && !inviteCodeMatches(inviteCode)) {
      return res.status(403).json({ error: "A valid inviteCode is required to register as JUDGE" });
    }

    const normalizedEmail = email.toLowerCase().trim();
    if (await User.exists({ email: normalizedEmail })) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email: normalizedEmail, passwordHash, role });

    return res.status(201).json({ token: signToken(user), user: user.toPublicJSON() });
  }),
);

router.post(
  "/login",
  asyncHandler(async (req, res) => {
    const { email, password } = req.body || {};
    if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
      return res.status(400).json({ error: "email and password required" });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() }).select("+passwordHash");
    const ok = user && (await bcrypt.compare(password, user.passwordHash));
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    return res.json({ token: signToken(user), user: user.toPublicJSON() });
  }),
);

export default router;
