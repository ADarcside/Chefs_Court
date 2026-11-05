import jwt from "jsonwebtoken";
import { config } from "../config/env.js";

export function signToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), role: user.role, name: user.name },
    config.jwtSecret,
    {
      expiresIn: config.jwtExpiresIn,
    },
  );
}

/** Verifies the Bearer token. With required=false, anonymous requests pass with req.user = null. */
export function authenticate({ required = true } = {}) {
  return (req, res, next) => {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;

    if (!token) {
      if (required) return res.status(401).json({ error: "Missing token" });
      req.user = null;
      return next();
    }

    try {
      const payload = jwt.verify(token, config.jwtSecret);
      req.user = { id: payload.sub, role: payload.role, name: payload.name };
      return next();
    } catch {
      return res.status(401).json({ error: "Invalid token" });
    }
  };
}

export function requireRoles(...allowed) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    if (!allowed.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden: insufficient role" });
    }
    return next();
  };
}
