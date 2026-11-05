import dotenv from "dotenv";

dotenv.config();

const REQUIRED = ["MONGO_URI", "JWT_SECRET"];

/**
 * Runtime configuration. Values are read lazily from process.env so that
 * tests can set variables before the app is created.
 */
export const config = {
  get nodeEnv() {
    return process.env.NODE_ENV || "development";
  },
  get isTest() {
    return this.nodeEnv === "test";
  },
  get port() {
    return Number(process.env.PORT) || 4000;
  },
  get mongoUri() {
    return process.env.MONGO_URI;
  },
  get jwtSecret() {
    return process.env.JWT_SECRET;
  },
  get jwtExpiresIn() {
    return process.env.JWT_EXPIRES_IN || "7d";
  },
  get uploadDir() {
    return process.env.UPLOAD_DIR || "./uploads";
  },
  get corsOrigin() {
    const raw = process.env.CORS_ORIGIN;
    if (!raw || raw === "*") return "*";
    return raw.split(",").map((origin) => origin.trim());
  },
  /** Judges must present this code at signup. If unset, judge signup is disabled. */
  get judgeInviteCode() {
    return process.env.JUDGE_INVITE_CODE || "";
  },
};

export function assertRequiredEnv() {
  const missing = REQUIRED.filter((key) => !process.env[key]);
  if (missing.length) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }
}
