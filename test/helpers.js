import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { MongoMemoryServer } from "mongodb-memory-server";
import mongoose from "mongoose";
import request from "supertest";

export const JUDGE_CODE = "test-judge-code";

/**
 * Starts an in-memory MongoDB and builds the Express app against it.
 * Env vars are set before the app module is imported.
 */
export async function setupTestApp() {
  const mongo = await MongoMemoryServer.create();
  const uploadDir = fs.mkdtempSync(path.join(os.tmpdir(), "chefs-court-uploads-"));

  process.env.NODE_ENV = "test";
  process.env.MONGO_URI = mongo.getUri();
  process.env.JWT_SECRET = "test-secret";
  process.env.JUDGE_INVITE_CODE = JUDGE_CODE;
  process.env.UPLOAD_DIR = uploadDir;

  const { createApp } = await import("../src/app.js");
  await mongoose.connect(mongo.getUri());
  await Promise.all(Object.values(mongoose.models).map((model) => model.syncIndexes()));

  const app = createApp();

  return {
    app,
    api: () => request(app),
    async reset() {
      await Promise.all(
        Object.values(mongoose.connection.collections).map((c) => c.deleteMany({})),
      );
    },
    async teardown() {
      await mongoose.disconnect();
      await mongo.stop();
      fs.rmSync(uploadDir, { recursive: true, force: true });
    },
  };
}

let counter = 0;

/** Signs up a user with the given role and returns { token, user }. */
export async function createUser(api, role, overrides = {}) {
  counter += 1;
  const body = {
    name: `${role} ${counter}`,
    email: `${role.toLowerCase()}${counter}@example.com`,
    password: "Passw0rd!",
    role,
    ...(role === "JUDGE" ? { inviteCode: JUDGE_CODE } : {}),
    ...overrides,
  };
  const res = await api().post("/auth/signup").send(body);
  if (res.status !== 201)
    throw new Error(`signup failed: ${res.status} ${JSON.stringify(res.body)}`);
  return res.body;
}

export const bearer = (token) => ({ Authorization: `Bearer ${token}` });

/** Files a case as the given party token and returns the created case. */
export async function fileCase(api, token, fields = {}) {
  const res = await api()
    .post("/case/submit")
    .set(bearer(token))
    .field("title", fields.title ?? "Stolen Pie")
    .field("partyName", fields.partyName ?? "Chef Luigi")
    .field("argumentText", fields.argumentText ?? "I did not steal the pie.");
  if (res.status !== 201)
    throw new Error(`submit failed: ${res.status} ${JSON.stringify(res.body)}`);
  return res.body;
}
