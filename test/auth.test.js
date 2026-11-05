import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";
import { createUser, setupTestApp } from "./helpers.js";

let ctx;
before(async () => {
  ctx = await setupTestApp();
});
after(() => ctx.teardown());
beforeEach(() => ctx.reset());

describe("health & docs", () => {
  it("GET /health responds ok", async () => {
    const res = await ctx.api().get("/health");
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
  });

  it("serves the OpenAPI spec", async () => {
    const res = await ctx.api().get("/openapi.json");
    assert.equal(res.status, 200);
    assert.equal(res.body.openapi, "3.0.3");
  });

  it("returns JSON 404 for unknown routes", async () => {
    const res = await ctx.api().get("/nope");
    assert.equal(res.status, 404);
    assert.equal(res.body.error, "Not found");
  });
});

describe("POST /auth/signup", () => {
  it("creates a user and never returns the password hash", async () => {
    const { token, user } = await createUser(ctx.api, "JUROR");
    assert.ok(token);
    assert.equal(user.role, "JUROR");
    assert.equal(user.passwordHash, undefined);
  });

  it("rejects missing fields, bad roles, bad emails and short passwords", async () => {
    const base = { name: "A", email: "a@example.com", password: "Passw0rd!", role: "JUROR" };
    const cases = [
      { ...base, name: undefined },
      { ...base, role: "CHEF" },
      { ...base, email: "not-an-email" },
      { ...base, password: "short" },
    ];
    for (const body of cases) {
      const res = await ctx.api().post("/auth/signup").send(body);
      assert.equal(res.status, 400, JSON.stringify(body));
    }
  });

  it("requires a valid invite code to register as JUDGE", async () => {
    const body = { name: "J", email: "j@example.com", password: "Passw0rd!", role: "JUDGE" };
    assert.equal((await ctx.api().post("/auth/signup").send(body)).status, 403);
    assert.equal(
      (
        await ctx
          .api()
          .post("/auth/signup")
          .send({ ...body, inviteCode: "wrong" })
      ).status,
      403,
    );
    await createUser(ctx.api, "JUDGE"); // helper supplies the right code
  });

  it("rejects duplicate emails (case-insensitive)", async () => {
    await createUser(ctx.api, "JUROR", { email: "dup@example.com" });
    const res = await ctx
      .api()
      .post("/auth/signup")
      .send({ name: "B", email: "DUP@example.com", password: "Passw0rd!", role: "JUROR" });
    assert.equal(res.status, 409);
  });
});

describe("POST /auth/login", () => {
  it("logs in with correct credentials only", async () => {
    await createUser(ctx.api, "PLAINTIFF", { email: "p@example.com" });

    const ok = await ctx
      .api()
      .post("/auth/login")
      .send({ email: "p@example.com", password: "Passw0rd!" });
    assert.equal(ok.status, 200);
    assert.ok(ok.body.token);

    const bad = await ctx
      .api()
      .post("/auth/login")
      .send({ email: "p@example.com", password: "nope" });
    assert.equal(bad.status, 401);
  });

  it("rejects requests without a token or with a bad token", async () => {
    assert.equal((await ctx.api().get("/case/all")).status, 401);
    const res = await ctx.api().get("/case/all").set("Authorization", "Bearer garbage");
    assert.equal(res.status, 401);
  });
});
