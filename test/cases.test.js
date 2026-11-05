import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";
import { bearer, createUser, fileCase, setupTestApp } from "./helpers.js";

let ctx;
let judge;
let juror;
let plaintiff;

before(async () => {
  ctx = await setupTestApp();
});
after(() => ctx.teardown());
beforeEach(async () => {
  await ctx.reset();
  judge = await createUser(ctx.api, "JUDGE");
  juror = await createUser(ctx.api, "JUROR");
  plaintiff = await createUser(ctx.api, "PLAINTIFF");
});

describe("case submission", () => {
  it("lets a plaintiff file a pending case", async () => {
    const doc = await fileCase(ctx.api, plaintiff.token);
    assert.equal(doc.status, "PENDING");
    assert.equal(doc.partyType, "PLAINTIFF");
  });

  it("forbids jurors and judges from filing", async () => {
    for (const { token } of [juror, judge]) {
      const res = await ctx.api().post("/case/submit").set(bearer(token)).field("title", "x");
      assert.equal(res.status, 403);
    }
  });

  it("validates required fields", async () => {
    const res = await ctx
      .api()
      .post("/case/submit")
      .set(bearer(plaintiff.token))
      .field("title", "x");
    assert.equal(res.status, 400);
  });

  it("accepts allowed evidence files and serves them only to signed-in users", async () => {
    const res = await ctx
      .api()
      .post("/case/submit")
      .set(bearer(plaintiff.token))
      .field("title", "Burnt Toast")
      .field("partyName", "Chef A")
      .field("argumentText", "It was the toaster.")
      .attach("files", Buffer.from("receipt"), {
        filename: "receipt.txt",
        contentType: "text/plain",
      });
    assert.equal(res.status, 201);
    const [filePath] = res.body.evidenceFiles;
    assert.match(filePath, /^\/uploads\/.+receipt\.txt$/);

    assert.equal((await ctx.api().get(filePath)).status, 401);
    const download = await ctx.api().get(filePath).set(bearer(juror.token));
    assert.equal(download.status, 200);
    assert.equal(download.text, "receipt");
  });

  it("rejects disallowed file types", async () => {
    const res = await ctx
      .api()
      .post("/case/submit")
      .set(bearer(plaintiff.token))
      .field("title", "x")
      .field("partyName", "y")
      .field("argumentText", "z")
      .attach("files", Buffer.from("MZ"), {
        filename: "evil.exe",
        contentType: "application/x-msdownload",
      });
    assert.equal(res.status, 400);
  });
});

describe("listing & visibility", () => {
  it("hides pending cases from jurors but not from judges", async () => {
    const pending = await fileCase(ctx.api, plaintiff.token, { title: "Pending" });
    const approved = await fileCase(ctx.api, plaintiff.token, { title: "Approved" });
    await ctx.api().patch(`/case/approve/${approved._id}`).set(bearer(judge.token));

    const jurorList = await ctx.api().get("/case/all").set(bearer(juror.token));
    assert.equal(jurorList.status, 200);
    assert.deepEqual(
      jurorList.body.data.map((c) => c.title),
      ["Approved"],
    );

    const judgeList = await ctx.api().get("/case/all").set(bearer(judge.token));
    assert.equal(judgeList.body.total, 2);

    const single = await ctx.api().get(`/case/${pending._id}`).set(bearer(juror.token));
    assert.equal(single.status, 404);
  });

  it("paginates and filters by status and search text", async () => {
    for (let i = 1; i <= 5; i += 1) {
      await fileCase(ctx.api, plaintiff.token, {
        title: `Case ${i}`,
        partyName: i === 3 ? "Gordon" : "Luigi",
      });
    }

    const page = await ctx.api().get("/case/all?page=2&limit=2").set(bearer(judge.token));
    assert.equal(page.status, 200);
    assert.equal(page.body.data.length, 2);
    assert.equal(page.body.total, 5);
    assert.equal(page.body.totalPages, 3);
    assert.equal(page.body.page, 2);

    const search = await ctx.api().get("/case/all?q=gord").set(bearer(judge.token));
    assert.equal(search.body.total, 1);

    const byStatus = await ctx.api().get("/case/all?status=APPROVED").set(bearer(judge.token));
    assert.equal(byStatus.body.total, 0);

    const forbidden = await ctx.api().get("/case/all?status=PENDING").set(bearer(juror.token));
    assert.equal(forbidden.status, 403);
  });

  it("treats search input as literal text, not a regex", async () => {
    const doc = await fileCase(ctx.api, plaintiff.token, { partyName: "Chef (a+)+" });
    await ctx.api().patch(`/case/approve/${doc._id}`).set(bearer(judge.token));

    const res = await ctx
      .api()
      .get(`/case/by-name/${encodeURIComponent("(a+)+")}`)
      .set(bearer(juror.token));
    assert.equal(res.status, 200);
    assert.equal(res.body.length, 1);

    const none = await ctx
      .api()
      .get(`/case/by-name/${encodeURIComponent(".*")}`)
      .set(bearer(juror.token));
    assert.equal(none.body.length, 0);
  });

  it("returns 400 for malformed ids", async () => {
    const res = await ctx.api().patch("/case/approve/not-an-id").set(bearer(judge.token));
    assert.equal(res.status, 400);
  });
});

describe("judge actions", () => {
  it("edits with schema validation and blocks invalid statuses", async () => {
    const doc = await fileCase(ctx.api, plaintiff.token);

    const ok = await ctx
      .api()
      .patch(`/case/edit/${doc._id}`)
      .set(bearer(judge.token))
      .send({ title: "Renamed" });
    assert.equal(ok.status, 200);
    assert.equal(ok.body.title, "Renamed");

    const badStatus = await ctx
      .api()
      .patch(`/case/edit/${doc._id}`)
      .set(bearer(judge.token))
      .send({ status: "WHATEVER" });
    assert.equal(badStatus.status, 400);

    const tooLong = await ctx
      .api()
      .patch(`/case/edit/${doc._id}`)
      .set(bearer(judge.token))
      .send({ title: "x".repeat(201) });
    assert.equal(tooLong.status, 400);
  });

  it("forbids non-judges from editing", async () => {
    const doc = await fileCase(ctx.api, plaintiff.token);
    const res = await ctx
      .api()
      .patch(`/case/edit/${doc._id}`)
      .set(bearer(plaintiff.token))
      .send({ title: "x" });
    assert.equal(res.status, 403);
  });

  it("deletes a case", async () => {
    const doc = await fileCase(ctx.api, plaintiff.token);
    assert.equal(
      (await ctx.api().delete(`/case/delete/${doc._id}`).set(bearer(judge.token))).status,
      200,
    );
    assert.equal(
      (await ctx.api().delete(`/case/delete/${doc._id}`).set(bearer(judge.token))).status,
      404,
    );
  });
});
