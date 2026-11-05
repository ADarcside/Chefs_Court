import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";
import { bearer, createUser, fileCase, setupTestApp } from "./helpers.js";

let ctx;
let judge;
let jurors;
let caseDoc;

const vote = (token, id, choice) =>
  ctx.api().post(`/jury/vote/${id}`).set(bearer(token)).send({ choice });

before(async () => {
  ctx = await setupTestApp();
});
after(() => ctx.teardown());
beforeEach(async () => {
  await ctx.reset();
  judge = await createUser(ctx.api, "JUDGE");
  jurors = await Promise.all([1, 2, 3].map(() => createUser(ctx.api, "JUROR")));
  const defendant = await createUser(ctx.api, "DEFENDANT");
  caseDoc = await fileCase(ctx.api, defendant.token);
});

const approve = () => ctx.api().patch(`/case/approve/${caseDoc._id}`).set(bearer(judge.token));

describe("voting", () => {
  it("only allows votes on approved cases", async () => {
    assert.equal((await vote(jurors[0].token, caseDoc._id, "guilty")).status, 400);
    await approve();
    assert.equal((await vote(jurors[0].token, caseDoc._id, "guilty")).status, 201);
  });

  it("makes votes final (second vote is 409)", async () => {
    await approve();
    assert.equal((await vote(jurors[0].token, caseDoc._id, "guilty")).status, 201);
    assert.equal((await vote(jurors[0].token, caseDoc._id, "not_guilty")).status, 409);

    const results = await ctx.api().get(`/jury/results/${caseDoc._id}`).set(bearer(judge.token));
    assert.deepEqual(results.body.results, { guilty: 1, not_guilty: 0, total: 1 });
  });

  it("validates the choice and the case id", async () => {
    await approve();
    assert.equal((await vote(jurors[0].token, caseDoc._id, "maybe")).status, 400);
    assert.equal((await vote(jurors[0].token, "bad-id", "guilty")).status, 400);
  });

  it("hides results of unapproved cases from jurors", async () => {
    const res = await ctx.api().get(`/jury/results/${caseDoc._id}`).set(bearer(jurors[0].token));
    assert.equal(res.status, 403);
  });
});

describe("verdicts", () => {
  it("closes a case with the jury majority", async () => {
    await approve();
    await vote(jurors[0].token, caseDoc._id, "guilty");
    await vote(jurors[1].token, caseDoc._id, "guilty");
    await vote(jurors[2].token, caseDoc._id, "not_guilty");

    const res = await ctx.api().patch(`/case/close/${caseDoc._id}`).set(bearer(judge.token));
    assert.equal(res.status, 200);
    assert.equal(res.body.status, "CLOSED");
    assert.equal(res.body.verdict.outcome, "guilty");
    assert.equal(res.body.verdict.total, 3);
    assert.equal(res.body.verdict.judgeOverride, false);

    // Closed cases accept no more votes or edits, but results stay visible to jurors.
    const late = await createUser(ctx.api, "JUROR");
    assert.equal((await vote(late.token, caseDoc._id, "not_guilty")).status, 400);
    const edit = await ctx
      .api()
      .patch(`/case/edit/${caseDoc._id}`)
      .set(bearer(judge.token))
      .send({ title: "x" });
    assert.equal(edit.status, 409);
    const results = await ctx
      .api()
      .get(`/jury/results/${caseDoc._id}`)
      .set(bearer(jurors[0].token));
    assert.equal(results.status, 200);
    assert.equal(results.body.verdict.outcome, "guilty");
  });

  it("requires the judge to break a tie", async () => {
    await approve();
    await vote(jurors[0].token, caseDoc._id, "guilty");
    await vote(jurors[1].token, caseDoc._id, "not_guilty");

    const tied = await ctx.api().patch(`/case/close/${caseDoc._id}`).set(bearer(judge.token));
    assert.equal(tied.status, 400);

    const res = await ctx
      .api()
      .patch(`/case/close/${caseDoc._id}`)
      .set(bearer(judge.token))
      .send({ verdict: "not_guilty" });
    assert.equal(res.status, 200);
    assert.equal(res.body.verdict.outcome, "not_guilty");
    assert.equal(res.body.verdict.judgeOverride, true);
  });

  it("cannot close a case that is not approved", async () => {
    const res = await ctx.api().patch(`/case/close/${caseDoc._id}`).set(bearer(judge.token));
    assert.equal(res.status, 409);
  });
});
