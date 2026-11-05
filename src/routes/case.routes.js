import { Router } from "express";
import {
  CASE_STATUS,
  EDITABLE_STATUSES,
  JUROR_VISIBLE_STATUSES,
  PARTY_ROLES,
  ROLES,
  UPLOAD,
  VOTE,
  VOTE_CHOICES,
} from "../constants.js";
import { authenticate, requireRoles } from "../middleware/auth.js";
import { removeUploads, toPublicPath, upload } from "../middleware/upload.js";
import { validateObjectId } from "../middleware/validateObjectId.js";
import { Case } from "../models/Case.js";
import { Vote } from "../models/Vote.js";
import { tallyVotes } from "../services/votes.js";
import { HttpError, asyncHandler } from "../utils/http.js";
import { containsRegex, parsePagination } from "../utils/query.js";

const router = Router();

const isJuror = (user) => user?.role === ROLES.JUROR;

/** Base filter restricting what the current user may see. */
function visibilityFilter(user) {
  return isJuror(user) ? { status: { $in: JUROR_VISIBLE_STATUSES } } : {};
}

async function findCaseOr404(id) {
  const doc = await Case.findById(id);
  if (!doc) throw new HttpError(404, "Case not found");
  return doc;
}

function assertNotClosed(doc) {
  if (doc.status === CASE_STATUS.CLOSED) throw new HttpError(409, "Case is closed");
}

// POST /case/submit — Defendant / Plaintiff
router.post(
  "/submit",
  authenticate(),
  requireRoles(...PARTY_ROLES),
  upload.array("files", UPLOAD.MAX_FILES),
  asyncHandler(async (req, res) => {
    const evidenceFiles = (req.files || []).map(toPublicPath);
    try {
      const { title, partyName, argumentText, evidenceText } = req.body || {};
      if (!title || !partyName || !argumentText) {
        throw new HttpError(400, "title, partyName, argumentText are required");
      }

      const doc = await Case.create({
        title,
        partyType: req.user.role,
        partyName,
        argumentText,
        evidenceText: evidenceText || "",
        evidenceFiles,
        createdBy: req.user.id,
        roleAtCreation: req.user.role,
        status: CASE_STATUS.PENDING, // judge approval is mandatory
      });
      return res.status(201).json(doc);
    } catch (err) {
      await removeUploads(evidenceFiles);
      throw err;
    }
  }),
);

// GET /case/all — all roles. Jurors see only approved/closed cases.
// Query: ?page, ?limit, ?status, ?q (matches title or party name)
router.get(
  "/all",
  authenticate(),
  asyncHandler(async (req, res) => {
    const { page, limit, skip } = parsePagination(req.query);
    const filter = visibilityFilter(req.user);

    const { status, q } = req.query;
    if (status) {
      if (!Object.values(CASE_STATUS).includes(status)) {
        throw new HttpError(400, "Invalid status filter");
      }
      if (isJuror(req.user) && !JUROR_VISIBLE_STATUSES.includes(status)) {
        throw new HttpError(403, "Jurors can only view approved or closed cases");
      }
      filter.status = status;
    }
    if (q) {
      const pattern = containsRegex(q);
      filter.$or = [{ title: pattern }, { partyName: pattern }];
    }

    const [data, total] = await Promise.all([
      Case.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit),
      Case.countDocuments(filter),
    ]);

    return res.json({ data, page, limit, total, totalPages: Math.ceil(total / limit) });
  }),
);

// GET /case/by-name/:name — Juror only; approved cases filtered by party name
router.get(
  "/by-name/:name",
  authenticate(),
  requireRoles(ROLES.JUROR),
  asyncHandler(async (req, res) => {
    const docs = await Case.find({
      status: CASE_STATUS.APPROVED,
      partyName: containsRegex(req.params.name),
    }).sort({ createdAt: -1 });
    return res.json(docs);
  }),
);

// GET /case/:id — single case, same visibility rules as /case/all
router.get(
  "/:id",
  authenticate(),
  validateObjectId("id"),
  asyncHandler(async (req, res) => {
    const doc = await Case.findOne({ _id: req.params.id, ...visibilityFilter(req.user) });
    if (!doc) throw new HttpError(404, "Case not found");
    return res.json(doc);
  }),
);

// PATCH /case/edit/:id — Judge only
router.patch(
  "/edit/:id",
  authenticate(),
  requireRoles(ROLES.JUDGE),
  validateObjectId("id"),
  asyncHandler(async (req, res) => {
    const editable = ["title", "partyName", "argumentText", "evidenceText", "partyType", "status"];
    const body = req.body || {};
    const update = {};
    for (const key of editable) if (key in body) update[key] = body[key];

    if ("status" in update && !EDITABLE_STATUSES.includes(update.status)) {
      throw new HttpError(400, `status must be one of ${EDITABLE_STATUSES.join(", ")}`);
    }

    const doc = await findCaseOr404(req.params.id);
    assertNotClosed(doc);
    doc.set(update);
    await doc.save(); // runs schema validators
    return res.json(doc);
  }),
);

// DELETE /case/delete/:id — Judge only. Also removes votes and evidence files.
router.delete(
  "/delete/:id",
  authenticate(),
  requireRoles(ROLES.JUDGE),
  validateObjectId("id"),
  asyncHandler(async (req, res) => {
    const doc = await Case.findByIdAndDelete(req.params.id);
    if (!doc) throw new HttpError(404, "Case not found");
    await Vote.deleteMany({ case: doc._id });
    await removeUploads(doc.evidenceFiles);
    return res.json({ ok: true });
  }),
);

function setStatusRoute(status) {
  return asyncHandler(async (req, res) => {
    const doc = await findCaseOr404(req.params.id);
    assertNotClosed(doc);
    doc.status = status;
    await doc.save();
    return res.json(doc);
  });
}

// PATCH /case/approve/:id and /case/reject/:id — Judge only
router.patch(
  "/approve/:id",
  authenticate(),
  requireRoles(ROLES.JUDGE),
  validateObjectId("id"),
  setStatusRoute(CASE_STATUS.APPROVED),
);
router.patch(
  "/reject/:id",
  authenticate(),
  requireRoles(ROLES.JUDGE),
  validateObjectId("id"),
  setStatusRoute(CASE_STATUS.REJECTED),
);

// PATCH /case/close/:id — Judge only. Ends voting and records the verdict.
// Body (optional): { verdict: "guilty" | "not_guilty" } — required when the jury is tied.
router.patch(
  "/close/:id",
  authenticate(),
  requireRoles(ROLES.JUDGE),
  validateObjectId("id"),
  asyncHandler(async (req, res) => {
    const doc = await findCaseOr404(req.params.id);
    if (doc.status !== CASE_STATUS.APPROVED) {
      throw new HttpError(409, "Only approved cases can be closed");
    }

    const counts = await tallyVotes(doc._id);
    const requested = req.body?.verdict;
    if (requested !== undefined && !VOTE_CHOICES.includes(requested)) {
      throw new HttpError(400, "verdict must be 'guilty' or 'not_guilty'");
    }

    let majority = null;
    if (counts.guilty > counts.not_guilty) majority = VOTE.GUILTY;
    else if (counts.not_guilty > counts.guilty) majority = VOTE.NOT_GUILTY;

    const outcome = requested ?? majority;
    if (!outcome) {
      throw new HttpError(400, "Jury is tied (or has not voted); provide a verdict in the body");
    }

    doc.status = CASE_STATUS.CLOSED;
    doc.verdict = {
      outcome,
      guilty: counts.guilty,
      notGuilty: counts.not_guilty,
      total: counts.total,
      judgeOverride: outcome !== majority,
      closedBy: req.user.id,
      closedAt: new Date(),
    };
    await doc.save();
    return res.json(doc);
  }),
);

export default router;
