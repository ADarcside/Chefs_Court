import { Router } from "express";
import { CASE_STATUS, JUROR_VISIBLE_STATUSES, ROLES, VOTE_CHOICES } from "../constants.js";
import { authenticate, requireRoles } from "../middleware/auth.js";
import { validateObjectId } from "../middleware/validateObjectId.js";
import { Case } from "../models/Case.js";
import { Vote } from "../models/Vote.js";
import { tallyVotes } from "../services/votes.js";
import { HttpError, asyncHandler } from "../utils/http.js";

const router = Router();

// POST /jury/vote/:caseId — Juror only; approved cases only; votes are final
router.post(
  "/vote/:caseId",
  authenticate(),
  requireRoles(ROLES.JUROR),
  validateObjectId("caseId"),
  asyncHandler(async (req, res) => {
    const { caseId } = req.params;
    const { choice } = req.body || {};
    if (!VOTE_CHOICES.includes(choice)) {
      throw new HttpError(400, "choice must be 'guilty' or 'not_guilty'");
    }

    const caseDoc = await Case.findById(caseId);
    if (!caseDoc) throw new HttpError(404, "Case not found");
    if (caseDoc.status !== CASE_STATUS.APPROVED) {
      throw new HttpError(400, "Case is not open for voting");
    }

    try {
      const vote = await Vote.create({ case: caseId, juror: req.user.id, choice });
      return res.status(201).json(vote);
    } catch (err) {
      if (err?.code === 11000) throw new HttpError(409, "You have already voted on this case");
      throw err;
    }
  }),
);

// GET /jury/results/:caseId — Juror / Judge
router.get(
  "/results/:caseId",
  authenticate(),
  requireRoles(ROLES.JUROR, ROLES.JUDGE),
  validateObjectId("caseId"),
  asyncHandler(async (req, res) => {
    const caseDoc = await Case.findById(req.params.caseId);
    if (!caseDoc) throw new HttpError(404, "Case not found");

    if (req.user.role === ROLES.JUROR && !JUROR_VISIBLE_STATUSES.includes(caseDoc.status)) {
      throw new HttpError(403, "Results unavailable for unapproved case");
    }

    const results = await tallyVotes(caseDoc._id);
    return res.json({
      caseId: caseDoc._id,
      status: caseDoc.status,
      results,
      verdict: caseDoc.verdict ?? null,
    });
  }),
);

export default router;
