import mongoose from "mongoose";
import { CASE_STATUS, PARTY_ROLES, VOTE_CHOICES } from "../constants.js";

const verdictSchema = new mongoose.Schema(
  {
    outcome: { type: String, enum: VOTE_CHOICES, required: true },
    guilty: { type: Number, required: true, min: 0 },
    notGuilty: { type: Number, required: true, min: 0 },
    total: { type: Number, required: true, min: 0 },
    /** True when the judge's decision differs from (or breaks a tie in) the jury majority. */
    judgeOverride: { type: Boolean, default: false },
    closedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    closedAt: { type: Date, default: Date.now },
  },
  { _id: false },
);

const caseSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true, maxlength: 200 },
    partyType: { type: String, enum: PARTY_ROLES, required: true },
    partyName: { type: String, required: true, trim: true, maxlength: 120 },
    argumentText: { type: String, required: true, trim: true, maxlength: 5000 },
    evidenceText: { type: String, trim: true, maxlength: 5000, default: "" },
    evidenceFiles: [{ type: String }], // public paths, e.g. /uploads/<file>
    status: {
      type: String,
      enum: Object.values(CASE_STATUS),
      default: CASE_STATUS.PENDING,
      index: true,
    },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    roleAtCreation: { type: String, enum: PARTY_ROLES, required: true },
    verdict: { type: verdictSchema, default: undefined },
  },
  { timestamps: true },
);

export const Case = mongoose.model("Case", caseSchema);
