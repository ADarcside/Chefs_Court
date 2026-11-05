import mongoose from "mongoose";
import { VOTE_CHOICES } from "../constants.js";

const voteSchema = new mongoose.Schema(
  {
    case: { type: mongoose.Schema.Types.ObjectId, ref: "Case", required: true, index: true },
    juror: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    choice: { type: String, enum: VOTE_CHOICES, required: true },
  },
  { timestamps: true },
);

// One vote per juror per case.
voteSchema.index({ case: 1, juror: 1 }, { unique: true });

export const Vote = mongoose.model("Vote", voteSchema);
