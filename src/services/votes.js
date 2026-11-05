import mongoose from "mongoose";
import { VOTE } from "../constants.js";
import { Vote } from "../models/Vote.js";

/** Counts guilty / not_guilty votes for a case. */
export async function tallyVotes(caseId) {
  const rows = await Vote.aggregate([
    { $match: { case: new mongoose.Types.ObjectId(String(caseId)) } },
    { $group: { _id: "$choice", count: { $sum: 1 } } },
  ]);

  const counts = { guilty: 0, not_guilty: 0, total: 0 };
  for (const row of rows) {
    if (row._id === VOTE.GUILTY) counts.guilty = row.count;
    if (row._id === VOTE.NOT_GUILTY) counts.not_guilty = row.count;
  }
  counts.total = counts.guilty + counts.not_guilty;
  return counts;
}
