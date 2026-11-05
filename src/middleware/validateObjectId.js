import mongoose from "mongoose";

/** Rejects requests whose route param is not a valid MongoDB ObjectId. */
export const validateObjectId =
  (param = "id") =>
  (req, res, next) => {
    if (!mongoose.isValidObjectId(req.params[param])) {
      return res.status(400).json({ error: `Invalid ${param}` });
    }
    return next();
  };
