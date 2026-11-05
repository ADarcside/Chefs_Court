import mongoose from "mongoose";
import validator from "validator";
import { ROLES } from "../constants.js";

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 120 },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      validate: { validator: (value) => validator.isEmail(value), message: "Invalid email" },
    },
    passwordHash: { type: String, required: true, select: false },
    role: { type: String, enum: Object.values(ROLES), required: true },
  },
  { timestamps: true },
);

userSchema.methods.toPublicJSON = function toPublicJSON() {
  return { id: this._id, name: this.name, email: this.email, role: this.role };
};

export const User = mongoose.model("User", userSchema);
