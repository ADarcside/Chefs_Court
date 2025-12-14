import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import multer from "multer";
import fs from "fs";
import path from "path";
import validator from "validator";
import rateLimit from "express-rate-limit";


dotenv.config();

// ---------- Setup ----------
const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(cors());
app.use(helmet());
app.use(morgan("dev"));

const limiter = rateLimit({ windowMs: 60_000, max: 120 });
app.use(limiter);

// Ensure upload dir
const UPLOAD_DIR = process.env.UPLOAD_DIR || "./uploads";
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use("/uploads", express.static(UPLOAD_DIR));

// ---------- DB ----------
await mongoose.connect(process.env.MONGO_URI);

// ---------- Constants ----------
const ROLES = {
  DEFENDANT: "DEFENDANT",
  PLAINTIFF: "PLAINTIFF",
  JUROR: "JUROR",
  JUDGE: "JUDGE"
};
const CASE_STATUS = {
  PENDING: "PENDING",
  APPROVED: "APPROVED",
  REJECTED: "REJECTED"
};
const VOTE = {
  GUILTY: "guilty",
  NOT_GUILTY: "not_guilty"
};

// ---------- Schemas ----------
const UserSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      validate: { validator: validator.isEmail, message: "Invalid email" }
    },
    passwordHash: { type: String, required: true },
    role: {
      type: String,
      enum: Object.values(ROLES),
      required: true
    }
  },
  { timestamps: true }
);

const CaseSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true, maxlength: 200 },
    partyType: {
      type: String,
      enum: [ROLES.DEFENDANT, ROLES.PLAINTIFF],
      required: true
    },
    partyName: { type: String, required: true, trim: true, maxlength: 120 },
    argumentText: { type: String, required: true, trim: true, maxlength: 5000 },
    evidenceText: { type: String, trim: true, maxlength: 5000 },
    evidenceFiles: [{ type: String }], // file paths
    status: {
      type: String,
      enum: Object.values(CASE_STATUS),
      default: CASE_STATUS.PENDING
    },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    roleAtCreation: { type: String, enum: [ROLES.DEFENDANT, ROLES.PLAINTIFF], required: true }
  },
  { timestamps: true }
);

const VoteSchema = new mongoose.Schema(
  {
    case: { type: mongoose.Schema.Types.ObjectId, ref: "Case", required: true, index: true },
    juror: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    choice: { type: String, enum: [VOTE.GUILTY, VOTE.NOT_GUILTY], required: true }
  },
  { timestamps: true }
);
VoteSchema.index({ case: 1, juror: 1 }, { unique: true });

const User = mongoose.model("User", UserSchema);
const Case = mongoose.model("Case", CaseSchema);
const VoteModel = mongoose.model("Vote", VoteSchema);

// ---------- Auth Helpers ----------
function signToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), role: user.role, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
  );
}

function auth(required = true) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

    if (!token) {
      if (required) return res.status(401).json({ error: "Missing token" });
      req.user = null;
      return next();
    }
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      req.user = { id: payload.sub, role: payload.role, name: payload.name };
      return next();
    } catch {
      return res.status(401).json({ error: "Invalid token" });
    }
  };
}

function requireRoles(...allowed) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    if (!allowed.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden: insufficient role" });
    }
    next();
  };
}

// ---------- Uploads (optional docs) ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safeBase = file.originalname.replace(/[^a-z0-9.\-_]/gi, "_");
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}-${safeBase}`;
    cb(null, unique);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10 MB per file
});

// ---------- Routes ----------

// Health
app.get("/health", (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// AUTH
// ----------------------------------
// 2. AUTH ROUTES — must go BEFORE 404 handler
// ----------------------------------
app.post("/auth/signup", async (req, res) => {
  try {
    const { name, email, password, role } = req.body || {};
    if (!name || !email || !password || !role)
      return res.status(400).json({ error: "name, email, password, role are required" });
    if (!Object.values(ROLES).includes(role))
      return res.status(400).json({ error: "Invalid role" });
    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing)
      return res.status(409).json({ error: "Email already registered" });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email: email.toLowerCase(), passwordHash, role });
    const token = signToken(user);
    res.status(201).json({
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
    });
  } catch (e) {
    res.status(500).json({ error: "Signup failed" });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ error: "email and password required" });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user)
      return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok)
      return res.status(401).json({ error: "Invalid credentials" });

    const token = signToken(user);
    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
    });
  } catch {
    res.status(500).json({ error: "Login failed" });
  }
});
// CASES

// POST /case/submit - Defendant / Plaintiff
app.post(
  "/case/submit",
  auth(true),
  requireRoles(ROLES.DEFENDANT, ROLES.PLAINTIFF),
  upload.array("files", 5),
  async (req, res) => {
    try {
      const { title, partyName, argumentText, evidenceText } = req.body || {};
      if (!title || !partyName || !argumentText) {
        return res.status(400).json({ error: "title, partyName, argumentText are required" });
      }

      const evidenceFiles = (req.files || []).map(f => `/uploads/${path.basename(f.path)}`);

      const doc = await Case.create({
        title: title.trim(),
        partyType: req.user.role, // role of the submitter (must be DEFENDANT or PLAINTIFF per middleware)
        partyName: partyName.trim(),
        argumentText: argumentText.trim(),
        evidenceText: evidenceText?.trim() || "",
        evidenceFiles,
        createdBy: req.user.id,
        roleAtCreation: req.user.role, // locked
        status: CASE_STATUS.PENDING // judge approval mandatory
      });
      res.status(201).json(doc);
    } catch (e) {
      res.status(500).json({ error: "Failed to submit case" });
    }
  }
);

// GET /case/all - All roles - View all submissions
// Note: Jurors see only APPROVED. Others see all.
app.get("/case/all", auth(true), async (req, res) => {
  try {
    const filter =
      req.user?.role === ROLES.JUROR
        ? { status: CASE_STATUS.APPROVED }
        : {}; // judges/plaintiffs/defendants see all
    const docs = await Case.find(filter).sort({ createdAt: -1 });
    res.json(docs);
  } catch {
    res.status(500).json({ error: "Failed to fetch cases" });
  }
});

// PATCH /case/edit/:id - Judge only
app.patch("/case/edit/:id", auth(true), requireRoles(ROLES.JUDGE), async (req, res) => {
  try {
    const { id } = req.params;
    const editable = ["title", "partyName", "argumentText", "evidenceText", "partyType", "status"];
    const update = {};
    for (const k of editable) if (k in req.body) update[k] = req.body[k];

    const doc = await Case.findByIdAndUpdate(id, update, { new: true });
    if (!doc) return res.status(404).json({ error: "Case not found" });
    res.json(doc);
  } catch {
    res.status(500).json({ error: "Failed to edit case" });
  }
});

// DELETE /case/delete/:id - Judge only
app.delete("/case/delete/:id", auth(true), requireRoles(ROLES.JUDGE), async (req, res) => {
  try {
    const { id } = req.params;
    const doc = await Case.findByIdAndDelete(id);
    if (!doc) return res.status(404).json({ error: "Case not found" });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Failed to delete case" });
  }
});

// Brownie: FILTER by party name - Juror only, approved only
app.get("/case/by-name/:name", auth(true), requireRoles(ROLES.JUROR), async (req, res) => {
  try {
    const name = req.params.name;
    const docs = await Case.find({
      status: CASE_STATUS.APPROVED,
      partyName: { $regex: new RegExp(validator.escape(name), "i") }
    }).sort({ createdAt: -1 });
    res.json(docs);
  } catch {
    res.status(500).json({ error: "Failed to filter" });
  }
});

// Brownie: Approve/Reject - Judge only
app.patch("/case/approve/:id", auth(true), requireRoles(ROLES.JUDGE), async (req, res) => {
  try {
    const doc = await Case.findByIdAndUpdate(
      req.params.id,
      { status: CASE_STATUS.APPROVED },
      { new: true }
    );
    if (!doc) return res.status(404).json({ error: "Case not found" });
    res.json(doc);
  } catch {
    res.status(500).json({ error: "Failed to approve" });
  }
});

app.patch("/case/reject/:id", auth(true), requireRoles(ROLES.JUDGE), async (req, res) => {
  try {
    const doc = await Case.findByIdAndUpdate(
      req.params.id,
      { status: CASE_STATUS.REJECTED },
      { new: true }
    );
    if (!doc) return res.status(404).json({ error: "Case not found" });
    res.json(doc);
  } catch {
    res.status(500).json({ error: "Failed to reject" });
  }
});

// JURY VOTING

// POST /jury/vote/:caseId - Juror only; only on APPROVED cases; one vote per juror per case
app.post("/jury/vote/:caseId", auth(true), requireRoles(ROLES.JUROR), async (req, res) => {
  try {
    const { caseId } = req.params;
    const { choice } = req.body || {};
    if (![VOTE.GUILTY, VOTE.NOT_GUILTY].includes(choice))
      return res.status(400).json({ error: "choice must be 'guilty' or 'not_guilty'" });

    const caseDoc = await Case.findById(caseId);
    if (!caseDoc) return res.status(404).json({ error: "Case not found" });
    if (caseDoc.status !== CASE_STATUS.APPROVED)
      return res.status(400).json({ error: "Case not approved for voting" });

    const vote = await VoteModel.findOneAndUpdate(
      { case: caseId, juror: req.user.id },
      { choice },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    res.status(201).json(vote);
  } catch (e) {
    if (e?.code === 11000) {
      return res.status(409).json({ error: "You have already voted on this case" });
    }
    res.status(500).json({ error: "Failed to vote" });
  }
});

// GET /jury/results/:caseId - Juror/Judge
app.get(
  "/jury/results/:caseId",
  auth(true),
  requireRoles(ROLES.JUROR, ROLES.JUDGE),
  async (req, res) => {
    try {
      const { caseId } = req.params;
      const caseDoc = await Case.findById(caseId);
      if (!caseDoc) return res.status(404).json({ error: "Case not found" });

      // For jurors, only reveal results if case is approved
      if (req.user.role === ROLES.JUROR && caseDoc.status !== CASE_STATUS.APPROVED) {
        return res.status(403).json({ error: "Results unavailable for unapproved case" });
      }

      const agg = await VoteModel.aggregate([
        { $match: { case: new mongoose.Types.ObjectId(caseId) } },
        {
          $group: {
            _id: "$choice",
            count: { $sum: 1 }
          }
        }
      ]);

      const counts = { guilty: 0, not_guilty: 0, total: 0 };
      for (const row of agg) {
        if (row._id === VOTE.GUILTY) counts.guilty = row.count;
        if (row._id === VOTE.NOT_GUILTY) counts.not_guilty = row.count;
      }
      counts.total = counts.guilty + counts.not_guilty;

      res.json({ caseId, status: caseDoc.status, results: counts });
    } catch {
      res.status(500).json({ error: "Failed to fetch results" });
    }
  }
);


// ---------- Error & Server ----------
app.use((req, res) => res.status(404).json({ error: "Not found" }));

const PORT = process.env.PORT || 4000;
app._router.stack.forEach(r => {
  if (r.route && r.route.path) {
    console.log("Loaded route:", r.route.path, Object.keys(r.route.methods));
  }
});

app.listen(PORT, () => {
  console.log(`Chef’s Court API running on :${PORT}`);
});
