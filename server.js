"use strict";

const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const USE_MEMORY = String(process.env.USE_MEMORY || "0") === "1";
const MONGODB_URI =
  process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/minijobs";
const JWT_SECRET = process.env.JWT_SECRET || "devsecret-change-me";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// serve /public
app.use(express.static(path.join(__dirname, "public")));

// ---- Templates ----
const TPL = (name) => path.join(__dirname, "public", name);
app.get("/", (_req, res) => res.redirect("/internships"));
app.get("/login", (_req, res) => res.sendFile(TPL("login.html")));
app.get("/signup", (_req, res) => res.sendFile(TPL("signup.html")));
app.get("/internships", (_req, res) => res.sendFile(TPL("internships.html")));

// ----------------- Models / Memory Stores -----------------
let Internship, User;
let memoryJobs = []; // { _id,title,company,role,createdAt,postedBy:{userId,email}, applicants:[{userId,email,appliedAt}] }
let memoryUsers = [];

if (USE_MEMORY) {
  console.log("⚠️  MEMORY MODE: data resets on restart.");
} else {
  mongoose
    .connect(MONGODB_URI)
    .then(() => console.log("✅ MongoDB connected"))
    .catch((err) => {
      console.error("❌ MongoDB error:", err.message);
      process.exit(1);
    });

  const InternshipSchema = new mongoose.Schema(
    {
      title: String,
      company: String,
      role: String,
      postedBy: {
        userId: String,
        email: String,
      },
      applicants: [
        {
          userId: String,
          email: String,
          appliedAt: Date,
        },
      ],
    },
    { timestamps: true }
  );
  Internship = mongoose.model("Internship", InternshipSchema);

  const UserSchema = new mongoose.Schema(
    {
      email: { type: String, required: true, unique: true },
      passwordHash: { type: String, required: true },
      role: { type: String, enum: ["employer", "seeker"], default: "seeker" },
    },
    { timestamps: true }
  );
  User = mongoose.model("User", UserSchema);
}

// ----------------- Helpers -----------------
function safeUser(u) {
  return { id: u._id?.toString?.() || u.id, email: u.email, role: u.role };
}
function signToken(u) {
  return jwt.sign(
    { id: u._id?.toString?.() || u.id, role: u.role, email: u.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}
function authRequired(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid/expired token" });
  }
}
const requireRole = (role) => (req, res, next) => {
  if (!req.user || req.user.role !== role)
    return res.status(403).json({ error: "Forbidden: wrong role" });
  next();
};
// optional auth (to show “applied” flag)
function optionalAuth(req, _res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (token) {
    try {
      req.user = jwt.verify(token, JWT_SECRET);
    } catch {
      /* ignore */
    }
  }
  next();
}

// ----------------- Auth APIs -----------------
app.post("/api/auth/signup", async (req, res) => {
  try {
    let { email, password, role } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ error: "email + password required" });
    email = email.toLowerCase().trim();
    role = role === "employer" ? "employer" : "seeker";

    if (USE_MEMORY) {
      if (memoryUsers.find((u) => u.email === email))
        return res.status(409).json({ error: "already registered" });
      const hash = await bcrypt.hash(password, 10);
      const u = { id: Date.now().toString(), email, passwordHash: hash, role };
      memoryUsers.push(u);
      return res.json({ user: safeUser(u), token: signToken(u) });
    }

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ error: "already registered" });
    const hash = await bcrypt.hash(password, 10);
    const u = await User.create({ email, passwordHash: hash, role });
    return res.json({ user: safeUser(u), token: signToken(u) });
  } catch {
    res.status(500).json({ error: "server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    let { email, password } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ error: "email + password required" });
    email = email.toLowerCase().trim();

    if (USE_MEMORY) {
      const u = memoryUsers.find((u) => u.email === email);
      if (!u) return res.status(401).json({ error: "invalid credentials" });
      const ok = await bcrypt.compare(password, u.passwordHash);
      if (!ok) return res.status(401).json({ error: "invalid credentials" });
      return res.json({ user: safeUser(u), token: signToken(u) });
    }

    const u = await User.findOne({ email });
    if (!u) return res.status(401).json({ error: "invalid credentials" });
    const ok = await bcrypt.compare(password, u.passwordHash);
    if (!ok) return res.status(401).json({ error: "invalid credentials" });
    return res.json({ user: safeUser(u), token: signToken(u) });
  } catch {
    res.status(500).json({ error: "server error" });
  }
});

// ----------------- Internship APIs -----------------

// List jobs (newest first) + applicantCount + applied flag for seekers
app.get("/api/internships", optionalAuth, async (req, res) => {
  if (USE_MEMORY) {
    const jobs = [...memoryJobs].sort(
      (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
    );
    const mapped = jobs.map((j) => ({
      ...j,
      applicantCount: j.applicants?.length || 0,
      applied:
        req.user && req.user.role === "seeker"
          ? (j.applicants || []).some((a) => a.userId === req.user.id)
          : false,
    }));
    return res.json(mapped);
  }

  const jobs = await Internship.find().sort({ createdAt: -1 });
  const mapped = jobs.map((j) => {
    const jj = j.toObject();
    return {
      ...jj,
      applicantCount: (jj.applicants || []).length,
      applied:
        req.user && req.user.role === "seeker"
          ? (jj.applicants || []).some((a) => a.userId === req.user.id)
          : false,
    };
  });
  res.json(mapped);
});

// Post a job (employer only) — now records poster
app.post(
  "/api/internships",
  authRequired,
  requireRole("employer"),
  async (req, res) => {
    const { title, company, role } = req.body || {};
    if (!title || !company || !role)
      return res.status(400).json({ error: "all fields required" });

    if (USE_MEMORY) {
      const job = {
        _id: Date.now().toString(),
        title,
        company,
        role,
        createdAt: new Date().toISOString(),
        postedBy: { userId: req.user.id, email: req.user.email },
        applicants: [],
      };
      memoryJobs.unshift(job);
      return res.status(201).json(job);
    }

    const job = await Internship.create({
      title,
      company,
      role,
      postedBy: { userId: req.user.id, email: req.user.email },
      applicants: [],
    });
    res.status(201).json(job);
  }
);

// Apply to a job (seeker only)
app.post(
  "/api/internships/:id/apply",
  authRequired,
  requireRole("seeker"),
  async (req, res) => {
    const jobId = req.params.id;

    if (USE_MEMORY) {
      const job = memoryJobs.find((j) => j._id == jobId);
      if (!job) return res.status(404).json({ error: "job not found" });
      job.applicants = job.applicants || [];
      if (job.applicants.some((a) => a.userId === req.user.id)) {
        return res.status(409).json({ error: "already applied" });
      }
      job.applicants.push({
        userId: req.user.id,
        email: req.user.email,
        appliedAt: new Date().toISOString(),
      });
      return res.json({ ok: true });
    }

    const job = await Internship.findById(jobId);
    if (!job) return res.status(404).json({ error: "job not found" });
    job.applicants = job.applicants || [];
    if (job.applicants.some((a) => a.userId === req.user.id)) {
      return res.status(409).json({ error: "already applied" });
    }
    job.applicants.push({
      userId: req.user.id,
      email: req.user.email,
      appliedAt: new Date(),
    });
    await job.save();
    res.json({ ok: true });
  }
);

// View applicants (ONLY the posting employer)
app.get(
  "/api/internships/:id/applicants",
  authRequired,
  requireRole("employer"),
  async (req, res) => {
    const jobId = req.params.id;

    if (USE_MEMORY) {
      const job = memoryJobs.find((j) => j._id == jobId);
      if (!job) return res.status(404).json({ error: "job not found" });
      if (!job.postedBy || job.postedBy.userId !== req.user.id) {
        return res
          .status(403)
          .json({ error: "only the poster can view applicants" });
      }
      return res.json(job.applicants || []);
    }

    const job = await Internship.findById(jobId);
    if (!job) return res.status(404).json({ error: "job not found" });
    const postedById = job.postedBy?.userId;
    if (!postedById || postedById !== req.user.id) {
      return res
        .status(403)
        .json({ error: "only the poster can view applicants" });
    }
    res.json(job.applicants || []);
  }
);

app.listen(PORT, () => console.log(`🚀 Running on http://localhost:${PORT}`));

