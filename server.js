import express from "express";
import mongoose from "mongoose";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import session from "express-session";
import MongoStore from "connect-mongo";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ----- Mongo -----
await mongoose.connect(process.env.MONGODB_URI, {
  serverSelectionTimeoutMS: 5000,
});

// ----- Schemas -----
const UserSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ["poster", "seeker"], required: true },
  },
  { timestamps: true }
);
const User = mongoose.model("User", UserSchema);

const InternshipSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    company: { type: String, required: true, trim: true },
    role: { type: String, required: true, trim: true },
    postedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    }, // poster id
  },
  { timestamps: true }
);
const Internship = mongoose.model("Internship", InternshipSchema);

const ApplicationSchema = new mongoose.Schema(
  {
    internship: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Internship",
      required: true,
    },
    seeker: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: true }
);
// prevent duplicate applications by same seeker to same internship
ApplicationSchema.index({ internship: 1, seeker: 1 }, { unique: true });
const Application = mongoose.model("Application", ApplicationSchema);

// ----- Sessions (NO JWT) -----
app.set("trust proxy", 1);
app.use(
  session({
    name: "sid",
    secret: process.env.SESSION_SECRET || "change_me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false, // set true behind HTTPS/proxy
      maxAge: 1000 * 60 * 60 * 8, // 8 hours
    },
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      ttl: 60 * 60 * 8,
    }),
  })
);

// ----- Auth helpers -----
function requireLogin(req, res, next) {
  if (!req.session.user)
    return res.status(401).json({ error: "auth required" });
  next();
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user)
      return res.status(401).json({ error: "auth required" });
    if (req.session.user.role !== role)
      return res.status(403).json({ error: `requires ${role}` });
    next();
  };
}

// ----- Auth routes -----
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, role } = req.body || {};
    if (!email || !password || !role || !["poster", "seeker"].includes(role))
      return res
        .status(400)
        .json({ error: "email, password, role=poster|seeker required" });

    const exists = await User.findOne({ email });
    if (exists)
      return res.status(409).json({ error: "email already registered" });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash, role });

    // login immediately
    req.session.user = {
      _id: user._id.toString(),
      email: user.email,
      role: user.role,
    };
    res.status(201).json(req.session.user);
  } catch (e) {
    res.status(500).json({ error: "registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "email and password required" });

  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ error: "invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });

  req.session.user = {
    _id: user._id.toString(),
    email: user.email,
    role: user.role,
  };
  res.json(req.session.user);
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("sid");
    res.json({ ok: true });
  });
});

app.get("/api/auth/me", (req, res) => {
  res.json(req.session.user || null);
});

// ----- Internship routes -----
app.get("/api/internships", async (req, res) => {
  const items = await Internship.find()
    .sort({ createdAt: -1 })
    .populate("postedBy", "email role")
    .lean();
  res.json(items);
});

// CREATE (poster only)
app.post("/api/internships", requireRole("poster"), async (req, res) => {
  const { title, company, role } = req.body || {};
  if (!title || !company || !role)
    return res.status(400).json({ error: "title, company, role required" });

  const job = await Internship.create({
    title,
    company,
    role,
    postedBy: req.session.user._id,
  });
  res.status(201).json(job);
});

// APPLY (seeker only)
app.post(
  "/api/internships/:id/apply",
  requireRole("seeker"),
  async (req, res) => {
    try {
      const internshipId = req.params.id;
      const internship = await Internship.findById(internshipId);
      if (!internship) return res.status(404).json({ error: "not found" });

      const appDoc = await Application.create({
        internship: internshipId,
        seeker: req.session.user._id,
      });
      res.status(201).json({ ok: true, applicationId: appDoc._id });
    } catch (e) {
      // duplicate application
      if (e.code === 11000)
        return res.status(409).json({ error: "already applied" });
      res.status(500).json({ error: "apply failed" });
    }
  }
);

// ----- Static client -----
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Mini Job Board (MERN + Sessions) http://localhost:${PORT}`)
);
