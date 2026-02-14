require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const morgan = require("morgan");

const db = require("./db");

const app = express();

/* ================= SECURITY ================= */

app.use(helmet());

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many requests from this IP. Try later.",
  })
);

app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

/* ================= FILE UPLOAD ================= */

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, "uploads/"),
  filename: (_, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname)),
});

const fileFilter = (_, file, cb) => {
  const allowed = [".jpg", ".jpeg", ".png"];
  const ext = path.extname(file.originalname).toLowerCase();

  if (!allowed.includes(ext)) {
    return cb(new Error("Only JPG, JPEG, PNG allowed"));
  }

  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 2 * 1024 * 1024 },
});

app.use("/uploads", express.static("uploads"));

/* ================= AUTH MIDDLEWARE ================= */

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Invalid or expired token" });
  }
};

/* ================= SIGNUP ================= */

app.post(
  "/api/signup",
  [
    body("email").isEmail(),
    body("password").isLength({ min: 6 }),
    body("name").notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json(errors);

    const { name, email, specialization, password } = req.body;

    try {
      const hash = await bcrypt.hash(password, 10);

      db.query(
        "INSERT INTO doctors (name,email,specialization,password) VALUES (?,?,?,?)",
        [name, email, specialization, hash],
        (err) => {
          if (err) return res.status(400).json({ message: "Email already exists" });

          res.json({ message: "Signup successful ✅" });
        }
      );
    } catch {
      res.status(500).json({ message: "Server error" });
    }
  }
);

/* ================= LOGIN ================= */

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM doctors WHERE email=?", [email], async (err, rows) => {
    if (err || rows.length === 0)
      return res.status(400).json({ message: "Invalid credentials" });

    const doctor = rows[0];
    const match = await bcrypt.compare(password, doctor.password);

    if (!match) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: doctor.id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      token,
      doctor: {
        id: doctor.id,
        name: doctor.name,
        email: doctor.email,
        specialization: doctor.specialization,
      },
    });
  });
});

/* ================= PROFILE ================= */

app.get("/api/profile", auth, (req, res) => {
  db.query(
    "SELECT id,name,email,profile_image,about,profession FROM doctors WHERE id=?",
    [req.user.id],
    (err, rows) => {
      if (err || rows.length === 0)
        return res.status(404).json({ message: "Profile not found" });

      res.json(rows[0]);
    }
  );
});

app.put("/api/profile", auth, upload.single("profile_image"), (req, res) => {
  const { name, about, profession } = req.body;
  const img = req.file ? `/uploads/${req.file.filename}` : null;

  let sql = "UPDATE doctors SET name=?,about=?,profession=?";
  const params = [name, about, profession];

  if (img) {
    sql += ",profile_image=?";
    params.push(img);
  }

  sql += " WHERE id=?";
  params.push(req.user.id);

  db.query(sql, params, (err) => {
    if (err) return res.status(500).json({ message: "Update failed" });

    res.json({ message: "Profile updated ✅" });
  });
});

/* ================= POSTS ================= */

app.post("/api/posts", auth, upload.single("image"), (req, res) => {
  const content = req.body.content;
  const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

  db.query(
    "INSERT INTO posts (doctor_id, content, image) VALUES (?,?,?)",
    [req.user.id, content, imagePath],
    (err) => {
      if (err) return res.status(500).json({ message: "Post failed" });

      res.json({ message: "Post created ✅" });
    }
  );
});

app.get("/api/posts", (req, res) => {
  const sql = `
    SELECT posts.*, doctors.name, doctors.profession, doctors.profile_image
    FROM posts
    JOIN doctors ON posts.doctor_id = doctors.id
    ORDER BY posts.created_at DESC
  `;

  db.query(sql, (err, posts) => {
    if (err) return res.status(500).json({ message: "Failed to load posts" });

    res.json(posts);
  });
});

/* ================= GLOBAL ERROR ================= */

app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(500).json({ message: err.message || "Server error" });
});

/* ================= SERVER ================= */

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 MedConnect backend running on port ${PORT}`);
});
