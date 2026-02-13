
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("./db");
const sendVerificationEmail = require("./email");
const multer = require("multer");
const path = require("path");


const app = express();
// ===== Multer Storage Setup =====
/*const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "uploads/");
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + path.extname(file.originalname);
        cb(null, uniqueName);
    },
}); */

// ROOT folder ki saari static files serve karega
app.use(express.static(__dirname));

// Optional: direct login page open karne ke liye
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, "uploads/"),
    filename: (req, file, cb) =>
        cb(null, Date.now() + path.extname(file.originalname)),
});

//const upload = multer({ storage });


const upload = multer({ storage });

app.use(cors());
app.use(bodyParser.json());
app.use("/uploads", express.static("uploads"));

const SECRET_KEY = "medconnect_secret";

// ================= SIGNUP =================
app.post("/api/signup", async (req, res) => {
    const { name, email, specialization, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const sql =
            "INSERT INTO doctors (name, email, specialization, password) VALUES (?, ?, ?, ?)";

        db.query(sql, [name, email, specialization, hashedPassword], (err, result) => {
            if (err) {
                return res.status(400).json({ message: "Email already exists" });
            }

            res.json({ message: "Doctor registered successfully ✅" });
        });
    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
});


// ================= LOGIN =================
app.post("/api/login", (req, res) => {
    const { email, password } = req.body;

    const sql = "SELECT * FROM doctors WHERE email = ?";

    db.query(sql, [email], async (err, results) => {

        if (err || results.length === 0) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        const doctor = results[0];

        const isMatch = await bcrypt.compare(password, doctor.password);

        if (!isMatch) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        // 🔐 Check doctor verification status
        /* if (doctor.status !== "verified") {
             return res.status(403).json({
                 message: "Your account is under verification. Please wait for approval.",
             });
         } */

        const token = jwt.sign({ id: doctor.id }, SECRET_KEY, { expiresIn: "7d" });

        res.json({
            message: "Login successful ✅",
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

// ===== VERIFY DOCTOR (ADMIN USE) =====


// ===== GET PENDING DOCTORS (ADMIN) =====
app.get("/api/admin/pending-doctors", (req, res) => {
    const sql = "SELECT id, name, email, specialization, status FROM doctors WHERE status = 'pending'";

    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ message: "Failed to load doctors" });

        res.json(results);
    });
});



// ======== GET LOGGED IN DOCTOR ========
app.get("/api/me", (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: "No token" });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, SECRET_KEY);

        const sql = "SELECT id, name, email, specialization FROM doctors WHERE id = ?";

        db.query(sql, [decoded.id], (err, results) => {
            if (err || results.length === 0) {
                return res.status(401).json({ message: "Invalid token" });
            }

            res.json(results[0]);
        });
    } catch (error) {
        res.status(401).json({ message: "Token expired" });
    }
});

// ===== GET PROFILE =====
app.get("/api/profile", (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "No token" });

    const decoded = jwt.verify(token, SECRET_KEY);

    db.query(
        "SELECT id,name,email,profile_image,about,profession FROM doctors WHERE id=?",
        [decoded.id],
        (err, results) => {
            if (err || results.length === 0)
                return res.status(404).json({ message: "Profile not found" });

            res.json(results[0]);
        }
    );
});


// ===== UPDATE PROFILE =====
app.put("/api/profile", upload.single("profile_image"), (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "No token" });

    const decoded = jwt.verify(token, SECRET_KEY);

    const { name, about, profession } = req.body;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

    let sql = "UPDATE doctors SET name=?, about=?, profession=?";
    const params = [name, about, profession];

    if (imagePath) {
        sql += ", profile_image=?";
        params.push(imagePath);
    }

    sql += " WHERE id=?";
    params.push(decoded.id);

    db.query(sql, params, (err) => {
        if (err) return res.status(500).json({ message: "Update failed" });

        res.json({ message: "Profile updated successfully ✅" });
    });
});



// ===== CREATE POST =====
app.post("/api/posts", upload.single("image"), (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: "No token" });

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, SECRET_KEY);

        const content = req.body.content;
        const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

        const sql =
            "INSERT INTO posts (doctor_id, content, image) VALUES (?, ?, ?)";

        db.query(sql, [decoded.id, content, imagePath], (err) => {
            if (err) return res.status(500).json({ message: "Post failed" });

            res.json({ message: "Post created successfully ✅" });
        });
    } catch {
        res.status(401).json({ message: "Invalid token" });
    }
});


// ===== GET ALL POSTS =====
app.get("/api/posts", (req, res) => {
    const sql = `
  SELECT 
    posts.*, 
    doctors.name, 
    doctors.profession,
    doctors.profile_image,
    COUNT(DISTINCT likes.id) AS like_count
  FROM posts
  JOIN doctors ON posts.doctor_id = doctors.id
  LEFT JOIN likes ON likes.post_id = posts.id
  GROUP BY posts.id
  ORDER BY posts.created_at DESC
`;


    db.query(sql, async (err, posts) => {
        if (err) return res.status(500).json({ message: "Failed to load posts" });

        // Load comments for each post
        const commentSql = `
      SELECT comments.*, doctors.name 
      FROM comments 
      JOIN doctors ON comments.doctor_id = doctors.id
      WHERE post_id = ?
      ORDER BY comments.created_at ASC
    `;

        for (let post of posts) {
            post.comments = await new Promise((resolve) => {
                db.query(commentSql, [post.id], (err, results) => {
                    resolve(results || []);
                });
            });
        }

        res.json(posts);
    });
});

// ===== DELETE POST =====
app.delete("/api/posts/:id", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: "No token" });

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const postId = req.params.id;

        // Check post owner
        const checkSql = "SELECT * FROM posts WHERE id = ? AND doctor_id = ?";
        db.query(checkSql, [postId, decoded.id], (err, results) => {
            if (results.length === 0) {
                return res.status(403).json({ message: "Not allowed" });
            }

            const deleteSql = "DELETE FROM posts WHERE id = ?";
            db.query(deleteSql, [postId], () => {
                res.json({ message: "Post deleted 🗑️" });
            });
        });
    } catch {
        res.status(401).json({ message: "Invalid token" });
    }
});


// ===== TOGGLE LIKE =====
app.post("/api/posts/:id/like", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: "No token" });

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const postId = req.params.id;

        // Check existing like
        const checkSql = "SELECT * FROM likes WHERE doctor_id = ? AND post_id = ?";
        db.query(checkSql, [decoded.id, postId], (err, results) => {
            if (results.length > 0) {
                // Unlike
                const deleteSql = "DELETE FROM likes WHERE doctor_id = ? AND post_id = ?";
                db.query(deleteSql, [decoded.id, postId], () => {
                    res.json({ message: "Unliked" });
                });
            } else {
                // Like
                const insertSql = "INSERT INTO likes (doctor_id, post_id) VALUES (?, ?)";
                db.query(insertSql, [decoded.id, postId], () => {
                    res.json({ message: "Liked" });
                });
            }
        });
    } catch {
        res.status(401).json({ message: "Invalid token" });
    }
});

// ===== ADD COMMENT =====
app.post("/api/posts/:id/comment", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: "No token" });

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const postId = req.params.id;
        const { content } = req.body;

        const sql =
            "INSERT INTO comments (doctor_id, post_id, content) VALUES (?, ?, ?)";

        db.query(sql, [decoded.id, postId, content], (err) => {
            if (err) return res.status(500).json({ message: "Comment failed" });

            res.json({ message: "Comment added ✅" });
        });
    } catch {
        res.status(401).json({ message: "Invalid token" });
    }
});


// ================= SERVER =================
app.listen(5000, () => {
    console.log("Server running on http://localhost:5000 🚀");
});
