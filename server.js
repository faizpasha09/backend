const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("./db");
const multer = require("multer");
const path = require("path");

const app = express();

// 1. CORS Configuration (Sabse important!)
// Yahan "https://medconnect.cloud" tera frontend domain hai.
app.use(cors({
    origin: ["https://medconnect.cloud", "http://72.61.227.128"],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
}));

app.use(bodyParser.json());

// 2. Uploads folder ko static banana taaki images dikh sakein
// Live server pe path resolution thoda alag hota hai isliye path.join use kiya hai
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Agar frontend Netlify pe hai, toh server.js se index.html serve karne ki zaroorat nahi hai.
// Lekin backup ke liye rakh sakte ho.

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, "uploads/"),
    filename: (req, file, cb) =>
        cb(null, Date.now() + path.extname(file.originalname)),
});

const upload = multer({ storage });

const SECRET_KEY = "medconnect_secret";

// ... (Baaki saara API logic: signup, login, profile - same rahega) ...

// ================= SERVER =================
// KVM pe 5000 port hi rehne do, lekin console log update kar dete hain
const PORT = 5000;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running live on http://72.61.227.128:${PORT} 🚀`);
});