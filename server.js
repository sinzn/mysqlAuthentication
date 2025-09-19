require("dotenv").config();
const express = require("express");
const session = require("express-session");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

// MySQL pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});

// Serve login/register page
app.get("/", (req, res) => {
  if (req.session.user) {
    res.send(`
      <div align="center" style="margin-top:100px;">
        <h2>Welcome ${req.session.user.username}</h2>
        <a href="/logout"><button>Logout</button></a>
      </div>
    `);
  } else {
    res.sendFile(path.join(__dirname, "index.html"));
  }
});

// Register
app.post("/register", async (req, res) => {
  const { ru, re, rp } = req.body;
  const hash = await bcrypt.hash(rp, 10);
  try {
    await pool.query("INSERT INTO users (username,email,password) VALUES (?,?,?)", [ru, re, hash]);
    res.send("✅ Registered successfully. <a href='/'>Login now</a>");
  } catch {
    res.send("⚠️ Username or Email already exists.");
  }
});

// Login (by email)
app.post("/login", async (req, res) => {
  const { u, p } = req.body;
  const [rows] = await pool.query("SELECT * FROM users WHERE email=?", [u]);
  if (rows.length && await bcrypt.compare(p, rows[0].password)) {
    req.session.user = { id: rows[0].id, username: rows[0].username };
    res.redirect("/");
  } else {
    res.send("❌ Invalid email or password. <a href='/'>Try again</a>");
  }
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.listen(3000, () => console.log("Auth server running on http://localhost:3000"));
