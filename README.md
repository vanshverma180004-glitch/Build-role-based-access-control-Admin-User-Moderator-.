# 8.3-html-23bcs12579-625b
Build role-based access control (Admin/User/Moderator).


// app.js
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(bodyParser.json());
app.use(cors());

// ===== CONFIG =====
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecret_demo_key"; // use env var in production
const JWT_EXPIRES_IN = "1h"; // token lifetime

// ===== In-memory "database" (for demo) =====
const users = []; // store { id, email, passwordHash, role, name }

// Seed example users (passwords: adminpass, modpass, userpass)
(async function seed() {
  const pwAdmin = await bcrypt.hash("adminpass", 10);
  const pwMod = await bcrypt.hash("modpass", 10);
  const pwUser = await bcrypt.hash("userpass", 10);

  users.push({ id: 1, email: "admin@example.com", name: "Alice Admin", passwordHash: pwAdmin, role: "admin" });
  users.push({ id: 2, email: "mod@example.com", name: "Moe Mod", passwordHash: pwMod, role: "moderator" });
  users.push({ id: 3, email: "user@example.com", name: "Uma User", passwordHash: pwUser, role: "user" });
})();

// ===== Logging middleware (request logger) =====
app.use((req, res, next) => {
  const now = new Date().toISOString();
  const authHeader = req.headers.authorization || "";
  const userInfo = authHeader.startsWith("Bearer ") ? "(token provided)" : "(no token)";
  console.log(`[${now}] ${req.method} ${req.url} ${userInfo}`);
  next();
});

// ===== Auth middleware =====
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Missing or invalid Authorization header" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // payload contains { userId, role, email, name, iat, exp }
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// role authorization middleware: allow if user's role is included
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(403).json({ message: "No role information found" });
    }
    if (allowedRoles.includes(req.user.role)) return next();
    return res.status(403).json({ message: "Forbidden: insufficient role" });
  };
}

// ===== Routes =====

// Register (demo: no email uniqueness checks in-depth)
app.post("/register", async (req, res) => {
  const { email, password, name, role } = req.body;
  if (!email || !password || !name) return res.status(400).json({ message: "email, password, name required" });
  if (users.find(u => u.email === email)) return res.status(409).json({ message: "Email already exists" });
  const hash = await bcrypt.hash(password, 10);
  const id = users.length ? Math.max(...users.map(u => u.id)) + 1 : 1;
  const newUser = { id, email, name, passwordHash: hash, role: role || "user" };
  users.push(newUser);
  return res.status(201).json({ message: "Registered", user: { id, email, name, role: newUser.role } });
});

// Login -> returns JWT
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: "Invalid credentials" });

  const payload = { userId: user.id, email: user.email, name: user.name, role: user.role };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  return res.json({ token, user: payload });
});

// Public route
app.get("/public", (req, res) => {
  res.json({ message: "This is public." });
});

// Protected: any authenticated user
app.get("/profile", authenticateJWT, (req, res) => {
  res.json({ message: "Your profile", user: req.user });
});

/*
 Role-protected endpoints:
 - /user-area -> any logged in user
 - /moderator-area -> moderators OR admins
 - /admin-area -> admins only
*/
app.get("/user-area", authenticateJWT, authorizeRoles("user", "moderator", "admin"), (req, res) => {
  res.json({ message: "Welcome to user area.", user: req.user });
});

app.get("/moderator-area", authenticateJWT, authorizeRoles("moderator", "admin"), (req, res) => {
  res.json({ message: "Moderator content (moderator + admin OK).", user: req.user });
});

app.get("/admin-area", authenticateJWT, authorizeRoles("admin"), (req, res) => {
  res.json({ message: "Admin-only content.", user: req.user });
});

// Example: endpoint where admin can change roles (admin-only)
app.post("/admin/change-role", authenticateJWT, authorizeRoles("admin"), (req, res) => {
  const { userId, newRole } = req.body;
  const target = users.find(u => u.id === Number(userId));
  if (!target) return res.status(404).json({ message: "User not found" });
  target.role = newRole;
  res.json({ message: "Role updated", user: { id: target.id, email: target.email, role: target.role } });
});

// Simple list users (admin+moderator can see)
app.get("/users", authenticateJWT, authorizeRoles("moderator", "admin"), (req, res) => {
  const safe = users.map(u => ({ id: u.id, email: u.email, name: u.name, role: u.role }));
  res.json({ users: safe });
});

app.listen(PORT, () => {
  console.log(`RBAC demo server started on http://localhost:${PORT}`);
  console.log("Seeded users (email / password): admin@example.com / adminpass, mod@example.com / modpass, user@example.com / userpass");
});
// app.js
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(bodyParser.json());
app.use(cors());

// ===== CONFIG =====
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecret_demo_key"; // use env var in production
const JWT_EXPIRES_IN = "1h"; // token lifetime

// ===== In-memory "database" (for demo) =====
const users = []; // store { id, email, passwordHash, role, name }

// Seed example users (passwords: adminpass, modpass, userpass)
(async function seed() {
  const pwAdmin = await bcrypt.hash("adminpass", 10);
  const pwMod = await bcrypt.hash("modpass", 10);
  const pwUser = await bcrypt.hash("userpass", 10);

  users.push({ id: 1, email: "admin@example.com", name: "Alice Admin", passwordHash: pwAdmin, role: "admin" });
  users.push({ id: 2, email: "mod@example.com", name: "Moe Mod", passwordHash: pwMod, role: "moderator" });
  users.push({ id: 3, email: "user@example.com", name: "Uma User", passwordHash: pwUser, role: "user" });
})();

// ===== Logging middleware (request logger) =====
app.use((req, res, next) => {
  const now = new Date().toISOString();
  const authHeader = req.headers.authorization || "";
  const userInfo = authHeader.startsWith("Bearer ") ? "(token provided)" : "(no token)";
  console.log(`[${now}] ${req.method} ${req.url} ${userInfo}`);
  next();
});

// ===== Auth middleware =====
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Missing or invalid Authorization header" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // payload contains { userId, role, email, name, iat, exp }
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// role authorization middleware: allow if user's role is included
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(403).json({ message: "No role information found" });
    }
    if (allowedRoles.includes(req.user.role)) return next();
    return res.status(403).json({ message: "Forbidden: insufficient role" });
  };
}

// ===== Routes =====

// Register (demo: no email uniqueness checks in-depth)
app.post("/register", async (req, res) => {
  const { email, password, name, role } = req.body;
  if (!email || !password || !name) return res.status(400).json({ message: "email, password, name required" });
  if (users.find(u => u.email === email)) return res.status(409).json({ message: "Email already exists" });
  const hash = await bcrypt.hash(password, 10);
  const id = users.length ? Math.max(...users.map(u => u.id)) + 1 : 1;
  const newUser = { id, email, name, passwordHash: hash, role: role || "user" };
  users.push(newUser);
  return res.status(201).json({ message: "Registered", user: { id, email, name, role: newUser.role } });
});

// Login -> returns JWT
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: "Invalid credentials" });

  const payload = { userId: user.id, email: user.email, name: user.name, role: user.role };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  return res.json({ token, user: payload });
});

// Public route
app.get("/public", (req, res) => {
  res.json({ message: "This is public." });
});

// Protected: any authenticated user
app.get("/profile", authenticateJWT, (req, res) => {
  res.json({ message: "Your profile", user: req.user });
});

/*
 Role-protected endpoints:
 - /user-area -> any logged in user
 - /moderator-area -> moderators OR admins
 - /admin-area -> admins only
*/
app.get("/user-area", authenticateJWT, authorizeRoles("user", "moderator", "admin"), (req, res) => {
  res.json({ message: "Welcome to user area.", user: req.user });
});

app.get("/moderator-area", authenticateJWT, authorizeRoles("moderator", "admin"), (req, res) => {
  res.json({ message: "Moderator content (moderator + admin OK).", user: req.user });
});

app.get("/admin-area", authenticateJWT, authorizeRoles("admin"), (req, res) => {
  res.json({ message: "Admin-only content.", user: req.user });
});

// Example: endpoint where admin can change roles (admin-only)
app.post("/admin/change-role", authenticateJWT, authorizeRoles("admin"), (req, res) => {
  const { userId, newRole } = req.body;
  const target = users.find(u => u.id === Number(userId));
  if (!target) return res.status(404).json({ message: "User not found" });
  target.role = newRole;
  res.json({ message: "Role updated", user: { id: target.id, email: target.email, role: target.role } });
});

// Simple list users (admin+moderator can see)
app.get("/users", authenticateJWT, authorizeRoles("moderator", "admin"), (req, res) => {
  const safe = users.map(u => ({ id: u.id, email: u.email, name: u.name, role: u.role }));
  res.json({ users: safe });
});

app.listen(PORT, () => {
  console.log(`RBAC demo server started on http://localhost:${PORT}`);
  console.log("Seeded users (email / password): admin@example.com / adminpass, mod@example.com / modpass, user@example.com / userpass");
});



<!-- index.html -->
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>RBAC Demo — Login</title>
  <style>
    body { font-family: Arial, sans-serif; max-width:800px; margin:40px auto; }
    .box { border:1px solid #ddd; padding:20px; border-radius:8px; margin-bottom:16px; }
    button { padding:8px 12px; margin-right:8px; }
    pre { background:#f7f7f7; padding:10px; border-radius:6px; overflow:auto; }
  </style>
</head>
<body>
  <h1>RBAC Demo (Admin / Moderator / User)</h1>

  <div class="box">
    <h3>Login</h3>
    <label>Email: <input id="email" value="admin@example.com"></label><br><br>
    <label>Password: <input id="password" type="password" value="adminpass"></label><br><br>
    <button id="btnLogin">Login</button>
    <button id="btnLogout" style="display:none">Logout</button>
  </div>

  <div class="box" id="userInfo" style="display:none">
    <h3>Current User</h3>
    <div id="who"></div>
    <div style="margin-top:12px;">
      <button id="btnProfile">Get Profile</button>
      <button id="btnUserArea">User area</button>
      <button id="btnModArea">Moderator area</button>
      <button id="btnAdminArea">Admin area</button>
      <button id="btnListUsers">List users (mod+admin)</button>
    </div>
  </div>

  <div class="box">
    <h3>Response</h3>
    <pre id="resp">Not yet called.</pre>
  </div>

<script>
const API = "http://localhost:4000";
let token = null;
let currentUser = null;

function showResp(obj) {
  document.getElementById("resp").textContent = JSON.stringify(obj, null, 2);
}

function setLoggedIn(user, jwt) {
  token = jwt;
  currentUser = user;
  document.getElementById("userInfo").style.display = "block";
  document.getElementById("btnLogout").style.display = "inline-block";
  document.getElementById("btnLogin").style.display = "none";
  document.getElementById("who").textContent = `${user.name} (${user.email}) — role: ${user.role}`;
}

function clearLogin() {
  token = null;
  currentUser = null;
  document.getElementById("userInfo").style.display = "none";
  document.getElementById("btnLogout").style.display = "none";
  document.getElementById("btnLogin").style.display = "inline-block";
  showResp("Logged out");
}

document.getElementById("btnLogin").addEventListener("click", async () => {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  try {
    const r = await fetch(API + "/login", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ email, password })
    });
    const data = await r.json();
    if (!r.ok) return showResp(data);
    setLoggedIn(data.user, data.token);
    showResp({ message: "Logged in", user: data.user });
  } catch (err) {
    showResp({ error: err.message });
  }
});

document.getElementById("btnLogout").addEventListener("click", () => {
  clearLogin();
});

async function call(path, method="GET", body=null) {
  const headers = { "Content-Type":"application/json" };
  if (token) headers["Authorization"] = "Bearer " + token;
  const r = await fetch(API + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await r.json();
  showResp({ status: r.status, ok: r.ok, body: data });
}

document.getElementById("btnProfile").addEventListener("click", () => call("/profile"));
document.getElementById("btnUserArea").addEventListener("click", () => call("/user-area"));
document.getElementById("btnModArea").addEventListener("click", () => call("/moderator-area"));
document.getElementById("btnAdminArea").addEventListener("click", () => call("/admin-area"));
document.getElementById("btnListUsers").addEventListener("click", () => call("/users"));
</script>
</body>
</html>
