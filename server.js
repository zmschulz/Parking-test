// Parking reservation server with Google sign-in. Zero dependencies, Node 18+.
// Configure via .env (see .env.example), then run: node server.js
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ---- minimal .env loader ----
try {
  for (const line of fs.readFileSync(path.join(__dirname, ".env"), "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
} catch {}

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const ALLOWED_DOMAIN = (process.env.ALLOWED_DOMAIN || "").toLowerCase();   // optional, e.g. mycompany.com
const MAX_PER_DAY = Number(process.env.MAX_RESERVATIONS_PER_DAY) || 1;       // per-user limit
const SECURE = BASE_URL.startsWith("https://");

if (!CLIENT_ID || !CLIENT_SECRET || SESSION_SECRET.length < 16) {
  console.error("Missing config: set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and a SESSION_SECRET (16+ chars) in .env. See README.md.");
  process.exit(1);
}

const SLOTS = ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8"];
const MAX_MIN = 180, STEP = 30;
const SESSION_TTL = 7 * 24 * 3600;   // seconds
const DATA_FILE = path.join(__dirname, "data.json");
const PUBLIC = path.join(__dirname, "public");

let reservations = [];
try { reservations = JSON.parse(fs.readFileSync(DATA_FILE, "utf8")); } catch { reservations = []; }
const save = () => fs.writeFileSync(DATA_FILE, JSON.stringify(reservations, null, 2));

// ---- helpers: json, cookies, signed sessions ----
const send = (res, code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
const redirect = (res, loc, cookies = []) => { res.writeHead(302, { Location: loc, "Set-Cookie": cookies }); res.end(); };
const parseCookies = req => Object.fromEntries((req.headers.cookie || "").split(";").map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(p => p[0]));
const cookie = (name, value, maxAge) => `${name}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${SECURE ? "; Secure" : ""}`;
const sign = s => crypto.createHmac("sha256", SESSION_SECRET).update(s).digest("base64url");
const makeSession = user => { const p = Buffer.from(JSON.stringify({ ...user, exp: Date.now() / 1000 + SESSION_TTL })).toString("base64url"); return p + "." + sign(p); };
function readSession(req) {
  const raw = parseCookies(req).session; if (!raw) return null;
  const [p, sig] = raw.split("."); if (!p || !sig) return null;
  const a = Buffer.from(sig), b = Buffer.from(sign(p));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const u = JSON.parse(Buffer.from(p, "base64url").toString()); return u.exp > Date.now() / 1000 ? u : null; } catch { return null; }
}
const readBody = req => new Promise((resolve, reject) => {
  let b = ""; req.on("data", c => { b += c; if (b.length > 1e5) req.destroy(); });
  req.on("end", () => { try { resolve(JSON.parse(b || "{}")); } catch (e) { reject(e); } });
});
const publicView = (r, sub) => ({ id: r.id, slot: r.slot, date: r.date, startMin: r.startMin, endMin: r.endMin, endTs: r.endTs, mine: r.owner === sub });

// ---- Google OAuth (authorization code flow) ----
async function handleAuth(req, res, url) {
  if (url.pathname === "/auth/google") {
    const state = crypto.randomBytes(16).toString("hex");
    const q = new URLSearchParams({ client_id: CLIENT_ID, redirect_uri: BASE_URL + "/auth/google/callback", response_type: "code", scope: "openid email profile", state, prompt: "select_account" });
    if (ALLOWED_DOMAIN) q.set("hd", ALLOWED_DOMAIN);
    return redirect(res, "https://accounts.google.com/o/oauth2/v2/auth?" + q, [cookie("oauth_state", state, 600)]);
  }
  if (url.pathname === "/auth/google/callback") {
    const fail = msg => redirect(res, "/?error=" + encodeURIComponent(msg), [cookie("oauth_state", "", 0)]);
    if (url.searchParams.get("error")) return fail("Sign-in was cancelled.");
    const state = url.searchParams.get("state"), code = url.searchParams.get("code");
    if (!state || !code || state !== parseCookies(req).oauth_state) return fail("Invalid sign-in request. Please try again.");
    try {
      const r = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ code, client_id: CLIENT_ID, client_secret: CLIENT_SECRET, redirect_uri: BASE_URL + "/auth/google/callback", grant_type: "authorization_code" }),
      });
      const tok = await r.json();
      if (!r.ok || !tok.id_token) return fail("Google sign-in failed.");
      // The ID token came straight from Google's token endpoint over TLS, so we only need to check its claims.
      const c = JSON.parse(Buffer.from(tok.id_token.split(".")[1], "base64url").toString());
      if (c.aud !== CLIENT_ID || !["accounts.google.com", "https://accounts.google.com"].includes(c.iss) || c.exp < Date.now() / 1000) return fail("Google sign-in failed.");
      if (!c.email || !c.email_verified) return fail("Your Google email is not verified.");
      if (ALLOWED_DOMAIN && !c.email.toLowerCase().endsWith("@" + ALLOWED_DOMAIN)) return fail(`Only @${ALLOWED_DOMAIN} accounts can sign in.`);
      return redirect(res, "/", [cookie("session", makeSession({ sub: c.sub, email: c.email, name: c.name || c.email }), SESSION_TTL), cookie("oauth_state", "", 0)]);
    } catch { return fail("Google sign-in failed."); }
  }
  if (url.pathname === "/auth/logout") return redirect(res, "/", [cookie("session", "", 0)]);
  send(res, 404, { error: "Not found." });
}

// ---- API (requires sign-in) ----
async function handleApi(req, res, url) {
  const user = readSession(req);
  if (!user) return send(res, 401, { error: "Please sign in." });
  const sub = user.sub;

  if (req.method === "GET" && url.pathname === "/api/me") return send(res, 200, { name: user.name, email: user.email, maxPerDay: MAX_PER_DAY });

  if (req.method === "GET" && url.pathname === "/api/reservations") {
    const date = url.searchParams.get("date");
    const list = reservations.filter(r => (date ? r.date === date : r.owner === sub));
    return send(res, 200, list.map(r => publicView(r, sub)));
  }

  if (req.method === "POST" && url.pathname === "/api/reservations") {
    let b; try { b = await readBody(req); } catch { return send(res, 400, { error: "Invalid JSON." }); }
    const { slot, date, startMin, durMin, tzOffset } = b;
    if (!SLOTS.includes(slot)) return send(res, 400, { error: "Unknown slot." });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return send(res, 400, { error: "Invalid date." });
    if (!Number.isInteger(startMin) || !Number.isInteger(durMin)) return send(res, 400, { error: "Invalid time." });
    if (startMin % STEP || durMin % STEP || startMin < 0) return send(res, 400, { error: "Times must be in 30-minute steps." });
    if (durMin <= 0 || durMin > MAX_MIN) return send(res, 400, { error: "Maximum reservation is 3 hours." });
    const endMin = startMin + durMin;
    if (endMin > 1440) return send(res, 400, { error: "A reservation can't extend past midnight." });
    const [y, m, d] = date.split("-").map(Number);
    const startTs = Date.UTC(y, m - 1, d) + startMin * 60000 + (Number(tzOffset) || 0) * 60000;
    if (startTs < Date.now() - 60000) return send(res, 400, { error: "That start time is in the past." });

    // Per-user limit (checked server-side, so it can't be bypassed from the browser).
    const mineThatDay = reservations.filter(r => r.owner === sub && r.date === date).length;
    if (mineThatDay >= MAX_PER_DAY) return send(res, 403, { error: `Limit reached: you can have at most ${MAX_PER_DAY} reservation${MAX_PER_DAY > 1 ? "s" : ""} per day. Cancel one to book another.` });

    // Overlap check runs synchronously, so two requests can never both pass.
    if (reservations.some(r => r.slot === slot && r.date === date && r.startMin < endMin && startMin < r.endMin))
      return send(res, 409, { error: "That slot is already booked for an overlapping time. Please choose another." });

    const r = { id: Date.now().toString(36) + crypto.randomBytes(3).toString("hex"), owner: sub, email: user.email, slot, date, startMin, endMin, endTs: startTs + durMin * 60000 };
    reservations.push(r); save();
    return send(res, 201, publicView(r, sub));
  }

  if (req.method === "DELETE" && url.pathname.startsWith("/api/reservations/")) {
    const i = reservations.findIndex(r => r.id === url.pathname.split("/").pop() && r.owner === sub);
    if (i < 0) return send(res, 404, { error: "Reservation not found." });
    reservations.splice(i, 1); save();
    return send(res, 200, { ok: true });
  }
  send(res, 404, { error: "Not found." });
}

const TYPES = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript" };
http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  const fail = () => send(res, 500, { error: "Server error." });
  if (url.pathname.startsWith("/auth/")) return handleAuth(req, res, url).catch(fail);
  if (url.pathname.startsWith("/api/")) return handleApi(req, res, url).catch(fail);
  const file = path.join(PUBLIC, url.pathname === "/" ? "index.html" : path.normalize(url.pathname));
  if (!file.startsWith(PUBLIC)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end("Not found"); }
    res.writeHead(200, { "Content-Type": TYPES[path.extname(file)] || "application/octet-stream" });
    res.end(data);
  });
}).listen(PORT, () => console.log(`Parking app running at ${BASE_URL}`));
