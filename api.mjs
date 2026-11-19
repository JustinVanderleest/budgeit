// Budgeit server — runs as a Netlify Function at /api/*
// Storage: Netlify Blobs (store "budgeit"): "users", "data", "vapid"
// Push: web-push with VAPID keys generated on first use and kept in Blobs.
import { getStore } from "@netlify/blobs";
import webpush from "web-push";
import crypto from "node:crypto";

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

const normPhone = (p) => {
  let d = String(p || "").replace(/\D/g, "");
  if (d.length === 10) d = "1" + d;
  return d;
};
const validPin = (p) => /^\d{4,8}$/.test(String(p || ""));
const rid = () => crypto.randomBytes(6).toString("hex");
const hashPin = (pin) => {
  const salt = crypto.randomBytes(16).toString("hex");
  return salt + ":" + crypto.scryptSync(String(pin), salt, 32).toString("hex");
};
const checkPin = (pin, stored) => {
  const [salt, hex] = String(stored || "").split(":");
  if (!salt || !hex) return false;
  const a = Buffer.from(hex, "hex");
  const b = crypto.scryptSync(String(pin || ""), salt, 32);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const pub = (u) => ({
  id: u.id,
  name: u.name,
  phone: u.phone,
  role: u.role,
  notify: u.notify || {},
  push: (u.subs || []).length > 0,
});

async function loadUsers(s) {
  const u = (await s.get("users", { type: "json" })) || {};
  return { users: u.users || [], tokens: u.tokens || {}, fails: u.fails || {} };
}
async function vapid(s) {
  let v = await s.get("vapid", { type: "json" });
  if (!v || !v.publicKey) {
    v = webpush.generateVAPIDKeys();
    await s.setJSON("vapid", v);
  }
  return v;
}
async function sendPush(s, U, filter, payload) {
  const v = await vapid(s);
  webpush.setVapidDetails(process.env.URL || "mailto:budgeit@example.com", v.publicKey, v.privateKey);
  let sent = 0;
  for (const u of U.users.filter(filter)) {
    const keep = [];
    for (const sub of u.subs || []) {
      try {
        await webpush.sendNotification(sub, JSON.stringify(payload));
        keep.push(sub);
        sent++;
      } catch (e) {
        // 404/410 = subscription expired or revoked; drop it. Keep others.
        if (!(e && (e.statusCode === 404 || e.statusCode === 410))) keep.push(sub);
      }
    }
    u.subs = keep;
  }
  return sent;
}
const newToken = (U, u) => {
  const t = crypto.randomBytes(24).toString("hex");
  U.tokens[t] = u.id;
  return t;
};
const revokeTokens = (U, id) => {
  for (const t in U.tokens) if (U.tokens[t] === id) delete U.tokens[t];
};

export default async (req) => {
  const s = getStore({ name: "budgeit", consistency: "strong" });
  const url = new URL(req.url);
  const parts = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
  const path = parts.join("/");
  const m = req.method;
  const body = ["POST", "PUT", "PATCH"].includes(m) ? await req.json().catch(() => ({})) : {};
  const U = await loadUsers(s);
  const saveU = () => s.setJSON("users", U);
  const tok = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const me = tok && U.tokens[tok] ? U.users.find((u) => u.id === U.tokens[tok]) : null;

  try {
    // ---------- public ----------
    if (path === "status" && m === "GET") {
      const v = await vapid(s);
      return json({ setup: U.users.length > 0, vapidPublicKey: v.publicKey, me: me ? pub(me) : null });
    }

    if (path === "setup" && m === "POST") {
      if (U.users.length) return json({ error: "Sharing is already set up. Sign in instead." }, 409);
      const name = String(body.name || "").trim().slice(0, 40);
      const phone = normPhone(body.phone);
      if (!name) return json({ error: "Enter your name" }, 400);
      if (phone.length < 11) return json({ error: "Enter a 10-digit phone number" }, 400);
      if (!validPin(body.pin)) return json({ error: "PIN must be 4–8 digits" }, 400);
      const u = { id: rid(), name, phone, role: "admin", pin: hashPin(body.pin), notify: { goals: true }, subs: [] };
      U.users.push(u);
      const token = newToken(U, u);
      await saveU();
      return json({ token, user: pub(u) });
    }

    if (path === "login" && m === "POST") {
      const phone = normPhone(body.phone);
      const f = U.fails[phone] || { n: 0, until: 0 };
      if (f.until > Date.now()) return json({ error: "Too many tries. Wait 15 minutes and try again." }, 429);
      const u = U.users.find((x) => x.phone === phone);
      if (!u || !checkPin(body.pin, u.pin)) {
        f.n = (f.n || 0) + 1;
        if (f.n >= 5) {
          f.until = Date.now() + 15 * 60e3;
          f.n = 0;
        }
        U.fails[phone] = f;
        await saveU();
        return json({ error: "Phone number or PIN not recognized" }, 401);
      }
      delete U.fails[phone];
      const token = newToken(U, u);
      await saveU();
      return json({ token, user: pub(u) });
    }

    // ---------- signed in ----------
    if (!me) return json({ error: "Not signed in" }, 401);
    const admin = me.role === "admin";

    if (path === "me" && m === "GET") return json({ user: pub(me) });
    if (path === "me" && m === "PATCH") {
      if (body.notify && typeof body.notify === "object") me.notify = { ...(me.notify || {}), goals: !!body.notify.goals };
      await saveU();
      return json({ user: pub(me) });
    }
    if (path === "logout" && m === "POST") {
      delete U.tokens[tok];
      await saveU();
      return json({ ok: true });
    }

    if (path === "data" && m === "GET") {
      const d = (await s.get("data", { type: "json" })) || { rev: 0, data: null };
      return json({ rev: d.rev || 0, data: d.data, updated: d.updated || null });
    }
    if (path === "data" && m === "PUT") {
      if (!admin) return json({ error: "View-only account" }, 403);
      if (!body.data || typeof body.data !== "object") return json({ error: "No data" }, 400);
      const prev = (await s.get("data", { type: "json" })) || { rev: 0, notified: [] };
      const notified = new Set(prev.notified || []);
      const hits = [];
      for (const g of body.data.planned || []) {
        const amt = Number(g.amount) || 0;
        if (g.goal && amt > 0 && (g.done || (Number(g.saved) || 0) >= amt) && !notified.has(g.id)) {
          notified.add(g.id);
          hits.push(g);
        }
      }
      const rev = (prev.rev || 0) + 1;
      await s.setJSON("data", { rev, data: body.data, notified: [...notified], updated: new Date().toISOString() });
      if (hits.length) {
        for (const g of hits) {
          await sendPush(s, U, (u) => u.notify && u.notify.goals, {
            title: "Goal reached 🎯",
            body: `${g.name} is fully funded ($${Math.round(Number(g.amount)).toLocaleString("en-CA")})`,
          });
        }
        await saveU();
      }
      return json({ rev });
    }

    if (path === "push/subscribe" && m === "POST") {
      const sub = body.subscription;
      if (!sub || !sub.endpoint) return json({ error: "Bad subscription" }, 400);
      me.subs = (me.subs || []).filter((x) => x.endpoint !== sub.endpoint).concat([sub]).slice(-5);
      await saveU();
      return json({ user: pub(me) });
    }
    if (path === "push/test" && m === "POST") {
      const n = await sendPush(s, U, (u) => u.id === me.id, { title: "Budgeit", body: "Notifications are working ✓" });
      await saveU();
      return json({ sent: n });
    }

    // ---------- admin: people ----------
    if (parts[0] === "users") {
      if (!admin) return json({ error: "Only the admin can manage users" }, 403);
      if (parts.length === 1 && m === "GET") return json({ users: U.users.map(pub) });
      if (parts.length === 1 && m === "POST") {
        const name = String(body.name || "").trim().slice(0, 40);
        const phone = normPhone(body.phone);
        if (!name) return json({ error: "Enter a name" }, 400);
        if (phone.length < 11) return json({ error: "Enter a 10-digit phone number" }, 400);
        if (!validPin(body.pin)) return json({ error: "PIN must be 4–8 digits" }, 400);
        if (U.users.some((u) => u.phone === phone)) return json({ error: "That number is already on the list" }, 409);
        U.users.push({ id: rid(), name, phone, role: "viewer", pin: hashPin(body.pin), notify: { goals: false }, subs: [] });
        await saveU();
        return json({ users: U.users.map(pub) });
      }
      const target = U.users.find((u) => u.id === parts[1]);
      if (!target) return json({ error: "User not found" }, 404);
      if (parts.length === 2 && m === "DELETE") {
        if (target.id === me.id) return json({ error: "You can't remove yourself" }, 400);
        U.users = U.users.filter((u) => u.id !== target.id);
        revokeTokens(U, target.id);
        await saveU();
        return json({ users: U.users.map(pub) });
      }
      if (parts[2] === "pin" && m === "POST") {
        if (!validPin(body.pin)) return json({ error: "PIN must be 4–8 digits" }, 400);
        target.pin = hashPin(body.pin);
        if (target.id !== me.id) revokeTokens(U, target.id);
        await saveU();
        return json({ ok: true });
      }
    }

    return json({ error: "Not found" }, 404);
  } catch (e) {
    console.error(e);
    return json({ error: "Server error" }, 500);
  }
};

export const config = { path: "/api/*" };
