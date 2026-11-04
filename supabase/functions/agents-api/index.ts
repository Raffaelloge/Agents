import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const PROJECT_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SECRET_KEYS = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS") ?? "{}");
const DB_SECRET = SECRET_KEYS.default ?? Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const encoder = new TextEncoder();
const corsHeaders = {
  "Access-Control-Allow-Origin": "https://raffaelloge.github.io",
  "Access-Control-Allow-Headers": "apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}

function base64url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64url(value: string) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function fromHex(value: string) {
  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function toHex(value: ArrayBuffer) {
  return Array.from(new Uint8Array(value)).map((n) => n.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(value: string) {
  return toHex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

async function derivePassword(password: string, saltHex: string) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: fromHex(saltHex), iterations: 250000, hash: "SHA-256" },
    key,
    256,
  ));
}

function sameBytes(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function signSession(username: string) {
  const payload = base64url(encoder.encode(JSON.stringify({
    sub: username,
    exp: Date.now() + 30 * 24 * 60 * 60 * 1000,
  })));
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(DB_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(payload)));
  return payload + "." + base64url(signature);
}

async function verifySession(token: string) {
  const parts = token.split(".");
  if (parts.length !== 2 || !DB_SECRET) return null;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(DB_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify("HMAC", key, fromBase64url(parts[1]), encoder.encode(parts[0]));
  if (!valid) return null;
  const payload = JSON.parse(new TextDecoder().decode(fromBase64url(parts[0])));
  if (typeof payload.sub !== "string" || payload.exp < Date.now()) return null;
  return payload.sub as string;
}

function dbHeaders(extra: Record<string, string> = {}) {
  return {
    "apikey": DB_SECRET,
    "Authorization": "Bearer " + DB_SECRET,
    "Content-Type": "application/json",
    ...extra,
  };
}

async function dbRequest(path: string, init: RequestInit = {}) {
  const response = await fetch(PROJECT_URL + "/rest/v1/" + path, {
    ...init,
    headers: dbHeaders((init.headers ?? {}) as Record<string, string>),
  });
  const body = await response.text();
  if (!response.ok) {
    console.error("Database request failed", response.status, body.slice(0, 300));
    throw new Error("Storage request failed");
  }
  if (!body) return null;
  return JSON.parse(body);
}

async function getAttempts(username: string, ipHash: string) {
  const query = "roster_login_attempts?username=eq." + encodeURIComponent(username) +
    "&ip_hash=eq." + encodeURIComponent(ipHash) +
    "&select=attempts,window_started_at,locked_until&limit=1";
  const rows = await dbRequest(query);
  return Array.isArray(rows) ? rows[0] ?? null : null;
}

async function recordFailure(username: string, ipHash: string, current: Record<string, unknown> | null) {
  const now = Date.now();
  const fresh = current && now - Date.parse(String(current.window_started_at)) < 15 * 60 * 1000;
  const attempts = fresh ? Number(current.attempts) + 1 : 1;
  const lockedUntil = attempts >= 5 ? new Date(now + 15 * 60 * 1000).toISOString() : null;
  const row = {
    username,
    ip_hash: ipHash,
    attempts,
    window_started_at: fresh ? current.window_started_at : new Date(now).toISOString(),
    locked_until: lockedUntil,
  };
  await dbRequest("roster_login_attempts?on_conflict=username,ip_hash", {
    method: "POST",
    headers: { "Prefer": "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify([row]),
  });
}

async function login(username: string, password: string, ipHash: string) {
  const attempts = await getAttempts(username, ipHash);
  if (attempts?.locked_until && Date.parse(String(attempts.locked_until)) > Date.now()) return false;

  const query = "roster_accounts?username=eq." + encodeURIComponent(username) +
    "&select=username,password_salt,password_hash&limit=1";
  const rows = await dbRequest(query);
  const account = Array.isArray(rows) ? rows[0] : null;
  let valid = false;
  if (account && typeof account.password_salt === "string" && typeof account.password_hash === "string") {
    const derived = await derivePassword(password, account.password_salt);
    valid = sameBytes(derived, fromHex(account.password_hash));
  }

  if (valid) {
    await dbRequest(
      "roster_login_attempts?username=eq." + encodeURIComponent(username) + "&ip_hash=eq." + encodeURIComponent(ipHash),
      { method: "DELETE" },
    );
    return true;
  }
  await recordFailure(username, ipHash, attempts);
  return false;
}

function normalizeAgents(value: unknown) {
  if (!Array.isArray(value)) return [];
  if (value.length > 500) throw new Error("Too many agents");
  return value.map((item: any) => {
    if (!item || typeof item !== "object") throw new Error("Invalid agent");
    const id = String(item.id ?? "");
    const name = String(item.name ?? "").trim();
    const role = String(item.role ?? "").trim();
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) throw new Error("Invalid agent id");
    if (name.length < 1 || name.length > 60 || role.length < 1 || role.length > 500) throw new Error("Invalid agent fields");
    return { id, name, role };
  });
}

function normalizeDeletedIds(value: unknown) {
  if (!Array.isArray(value)) return [];
  return Array.from(new Set(value.map(String).filter((id) => /^[A-Za-z0-9_-]{1,64}$/.test(id)))).slice(0, 500);
}

async function syncAgents(username: string, localValue: unknown, deletedValue: unknown) {
  const deletedIds = normalizeDeletedIds(deletedValue);
  if (deletedIds.length) {
    await dbRequest(
      "roster_agents?username=eq." + encodeURIComponent(username) + "&id=in.(" + deletedIds.join(",") + ")",
      { method: "DELETE" },
    );
  }

  const localAgents = normalizeAgents(localValue);
  if (localAgents.length) {
    const rows = localAgents.map((agent) => ({
      username,
      id: agent.id,
      name: agent.name,
      role: agent.role,
      updated_at: new Date().toISOString(),
    }));
    await dbRequest("roster_agents?on_conflict=username,id", {
      method: "POST",
      headers: { "Prefer": "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify(rows),
    });
  }

  const query = "roster_agents?username=eq." + encodeURIComponent(username) +
    "&select=id,name,role&order=created_at.asc,id.asc";
  const rows = await dbRequest(query);
  return Array.isArray(rows) ? rows : [];
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  if (!PROJECT_URL || !DB_SECRET) return json({ error: "Cloud storage is unavailable" }, 503);

  try {
    const body = await req.json();
    if (!body || typeof body !== "object") return json({ error: "Invalid request" }, 400);

    if (body.action === "login") {
      const username = String(body.username ?? "").trim().toLowerCase();
      const password = String(body.password ?? "");
      if (!/^[a-z0-9_-]{1,32}$/.test(username) || password.length < 1 || password.length > 128) {
        return json({ error: "Username or password is incorrect" }, 401);
      }
      const ip = req.headers.get("cf-connecting-ip") ?? req.headers.get("x-forwarded-for") ?? "unknown";
      const ipHash = await sha256Hex(ip.split(",")[0].trim());
      const authenticated = await login(username, password, ipHash);
      if (!authenticated) return json({ error: "Username or password is incorrect" }, 401);
      const session = await signSession(username);
      const agents = await syncAgents(username, body.agents, body.deletedIds);
      return json({ session, agents });
    }

    if (body.action === "sync") {
      const username = await verifySession(String(body.session ?? ""));
      if (!username) return json({ error: "Please log in again" }, 401);
      const agents = await syncAgents(username, body.agents, body.deletedIds);
      return json({ agents });
    }

    return json({ error: "Unknown action" }, 400);
  } catch (error) {
    console.error("agents-api failed", error);
    return json({ error: "Could not reach cloud storage" }, 500);
  }
});
