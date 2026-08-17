import { createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { networkInterfaces } from "node:os";
import z from "@deepseek-ai/schemastery";
import { settingsNamespace } from "@deepseek-ai/dsh-settings";
import { toFetchHandler } from "@deepseek-ai/dsh-host-apiproxy";

const name = "auth-guard";
const inject = ["webServer", "settings", "apiProxy"];

const AUTH_GUARD_NS = "auth-guard";
const ConfigSchema = z.object({
  authEnabled: z.boolean().default(false),
  username: z.string().default("admin"),
  passwordHash: z.string().role("secret").default(""),
  salt: z.string().role("secret").default(""),
  tokenSecret: z.string().role("secret").default(""),
  requireAuthForLan: z.boolean().default(true)
});

const PRIVILEGED_METHODS = [
  "agentPreset.read",
  "agentPreset.copy",
  "agentPreset.openDocument",
  "agentPreset.remove",
  "host.pickDirectory",
  "host.listDirectory",
  "host.createDirectory",
  "host.openPath",
  "settings.describe",
  "settings.openDocument",
  "settings.update",
  "settings.replace",
  "settings.mutate",
  "credentials.describe",
  "credentials.set",
  "credentials.unset",
  "llm.discoverModels"
];

const POLYFILL_SCRIPT = `<script>
(function() {
  if (typeof window !== 'undefined') {
    if (!window.crypto) window.crypto = {};
    if (!window.crypto.randomUUID) {
      window.crypto.randomUUID = function() {
        return '10000000-1000-4000-8000-100000000000'.replace(/[018]/g, function(c) {
          var r = (window.crypto.getRandomValues ? window.crypto.getRandomValues(new Uint8Array(1))[0] : Math.floor(Math.random() * 256));
          return (c ^ (r & (15 >> (c / 4)))).toString(16);
        });
      };
    }
  }
})();
</script>`;

function injectPolyfill(html) {
  if (html.includes("crypto.randomUUID")) return html;
  const headIndex = html.indexOf("<head>");
  if (headIndex !== -1) {
    return html.slice(0, headIndex + 6) + "\n" + POLYFILL_SCRIPT + "\n" + html.slice(headIndex + 6);
  }
  return POLYFILL_SCRIPT + html;
}

// Enterprise-grade constant-time password hashing & verification
const DUMMY_SALT = "0123456789abcdef0123456789abcdef";
const DUMMY_HASH = scryptSync("dummy_password_timing_pad", DUMMY_SALT, 32).toString("hex");

function hashPassword(password, salt) {
  return scryptSync(password, salt, 32).toString("hex");
}

function verifyPassword(password, salt, storedHash) {
  const safePassword = typeof password === "string" && password ? password : "invalid_dummy";
  const safeSalt = salt || DUMMY_SALT;
  const safeStored = storedHash || DUMMY_HASH;
  try {
    const computed = scryptSync(safePassword, safeSalt, 32);
    const stored = Buffer.from(safeStored, "hex");
    if (computed.length !== stored.length) return false;
    const match = timingSafeEqual(computed, stored);
    return Boolean(storedHash && salt && match);
  } catch {
    return false;
  }
}

function getPasswordFingerprint(passwordHash) {
  return passwordHash ? passwordHash.slice(0, 16) : "none";
}

function signToken(username, expiresAt, secret, passwordHash) {
  const fp = getPasswordFingerprint(passwordHash);
  const data = `${username}:${expiresAt}:${fp}`;
  const sig = createHmac("sha256", secret).update(data).digest("hex");
  return `v1.${Buffer.from(username).toString("base64url")}.${expiresAt}.${sig}`;
}

function verifyToken(token, secret, currentPasswordHash) {
  if (!token || typeof token !== "string" || !secret) return null;
  const parts = token.split(".");
  if (parts.length !== 4 || parts[0] !== "v1") return null;
  try {
    const username = Buffer.from(parts[1], "base64url").toString("utf8");
    const expiresAt = Number(parts[2]);
    const sig = parts[3];
    if (!username || !expiresAt || isNaN(expiresAt)) return null;
    if (Date.now() > expiresAt) return null;

    const fp = getPasswordFingerprint(currentPasswordHash);
    const data = `${username}:${expiresAt}:${fp}`;
    const expectedSig = createHmac("sha256", secret).update(data).digest("hex");
    const bufSig = Buffer.from(sig, "hex");
    const bufExpected = Buffer.from(expectedSig, "hex");
    if (bufSig.length !== bufExpected.length || !timingSafeEqual(bufSig, bufExpected)) return null;

    return { username, expiresAt };
  } catch {
    return null;
  }
}

// RFC 6265 compliant cookie parser (first cookie wins + quotes stripped)
function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  for (const part of cookieHeader.split(";")) {
    const idx = part.indexOf("=");
    if (idx !== -1) {
      const key = part.slice(0, idx).trim();
      let val = part.slice(idx + 1).trim();
      if (val.startsWith('"') && val.endsWith('"')) {
        val = val.slice(1, -1);
      }
      if (cookies[key] === undefined) {
        cookies[key] = val;
      }
    }
  }
  return cookies;
}

// Strict token extraction: ONLY from Authorization Bearer or HttpOnly Cookie
function getRequestToken(req) {
  const authHeader = req.headers ? (typeof req.headers.get === "function" ? req.headers.get("authorization") : req.headers["authorization"]) : undefined;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7).trim();
  }
  const rawCookie = req.headers ? (typeof req.headers.get === "function" ? req.headers.get("cookie") : req.headers["cookie"]) : undefined;
  const cookies = parseCookies(rawCookie);
  if (cookies["dsh_auth_token"]) {
    return cookies["dsh_auth_token"];
  }
  return undefined;
}

// Strictly verify direct physical socket loopback connection
function isPhysicalLoopback(req) {
  if (req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || req.headers["cf-connecting-ip"]) {
    return false;
  }
  const remote = (req.socket?.remoteAddress || "").trim().toLowerCase();
  return remote === "127.0.0.1" || remote === "::1" || remote === "::ffff:127.0.0.1";
}

// Anti-spoofing true IP resolution (only trust proxy headers if socket is confirmed local reverse proxy)
function getClientIp(req) {
  const socketIp = (req.socket?.remoteAddress || "unknown").replace(/^::ffff:/, "");
  const isDirectFromProxy = socketIp === "127.0.0.1" || socketIp === "::1";
  if (isDirectFromProxy && req.headers["x-forwarded-for"]) {
    const xForwardedFor = req.headers["x-forwarded-for"];
    const firstIp = (typeof xForwardedFor === "string" ? xForwardedFor : "").split(",")[0].trim();
    if (firstIp) return firstIp.replace(/^::ffff:/, "");
  }
  if (isDirectFromProxy && req.headers["x-real-ip"]) {
    const xReal = req.headers["x-real-ip"];
    if (typeof xReal === "string" && xReal.trim()) return xReal.trim().replace(/^::ffff:/, "");
  }
  return socketIp;
}

// Strict regex patterns for public whitelist
const ASSETS_PATTERN = /^\/assets\/[a-zA-Z0-9_.-]+(\.(js|css|svg|png|jpg|jpeg|gif|webp|woff2?|ttf|ico|webmanifest))?$/;
const PLUGINS_PATTERN = /^\/plugins\/(?:@[a-zA-Z0-9_.-]+\/)?[a-zA-Z0-9_.-]+\/client\.js(\.map)?$/;

function isPublicWhitelistedPath(pathname, method = "GET") {
  if (pathname === "/" || pathname === "/index.html") return true;
  if (pathname === "/favicon.ico" || pathname === "/favicon.svg") return true;
  if (pathname === "/manifest.webmanifest") return true;
  if (ASSETS_PATTERN.test(pathname)) return true;
  if (PLUGINS_PATTERN.test(pathname)) return true;
  if (pathname === "/auth/api/status") return true;
  if (pathname === "/auth/api/login" && method === "POST") return true;
  return false;
}

function isHttpsReq(req) {
  if (req.socket?.encrypted) return true;
  const proto = req.headers ? (typeof req.headers.get === "function" ? req.headers.get("x-forwarded-proto") : req.headers["x-forwarded-proto"]) : undefined;
  return proto === "https";
}

const MAX_BODY_LIMIT = 64 * 1024; // 64 KB protection against OOM stream DoS

async function readJson(req) {
  const chunks = [];
  let totalBytes = 0;
  for await (const chunk of req) {
    totalBytes += chunk.length;
    if (totalBytes > MAX_BODY_LIMIT) {
      const err = new Error("Payload too large (exceeds 64KB limit)");
      err.status = 413;
      throw err;
    }
    chunks.push(Buffer.from(chunk));
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text.trim()) return {};
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      const err = new Error("Invalid JSON body (must be a JSON object)");
      err.status = 400;
      throw err;
    }
    return parsed;
  } catch (e) {
    const err = new Error(e.message || "Invalid JSON syntax");
    err.status = 400;
    throw err;
  }
}

// Enterprise security response headers
const ENTERPRISE_SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "SAMEORIGIN",
  "referrer-policy": "strict-origin-when-cross-origin",
  "cache-control": "no-store, no-cache, must-revalidate, private",
  "pragma": "no-cache"
};

function sendJson(res, status, obj, headers = {}) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    ...ENTERPRISE_SECURITY_HEADERS,
    ...headers
  });
  res.end(JSON.stringify(obj));
}

function getLanAddresses() {
  const ifaces = networkInterfaces();
  const res = [];
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name] || []) {
      if (iface.family === "IPv4" && !iface.internal) {
        res.push(iface.address);
      }
    }
  }
  return res;
}

async function bridgeRequest(req, res, fetchHandler) {
  const abort = new AbortController();
  res.on("close", () => {
    if (!res.writableEnded) abort.abort();
  });
  const chunks = [];
  let totalBytes = 0;
  for await (const chunk of req) {
    totalBytes += chunk.length;
    if (totalBytes > 167772160) {
      res.writeHead(413, { "content-type": "application/json", ...ENTERPRISE_SECURITY_HEADERS });
      res.end(JSON.stringify({ ok: false, error: "Payload too large" }));
      return;
    }
    chunks.push(Buffer.from(chunk));
  }
  const request = new Request(new URL(req.url || "/", "http://dsh.internal"), {
    method: req.method || "GET",
    headers: Object.fromEntries(Object.entries(req.headers).filter(([, v]) => typeof v === "string")),
    body: chunks.length > 0 ? Buffer.concat(chunks) : undefined,
    signal: abort.signal
  });
  const response = await fetchHandler.fetch(request);
  res.writeHead(response.status, {
    ...Object.fromEntries(response.headers.entries()),
    ...ENTERPRISE_SECURITY_HEADERS
  });
  if (response.body === null) {
    res.end();
    return;
  }
  for await (const chunk of response.body) {
    if (!res.write(chunk)) await new Promise((resolve) => res.once("drain", resolve));
  }
  res.end();
}

function apply(ctx) {
  const ns = settingsNamespace(AUTH_GUARD_NS);
  ctx.settings.register(ns, ConfigSchema);

  // Active remote WebSockets registry for instant purge on password change / logout
  const activeRemoteSockets = new Set();

  const purgeActiveRemoteSockets = () => {
    for (const socket of activeRemoteSockets) {
      try {
        socket.destroy();
      } catch {}
    }
    activeRemoteSockets.clear();
  };

  // Hardened bounded sliding-window rate limiter with auto garbage collection
  const MAX_FAILED_RECORDS = 5000;
  const failedAttempts = new Map();

  // Global distributed rate-limiter: maximum 40 login attempts per minute globally
  const globalLoginTimestamps = [];
  const checkGlobalRateLimit = () => {
    const now = Date.now();
    while (globalLoginTimestamps.length > 0 && now - globalLoginTimestamps[0] > 60 * 1000) {
      globalLoginTimestamps.shift();
    }
    if (globalLoginTimestamps.length >= 40) {
      return { allowed: false, error: "系统登录请求过于频繁，请稍后重试。" };
    }
    globalLoginTimestamps.push(now);
    return { allowed: true };
  };

  const cleanupExpiredAttempts = () => {
    const now = Date.now();
    for (const [ip, record] of failedAttempts.entries()) {
      if (record.lockedUntil && now >= record.lockedUntil) failedAttempts.delete(ip);
      else if (record.firstAttempt && now - record.firstAttempt > 15 * 60 * 1000) failedAttempts.delete(ip);
    }
  };

  const cleanupTimer = setInterval(cleanupExpiredAttempts, 5 * 60 * 1000);
  ctx.effect(() => () => clearInterval(cleanupTimer), "auth-guard: rate-limiter cleanup");

  const checkRateLimit = (ip) => {
    const record = failedAttempts.get(ip);
    if (!record) return { allowed: true };
    const now = Date.now();
    if (record.lockedUntil && now < record.lockedUntil) {
      const waitSec = Math.ceil((record.lockedUntil - now) / 1000);
      return { allowed: false, error: `登录失败次数过多，已被临时锁定，请在 ${waitSec} 秒后重试。` };
    }
    if (record.lockedUntil && now >= record.lockedUntil) {
      failedAttempts.delete(ip);
      return { allowed: true };
    }
    if (record.firstAttempt && now - record.firstAttempt > 15 * 60 * 1000) {
      failedAttempts.delete(ip);
      return { allowed: true };
    }
    return { allowed: true };
  };

  const recordFailedAttempt = (ip) => {
    const now = Date.now();
    if (failedAttempts.size >= MAX_FAILED_RECORDS) {
      cleanupExpiredAttempts();
      if (failedAttempts.size >= MAX_FAILED_RECORDS) {
        const keys = Array.from(failedAttempts.keys());
        for (let i = 0; i < Math.floor(MAX_FAILED_RECORDS * 0.2); i++) {
          failedAttempts.delete(keys[i]);
        }
      }
    }
    const record = failedAttempts.get(ip) || { count: 0, firstAttempt: now, lockedUntil: 0 };
    record.count += 1;
    if (record.count >= 5) {
      record.lockedUntil = now + 15 * 60 * 1000; // 15 mins
    }
    failedAttempts.set(ip, record);
  };

  const resetFailedAttempts = (ip) => {
    failedAttempts.delete(ip);
  };

  const getConfig = () => {
    const descriptor = ctx.settings.describe({ redactSecrets: false }).find((c) => c.ns === ns);
    return {
      authEnabled: descriptor?.value?.authEnabled ?? false,
      username: descriptor?.value?.username ?? "admin",
      passwordHash: descriptor?.value?.passwordHash ?? "",
      salt: descriptor?.value?.salt ?? "",
      tokenSecret: descriptor?.value?.tokenSecret ?? "",
      requireAuthForLan: descriptor?.value?.requireAuthForLan ?? true
    };
  };

  const ensureSecret = async () => {
    const cfg = getConfig();
    if (!cfg.tokenSecret) {
      const newSecret = randomBytes(32).toString("hex");
      await ctx.settings.update(ns, { tokenSecret: newSecret });
      return newSecret;
    }
    return cfg.tokenSecret;
  };

  const isAuthRequired = (req) => {
    const cfg = getConfig();
    if (cfg.authEnabled) return true;
    if (cfg.requireAuthForLan && !isPhysicalLoopback(req) && cfg.passwordHash) return true;
    return false;
  };

  const isAuthed = (req) => {
    if (!isAuthRequired(req)) return true;
    const cfg = getConfig();
    if (!cfg.tokenSecret) return false;
    const token = getRequestToken(req);
    if (!token) return false;
    const verified = verifyToken(token, cfg.tokenSecret, cfg.passwordHash);
    return Boolean(verified);
  };

  // 1. Dynamic index tap for randomUUID Polyfill
  ctx.effect(() => {
    return ctx.webServer.tapIndex((html) => injectPolyfill(html));
  }, "auth-guard: index.html polyfill tap");

  // 2. Global Zero-Trust Gateway Hook on webServer.server ('request' & 'upgrade')
  ctx.effect(() => {
    const server = ctx.webServer.server;
    if (!server) return () => {};

    const originalRequestListeners = server.listeners("request").slice();
    server.removeAllListeners("request");

    const zeroTrustRequestHandler = async (req, res) => {
      try {
        const rawPath = new URL(req.url || "/", "http://dsh.internal").pathname;

        // Enterprise Security: Append baseline defense headers to every HTTP response
        for (const [hKey, hVal] of Object.entries(ENTERPRISE_SECURITY_HEADERS)) {
          if (!res.hasHeader(hKey)) {
            res.setHeader(hKey, hVal);
          }
        }

        // CSRF & Cross-Origin POST Defense: Block cross-site state modifications
        if (req.method !== "GET" && req.method !== "HEAD" && req.method !== "OPTIONS") {
          const fetchSite = req.headers["sec-fetch-site"];
          if (fetchSite === "cross-site") {
            res.writeHead(403, { "content-type": "application/json" });
            res.end(JSON.stringify({ ok: false, error: "Cross-site request blocked by CSRF policy" }));
            return;
          }
          const origin = req.headers["origin"];
          if (origin && typeof origin === "string") {
            try {
              const originUrl = new URL(origin);
              const originHostName = originUrl.hostname.toLowerCase();
              const reqHostName = (req.headers["host"] || "").split(":")[0].toLowerCase();
              const isLoopback = originHostName === "127.0.0.1" || originHostName === "localhost" || originHostName === "::1";
              const isSameHost = originHostName === reqHostName;
              if (!isLoopback && !isSameHost) {
                res.writeHead(403, { "content-type": "application/json" });
                res.end(JSON.stringify({ ok: false, error: "Cross-origin request blocked" }));
                return;
              }
            } catch {
              res.writeHead(403, { "content-type": "application/json" });
              res.end(JSON.stringify({ ok: false, error: "Malformed origin header" }));
              return;
            }
          }
        }

        // Check public whitelist
        if (!isPublicWhitelistedPath(rawPath, req.method)) {
          if (!isAuthed(req)) {
            res.writeHead(401, { "content-type": "application/json" });
            res.end(JSON.stringify({
              type: "server-response",
              rpcId: "auth-guard-gateway",
              result: { ok: false, error: { code: "unauthorized", message: "未授权访问，请先通过安全验证登录。" } }
            }));
            return;
          }
        }

        // Pass through to webServer routing
        for (const listener of originalRequestListeners) {
          listener(req, res);
        }
      } catch (err) {
        if (!res.headersSent) {
          const status = err?.status || 500;
          res.writeHead(status, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: false, error: String(err?.message || err) }));
        }
      }
    };

    server.on("request", zeroTrustRequestHandler);

    // Wrap WebSocket upgrade listeners (with CSWSH defense)
    const originalUpgradeListeners = server.listeners("upgrade").slice();
    server.removeAllListeners("upgrade");

    const zeroTrustUpgradeHandler = (req, socket, head) => {
      try {
        // CSWSH Defense: Verify WebSocket handshake Origin
        const origin = req.headers ? (typeof req.headers.get === "function" ? req.headers.get("origin") : req.headers["origin"]) : undefined;
        if (origin && typeof origin === "string") {
          try {
            const originUrl = new URL(origin);
            const originHostName = originUrl.hostname.toLowerCase();
            const reqHostName = (req.headers["host"] || "").split(":")[0].toLowerCase();
            const isLoopback = originHostName === "127.0.0.1" || originHostName === "localhost" || originHostName === "::1";
            const isSameHost = originHostName === reqHostName;
            if (!isLoopback && !isSameHost) {
              socket.write("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nForbidden: CSWSH origin rejected\r\n");
              socket.end();
              return;
            }
          } catch {
            socket.write("HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nBad Request: Malformed origin\r\n");
            socket.end();
            return;
          }
        }

        if (!isAuthed(req)) {
          socket.write("HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nUnauthorized: Authentication required\r\n");
          socket.end();
          return;
        }

        // Track remote active WebSockets for instant revocation on security state change
        if (!isPhysicalLoopback(req)) {
          activeRemoteSockets.add(socket);
          socket.once("close", () => activeRemoteSockets.delete(socket));
        }
        for (const listener of originalUpgradeListeners) {
          listener(req, socket, head);
        }
      } catch (err) {
        socket.write("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nInternal Server Error\r\n");
        socket.end();
      }
    };

    server.on("upgrade", zeroTrustUpgradeHandler);

    return () => {
      server.removeListener("request", zeroTrustRequestHandler);
      for (const listener of originalRequestListeners) server.on("request", listener);
      server.removeListener("upgrade", zeroTrustUpgradeHandler);
      for (const listener of originalUpgradeListeners) server.on("upgrade", listener);
    };
  }, "auth-guard: zero-trust gateway");

  // 3. Exact routes for Privileged RPCs to support authenticated LAN access without 403
  for (const method of PRIVILEGED_METHODS) {
    ctx.effect(() => {
      return ctx.webServer.register({
        kind: "exact",
        path: `/api/${method}`,
        handler: async (req, res) => {
          if (!isAuthed(req)) {
            return sendJson(res, 401, {
              type: "server-response",
              rpcId: "auth-guard",
              result: { ok: false, error: { code: "unauthorized", message: "未授权访问，请先登录。" } }
            });
          }
          const apiProxy = ctx.get("apiProxy");
          if (!apiProxy) {
            res.writeHead(500, { "content-type": "text/plain" });
            res.end("ApiProxy unavailable");
            return;
          }
          await bridgeRequest(req, res, toFetchHandler(apiProxy));
        }
      });
    }, `auth-guard: privileged exact /api/${method}`);
  }

  // 4. Register Auth Management Endpoints
  ctx.effect(() => {
    return ctx.webServer.register({
      kind: "prefix",
      path: "/auth/api",
      handler: async (req, res) => {
        const url = new URL(req.url, "http://dsh.internal");
        const pathname = url.pathname;
        const clientIp = getClientIp(req);
        const isHttps = isHttpsReq(req);
        const secureFlag = isHttps ? "; Secure" : "";

        try {
          if (pathname === "/auth/api/status") {
            const cfg = getConfig();
            const authed = isAuthed(req);
            return sendJson(res, 200, {
              ok: true,
              authEnabled: cfg.authEnabled,
              hasPassword: !!cfg.passwordHash,
              requireAuthForLan: cfg.requireAuthForLan,
              authenticated: authed,
              username: cfg.username,
              isLoopback: isPhysicalLoopback(req),
              lanAddresses: getLanAddresses(),
              port: ctx.webServer.port
            });
          }

          if (pathname === "/auth/api/login" && req.method === "POST") {
            // Global anti-distributed brute-force check
            const globalCheck = checkGlobalRateLimit();
            if (!globalCheck.allowed) {
              return sendJson(res, 429, { ok: false, error: globalCheck.error });
            }

            // Per-IP anti-brute-force check
            const rateCheck = checkRateLimit(clientIp);
            if (!rateCheck.allowed) {
              return sendJson(res, 429, { ok: false, error: rateCheck.error });
            }

            const body = await readJson(req);
            const { username, password } = body;

            // Strict Type Guard (CWE-843 Type Confusion defense)
            if (typeof username !== "string" || typeof password !== "string") {
              return sendJson(res, 400, { ok: false, error: "用户名或密码格式不正确 (必须为字符串)" });
            }

            const trimmedUser = username.trim();
            const cfg = getConfig();
            const secret = await ensureSecret();

            // Initial Password Setup Security: ONLY allow physical loopback
            if (!cfg.passwordHash) {
              if (!isPhysicalLoopback(req)) {
                return sendJson(res, 403, {
                  ok: false,
                  error: "初始管理员密码必须在服务器本机 (127.0.0.1) 首次设置，禁止从局域网或外部远程初始化。"
                });
              }
              if (password.length < 6) {
                return sendJson(res, 400, { ok: false, error: "密码长度至少需要 6 个字符" });
              }
              const salt = randomBytes(16).toString("hex");
              const passwordHash = hashPassword(password, salt);
              await ctx.settings.update(ns, {
                username: trimmedUser || "admin",
                passwordHash,
                salt,
                authEnabled: true
              });
              cfg.passwordHash = passwordHash;
              cfg.username = trimmedUser || "admin";
            } else {
              const userMatch = trimmedUser === cfg.username;
              const passMatch = verifyPassword(password, cfg.salt, cfg.passwordHash);
              if (!userMatch || !passMatch) {
                recordFailedAttempt(clientIp);
                return sendJson(res, 401, { ok: false, error: "用户名或密码错误" });
              }
            }

            resetFailedAttempts(clientIp);

            const expiresAt = Date.now() + 7 * 86400 * 1000;
            const token = signToken(cfg.username, expiresAt, secret, cfg.passwordHash);

            const cookieHeader = `dsh_auth_token=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${secureFlag}`;
            return sendJson(res, 200, { ok: true, token, username: cfg.username }, { "Set-Cookie": cookieHeader });
          }

          if (pathname === "/auth/api/logout" && req.method === "POST") {
            // Cut off active remote sockets on logout
            purgeActiveRemoteSockets();
            const cookieHeader = `dsh_auth_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secureFlag}`;
            return sendJson(res, 200, { ok: true }, { "Set-Cookie": cookieHeader });
          }

          if (pathname === "/auth/api/update" && req.method === "POST") {
            if (!isAuthed(req) && !isPhysicalLoopback(req)) {
              return sendJson(res, 401, { ok: false, error: "Unauthorized" });
            }
            const body = await readJson(req);
            const cfg = getConfig();
            const patch = {};

            if (typeof body.authEnabled === "boolean") patch.authEnabled = body.authEnabled;
            if (typeof body.requireAuthForLan === "boolean") patch.requireAuthForLan = body.requireAuthForLan;
            if (typeof body.username === "string" && body.username.trim()) patch.username = body.username.trim();

            // Sudo challenge: when changing security mode or password from remote, require oldPassword verification
            if (body.newPassword || (body.authEnabled === false && cfg.authEnabled)) {
              if (cfg.passwordHash && !isPhysicalLoopback(req)) {
                if (typeof body.oldPassword !== "string" || !verifyPassword(body.oldPassword, cfg.salt, cfg.passwordHash)) {
                  return sendJson(res, 400, { ok: false, error: "原密码不正确，无法执行敏感安全变更" });
                }
              }
            }

            if (body.newPassword) {
              if (typeof body.newPassword !== "string" || body.newPassword.length < 6) {
                return sendJson(res, 400, { ok: false, error: "新密码长度至少需要 6 个字符" });
              }
              const salt = randomBytes(16).toString("hex");
              patch.salt = salt;
              patch.passwordHash = hashPassword(body.newPassword, salt);
              // Instantly terminate all existing remote WebSockets on password change!
              purgeActiveRemoteSockets();
            }

            await ctx.settings.update(ns, patch);
            return sendJson(res, 200, { ok: true, message: "Settings updated" });
          }

          return sendJson(res, 404, { ok: false, error: "Not found" });
        } catch (err) {
          const status = err?.status || 500;
          return sendJson(res, status, { ok: false, error: String(err?.message || err) });
        }
      }
    });
  }, "auth-guard: auth api routes");
}

export { ConfigSchema as Config, apply, inject, name };
