import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";

test("auth-guard module exports and schema", async () => {
  const mod = await import("../lib/index.js");
  assert.equal(mod.name, "auth-guard");
  assert.deepEqual(mod.inject, ["webServer", "settings"]);
  assert.equal(typeof mod.apply, "function");
  assert.ok(mod.Config);
  assert.equal(mod.Config.type, "object");
  assert.ok(mod.Config.dict.authEnabled);
  assert.ok(mod.Config.dict.username);
  assert.ok(mod.Config.dict.passwordHash);
  assert.ok(mod.Config.dict.tokenSecret);
  assert.ok(mod.Config.dict.requireAuthForLan);
});

test("auth-guard apply and lifecycle", async () => {
  const mod = await import("../lib/index.js");

  // Mock server
  const mockServer = new EventEmitter();
  mockServer.listeners = (event) => {
    return mockServer.rawListeners(event) || [];
  };

  // Mock webServer
  const registeredRoutes = [];
  const registeredTaps = [];
  const mockWebServer = {
    server: mockServer,
    port: 3080,
    register(route) {
      registeredRoutes.push(route);
      return () => {
        const idx = registeredRoutes.indexOf(route);
        if (idx !== -1) registeredRoutes.splice(idx, 1);
      };
    },
    tapIndex(fn) {
      registeredTaps.push(fn);
      return () => {
        const idx = registeredTaps.indexOf(fn);
        if (idx !== -1) registeredTaps.splice(idx, 1);
      };
    }
  };

  // Mock settings
  let settingsState = {
    authEnabled: false,
    username: "admin",
    passwordHash: "",
    salt: "",
    tokenSecret: "",
    requireAuthForLan: true
  };
  const mockSettings = {
    register(ns, schema) {
      assert.equal(ns, "auth-guard");
    },
    describe(options) {
      return [{ ns: "auth-guard", value: settingsState }];
    },
    async update(ns, patch) {
      settingsState = { ...settingsState, ...patch };
    }
  };

  // Mock connection (DSH v0.1.2-rc.1 Host Connection)
  const mockConnection = {
    trustedHosts: ["127.0.0.1", "192.168.1.3"],
    browserAuth: {
      secret: Buffer.alloc(32, 1),
      isAuthenticated(req) {
        return Boolean(req.headers?.cookie?.includes("dsh-auth-"));
      },
      authorizeIndex(req, res) {
        return false;
      }
    },
    authorizeIndex(req, res) {
      return this.browserAuth.authorizeIndex(req, res);
    },
    requestRejection(req) {
      return 401;
    }
  };

  // Mock Cordis Context
  const services = new Map([
    ["webServer", mockWebServer],
    ["settings", mockSettings],
    ["connection", mockConnection]
  ]);
  const effects = [];
  const mockCtx = {
    webServer: mockWebServer,
    settings: mockSettings,
    get(name) {
      return services.get(name);
    },
    effect(fn, desc) {
      const cleanup = fn();
      effects.push(cleanup);
      return cleanup;
    },
    inject(deps, fn) {
      fn({ connection: mockConnection });
    }
  };

  // Run apply
  mod.apply(mockCtx);

  // 1. Verify index tap registered
  assert.equal(registeredTaps.length, 1);
  const htmlWithHead = "<html><head></head><body></body></html>";
  const transformed = registeredTaps[0](htmlWithHead);
  assert.ok(transformed.includes("crypto.randomUUID"), "Polyfill must be injected");

  // 2. Verify /auth/api prefix route registered
  const authRoute = registeredRoutes.find(r => r.path === "/auth/api");
  assert.ok(authRoute, "/auth/api route must be registered");
  assert.equal(authRoute.kind, "prefix");

  // 3. Verify connection.authorizeIndex hook
  assert.equal(mockConnection.authorizeIndex({ url: "/" }, {}), true, "authorizeIndex should allow index.html for auth-guard");

  // 4. Verify connection.requestRejection hook
  // When auth not required (loopback, authEnabled=false, no password set):
  const loopbackReq = {
    url: "/api/settings/describe",
    headers: { host: "127.0.0.1:3080" },
    socket: { remoteAddress: "127.0.0.1" }
  };
  assert.equal(mockConnection.requestRejection(loopbackReq), undefined, "Loopback request should be allowed when auth not required");

  // 5. Verify dynamic trustedHosts addition
  const lanReq = {
    url: "/api/settings/describe",
    headers: { host: "192.168.10.50:3080" },
    socket: { remoteAddress: "127.0.0.1" }
  };
  mockConnection.requestRejection(lanReq);
  assert.ok(mockConnection.trustedHosts.includes("192.168.10.50:3080"), "trustedHosts should include new host");
  assert.ok(mockConnection.trustedHosts.includes("192.168.10.50"), "trustedHosts should include host without port");

  // 6. Test /auth/api/status endpoint
  const simulateReq = async (method, path, headers = {}, body = null) => {
    const req = new EventEmitter();
    req.method = method;
    req.url = path;
    req.headers = { host: "127.0.0.1:3080", ...headers };
    req.socket = { remoteAddress: "127.0.0.1" };
    const chunks = body ? [Buffer.from(typeof body === "string" ? body : JSON.stringify(body))] : [];
    req[Symbol.asyncIterator] = async function* () {
      for (const chunk of chunks) yield chunk;
    };

    let statusCode = 200;
    let resHeaders = {};
    let resBody = "";
    const res = {
      writeHead(code, h = {}) {
        statusCode = code;
        resHeaders = { ...resHeaders, ...h };
      },
      setHeader(k, v) {
        resHeaders[k.toLowerCase()] = v;
      },
      hasHeader(k) {
        return Boolean(resHeaders[k.toLowerCase()]);
      },
      end(d) {
        if (d) resBody += d;
      }
    };
    await authRoute.handler(req, res);
    let parsed = null;
    try { parsed = JSON.parse(resBody); } catch {}
    return { status: statusCode, headers: resHeaders, body: parsed };
  };

  const statusRes = await simulateReq("GET", "/auth/api/status");
  assert.equal(statusRes.status, 200);
  assert.equal(statusRes.body.ok, true);
  assert.equal(statusRes.body.hasPassword, false);

  // 7. Initial password setup on loopback
  const initLoginRes = await simulateReq("POST", "/auth/api/login", {}, {
    username: "admin",
    password: "mypassword123"
  });
  assert.equal(initLoginRes.status, 200);
  assert.equal(initLoginRes.body.ok, true);
  assert.ok(initLoginRes.body.token, "Must return signed token");

  // Verify cookies set: both dsh_auth_token and native dsh-auth-... cookie
  const setCookies = initLoginRes.headers["set-cookie"];
  assert.ok(Array.isArray(setCookies) || typeof setCookies === "string");
  const cookieStr = Array.isArray(setCookies) ? setCookies.join("; ") : setCookies;
  assert.ok(cookieStr.includes("dsh_auth_token="), "Must set dsh_auth_token cookie");
  assert.ok(cookieStr.includes("dsh-auth-"), "Must set DSH native cookie");

  // Settings should have been updated with passwordHash and salt
  assert.ok(settingsState.passwordHash);
  assert.ok(settingsState.salt);
  assert.equal(settingsState.authEnabled, true);

  // 8. Now unauthenticated request should be rejected by requestRejection
  assert.equal(mockConnection.requestRejection(loopbackReq), 401, "Unauthenticated request should return 401");

  // Authenticated request with token cookie should be accepted
  const authedReq = {
    url: "/api/settings/describe",
    headers: {
      host: "127.0.0.1:3080",
      cookie: `dsh_auth_token=${initLoginRes.body.token}`
    },
    socket: { remoteAddress: "127.0.0.1" }
  };
  assert.equal(mockConnection.requestRejection(authedReq), undefined, "Authenticated request should be allowed");

  // 9. Logout
  const logoutRes = await simulateReq("POST", "/auth/api/logout");
  assert.equal(logoutRes.status, 200);
  assert.equal(logoutRes.body.ok, true);

  // Cleanup effects
  for (const cleanup of effects) {
    if (typeof cleanup === "function") cleanup();
  }
});

test("auth-guard client.js syntax and module loading", async () => {
  // Simulate browser window.__ModuleLoader__
  let loadedModule = null;
  globalThis.window = {
    __ModuleLoader__: {
      load(mod) {
        loadedModule = mod;
      }
    },
    BroadcastChannel: class {
      postMessage() {}
      addEventListener() {}
      removeEventListener() {}
    }
  };
  globalThis.document = {
    getElementById() { return null; },
    createElement() {
      return {
        setAttribute() {},
        style: {},
        appendChild() {},
        remove() {}
      };
    },
    head: { appendChild() {} },
    body: { setAttribute() {}, removeAttribute() {} }
  };

  await import("../lib/client.js");
  assert.ok(loadedModule, "client.js must register with __ModuleLoader__");
  assert.equal(loadedModule.id, "dsh-plugin-auth-guard");
  assert.equal(typeof loadedModule.factory, "function");

  // Mock client require
  const mockRequire = (id) => {
    if (id === "react") {
      return {
        createElement: () => ({}),
        useState: (v) => [v, () => {}],
        useEffect: (fn) => {},
        useRef: () => ({ current: null })
      };
    }
    if (id === "react-dom") {
      return { createPortal: (c) => c };
    }
    return {};
  };

  const clientExports = loadedModule.factory(mockRequire);
  assert.equal(clientExports.name, "auth-guard-client");
  assert.deepEqual(clientExports.inject, ["slots", "locale"]);
  assert.equal(typeof clientExports.apply, "function");

  // Test apply(ctx)
  let registeredSlot = null;
  const mockClientCtx = {
    slots: {
      inject(name, fn) { fn(); },
      register(spec, comp) {
        registeredSlot = spec;
      }
    },
    get(name) { return null; },
    on() {},
    inject() {}
  };

  clientExports.apply(mockClientCtx);
  assert.ok(registeredSlot);
});
