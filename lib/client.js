window.__ModuleLoader__.load({
  id: "dsh-plugin-auth-guard",
  factory: (require) => {
    const module = { exports: {} };
    const exports = module.exports;
    const React = require("react");
    const ReactDOM = require("react-dom");
    const { createElement: h, useState, useEffect, useRef } = React;
    const { createPortal } = ReactDOM;

    let Primitives = {};
    try {
      Primitives = require("@deepseek-ai/dsh-client-ui-primitives") || {};
    } catch {}

    const { FishLogo } = Primitives;

    exports.name = "auth-guard-client";
    exports.inject = ["slots", "locale"];

    // Multi-tab cross-window synchronization channel
    const authChannel = typeof window !== "undefined" && typeof window.BroadcastChannel !== "undefined"
      ? new window.BroadcastChannel("dsh_auth_sync_channel")
      : null;

    function notifyAuthChange(action) {
      if (authChannel) {
        try {
          authChannel.postMessage({ type: action, timestamp: Date.now() });
        } catch {}
      }
    }

    // Ensure global lock style tag exists
    function updateGlobalLockStyle(locked) {
      let styleEl = document.getElementById("dsh-auth-guard-lock-style");
      if (locked) {
        document.body.setAttribute("data-dsh-auth-locked", "true");
        if (!styleEl) {
          styleEl = document.createElement("style");
          styleEl.id = "dsh-auth-guard-lock-style";
          styleEl.textContent = `
            body[data-dsh-auth-locked] > :not(#dsh-auth-lock-overlay) {
              pointer-events: none !important;
              user-select: none !important;
              filter: blur(4px) brightness(0.65) !important;
              transition: filter 0.25s ease !important;
            }
          `;
          document.head.appendChild(styleEl);
        }
      } else {
        document.body.removeAttribute("data-dsh-auth-locked");
        if (styleEl) {
          styleEl.remove();
        }
      }
    }

    // DSH Native Style System
    const dshStyles = {
      overlay: {
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: "rgba(11, 14, 19, 0.75)",
        backdropFilter: "blur(12px)",
        WebkitBackdropFilter: "blur(12px)",
        zIndex: 2147483647,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "16px",
        pointerEvents: "auto"
      },
      modal: {
        width: "100%",
        maxWidth: "390px",
        backgroundColor: "var(--dsw-alias-bg-layer-1, #181b22)",
        border: "1px solid var(--dsw-alias-border-l1, #30363d)",
        borderRadius: "14px",
        padding: "32px 28px 28px 28px",
        boxShadow: "0 24px 48px rgba(0, 0, 0, 0.6), 0 0 0 1px rgba(255, 255, 255, 0.05)",
        color: "var(--dsw-alias-label-primary, #f0f6fc)",
        fontFamily: "var(--dsw-font-family, system-ui, -apple-system, sans-serif)",
        boxSizing: "border-box"
      },
      brandHeader: {
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        marginBottom: "24px",
        textAlign: "center"
      },
      logoWrap: {
        width: "48px",
        height: "48px",
        borderRadius: "12px",
        backgroundColor: "var(--dsw-alias-bg-layer-2, #21262d)",
        border: "1px solid var(--dsw-alias-border-l2, rgba(255,255,255,0.1))",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        marginBottom: "14px",
        color: "var(--dsw-alias-brand-primary, #4d6bfe)"
      },
      title: {
        fontSize: "17px",
        fontWeight: "600",
        color: "var(--dsw-alias-label-primary, #f0f6fc)",
        margin: "0 0 6px 0",
        letterSpacing: "0.01em"
      },
      subtitle: {
        fontSize: "13px",
        lineHeight: "18px",
        color: "var(--dsw-alias-label-secondary, #8b949e)",
        margin: 0
      },
      formGroup: {
        marginBottom: "16px"
      },
      label: {
        display: "block",
        fontSize: "13px",
        fontWeight: "500",
        marginBottom: "6px",
        color: "var(--dsw-alias-label-primary, #f0f6fc)"
      },
      input: {
        width: "100%",
        boxSizing: "border-box",
        height: "38px",
        padding: "0 12px",
        backgroundColor: "var(--dsw-alias-bg-layer-2, #0d1117)",
        border: "1px solid var(--dsw-alias-border-l2, #30363d)",
        borderRadius: "8px",
        color: "var(--dsw-alias-label-primary, #f0f6fc)",
        fontSize: "14px",
        outline: "none",
        transition: "border-color 0.15s ease, box-shadow 0.15s ease"
      },
      primaryButton: {
        width: "100%",
        height: "38px",
        backgroundColor: "var(--dsw-alias-button-primary-fill, #3964fe)",
        color: "var(--dsw-alias-label-primary-foreground, #ffffff)",
        border: "none",
        borderRadius: "8px",
        fontSize: "14px",
        fontWeight: "500",
        cursor: "pointer",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        marginTop: "12px",
        transition: "background-color 0.15s ease, opacity 0.15s ease"
      },
      secondaryButton: {
        height: "36px",
        padding: "0 16px",
        backgroundColor: "var(--dsw-alias-bg-layer-2, #21262d)",
        color: "var(--dsw-alias-label-primary, #f0f6fc)",
        border: "1px solid var(--dsw-alias-border-l2, #30363d)",
        borderRadius: "8px",
        fontSize: "13px",
        fontWeight: "500",
        cursor: "pointer",
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        transition: "background-color 0.15s ease"
      },
      errorText: {
        color: "var(--dsw-alias-state-error-primary, #f85149)",
        fontSize: "12px",
        marginTop: "8px",
        textAlign: "center"
      },
      section: {
        padding: "24px 32px",
        maxWidth: "840px",
        color: "var(--dsw-alias-label-primary, #f0f6fc)",
        fontFamily: "var(--dsw-font-family, system-ui, -apple-system, sans-serif)"
      },
      sectionTitle: {
        fontSize: "20px",
        fontWeight: "600",
        marginBottom: "20px",
        color: "var(--dsw-alias-label-primary, #f0f6fc)"
      },
      card: {
        backgroundColor: "var(--dsw-alias-bg-layer-1, #181b22)",
        border: "1px solid var(--dsw-alias-border-l2, rgba(255,255,255,0.08))",
        borderRadius: "12px",
        padding: "20px 24px",
        marginBottom: "20px"
      },
      cardHeader: {
        fontSize: "15px",
        fontWeight: "600",
        color: "var(--dsw-alias-label-primary, #f0f6fc)",
        marginBottom: "6px"
      },
      cardDesc: {
        fontSize: "13px",
        color: "var(--dsw-alias-label-secondary, #8b949e)",
        lineHeight: "18px",
        marginBottom: "16px"
      },
      ipTag: {
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        padding: "6px 12px",
        backgroundColor: "var(--dsw-alias-bg-layer-2, #21262d)",
        border: "1px solid var(--dsw-alias-border-l2, rgba(255,255,255,0.1))",
        borderRadius: "6px",
        fontSize: "13px",
        fontFamily: "var(--ds-font-family-code, ui-monospace, Consolas, monospace)",
        color: "var(--dsw-alias-brand-primary, #4d6bfe)",
        marginRight: "10px",
        marginBottom: "10px",
        cursor: "pointer",
        transition: "border-color 0.15s ease"
      }
    };

    function LoginOverlay() {
      const [status, setStatus] = useState(null);
      const [username, setUsername] = useState("admin");
      const [password, setPassword] = useState("");
      const [error, setError] = useState("");
      const [loading, setLoading] = useState(false);

      const checkStatus = async () => {
        try {
          const res = await fetch("/auth/api/status");
          const data = await res.json();
          setStatus(data);
          if (data.username) setUsername(data.username);
        } catch (e) {
          console.error("Failed to check auth status", e);
        }
      };

      useEffect(() => {
        checkStatus();
        if (authChannel) {
          const handleMsg = (ev) => {
            if (ev.data && (ev.data.type === "logout" || ev.data.type === "login" || ev.data.type === "update")) {
              checkStatus();
            }
          };
          authChannel.addEventListener("message", handleMsg);
          return () => authChannel.removeEventListener("message", handleMsg);
        }
      }, []);

      const needsLogin = status && !status.authenticated && (status.authEnabled || (status.requireAuthForLan && !status.isLoopback && status.hasPassword));

      useEffect(() => {
        updateGlobalLockStyle(Boolean(needsLogin));
        return () => {
          updateGlobalLockStyle(false);
        };
      }, [needsLogin]);

      if (!needsLogin) return null;

      const handleSubmit = async (e) => {
        e.preventDefault();
        setError("");
        setLoading(true);
        try {
          const res = await fetch("/auth/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
          });
          const data = await res.json();
          if (data.ok) {
            updateGlobalLockStyle(false);
            notifyAuthChange("login");
            window.location.reload();
          } else {
            setError(data.error || "用户名或密码错误");
          }
        } catch (err) {
          setError("网络请求失败: " + err.message);
        } finally {
          setLoading(false);
        }
      };

      const overlayNode = h("div", {
        id: "dsh-auth-lock-overlay",
        style: dshStyles.overlay,
        onClick: (e) => e.stopPropagation()
      },
        h("div", { style: dshStyles.modal },
          h("div", { style: dshStyles.brandHeader },
            h("div", { style: dshStyles.logoWrap },
              FishLogo ? h(FishLogo, { size: 28 }) : h("span", { style: { fontSize: "22px" } }, "🐳")
            ),
            h("h2", { style: dshStyles.title },
              status.hasPassword ? "DeepSeek Harness 访问验证" : "初始化管理员密码"
            ),
            h("p", { style: dshStyles.subtitle },
              status.hasPassword
                ? "当前环境已启用网络安全访问控制，请输入凭据解锁。"
                : "首次开启网络安全访问，请设置您的管理员密码 (至少6位)。"
            )
          ),
          h("form", { onSubmit: handleSubmit },
            h("div", { style: dshStyles.formGroup },
              h("label", { style: dshStyles.label }, "用户名"),
              h("input", {
                type: "text",
                style: dshStyles.input,
                value: username,
                onChange: (e) => setUsername(e.target.value),
                required: true
              })
            ),
            h("div", { style: dshStyles.formGroup },
              h("label", { style: dshStyles.label }, "密码"),
              h("input", {
                type: "password",
                style: dshStyles.input,
                value: password,
                placeholder: status.hasPassword ? "输入访问密码" : "设置新密码 (≥6位)",
                onChange: (e) => setPassword(e.target.value),
                required: true,
                autoFocus: true
              })
            ),
            error && h("div", { style: dshStyles.errorText }, error),
            h("button", {
              type: "submit",
              style: { ...dshStyles.primaryButton, opacity: loading ? 0.6 : 1 },
              disabled: loading
            }, loading ? "正在验证..." : (status.hasPassword ? "解锁并进入" : "保存并进入"))
          )
        )
      );

      return createPortal ? createPortal(overlayNode, document.body) : overlayNode;
    }

    function AuthGuardSettings() {
      const [status, setStatus] = useState(null);
      const [authEnabled, setAuthEnabled] = useState(false);
      const [requireLan, setRequireLan] = useState(true);
      const [username, setUsername] = useState("admin");
      const [oldPassword, setOldPassword] = useState("");
      const [newPassword, setNewPassword] = useState("");
      const [msg, setMsg] = useState("");
      const [err, setErr] = useState("");
      const [copiedIp, setCopiedIp] = useState("");

      const load = async () => {
        try {
          const res = await fetch("/auth/api/status");
          const data = await res.json();
          setStatus(data);
          setAuthEnabled(data.authEnabled);
          setRequireLan(data.requireAuthForLan);
          if (data.username) setUsername(data.username);
        } catch (e) {
          setErr("加载安全状态失败");
        }
      };

      useEffect(() => { load(); }, []);

      const saveSettings = async () => {
        setMsg("");
        setErr("");
        try {
          const res = await fetch("/auth/api/update", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              authEnabled,
              requireAuthForLan: requireLan,
              username,
              oldPassword: oldPassword || undefined,
              newPassword: newPassword || undefined
            })
          });
          const data = await res.json();
          if (data.ok) {
            setMsg("✅ 设置已成功保存！");
            setOldPassword("");
            setNewPassword("");
            notifyAuthChange("update");
            load();
          } else {
            setErr(data.error || "保存失败");
          }
        } catch (e) {
          setErr("请求失败: " + e.message);
        }
      };

      const handleLogout = async () => {
        await fetch("/auth/api/logout", { method: "POST" });
        notifyAuthChange("logout");
        window.location.reload();
      };

      if (!status) return h("div", { style: dshStyles.section }, "正在加载安全与访问配置...");

      return h("div", { style: dshStyles.section },
        h("div", { style: { display: "flex", alignItems: "center", gap: "10px", marginBottom: "20px" } },
          FishLogo && h(FishLogo, { size: 22 }),
          h("h2", { style: { ...dshStyles.sectionTitle, margin: 0 } }, "安全与网络访问控制")
        ),

        // 1. Network Status Card
        h("div", { style: dshStyles.card },
          h("div", { style: dshStyles.cardHeader }, "🌐 局域网 / 本机访问地址"),
          h("div", { style: dshStyles.cardDesc },
            `服务正在监听 0.0.0.0 端口 ${status.port || 3080}。局域网内其他设备可通过以下链接直接访问：`
          ),
          h("div", { style: { display: "flex", flexWrap: "wrap" } },
            (status.lanAddresses || []).map(ip => {
              const url = `http://${ip}:${status.port || 3080}`;
              return h("div", {
                key: ip,
                style: dshStyles.ipTag,
                title: "点击复制地址",
                onClick: () => {
                  navigator.clipboard.writeText(url);
                  setCopiedIp(ip);
                  setTimeout(() => setCopiedIp(""), 2000);
                }
              },
                h("span", null, url),
                h("span", { style: { fontSize: "11px", color: copiedIp === ip ? "#3fb950" : "inherit" } },
                  copiedIp === ip ? "已复制 ✓" : "📋"
                )
              );
            })
          ),
          h("div", { style: { marginTop: "8px", fontSize: "12px", color: "var(--dsw-alias-label-secondary)" } },
            `当前客户端：${status.isLoopback ? "本机回环 (127.0.0.1)" : "局域网/公网设备"} ｜ 鉴权状态：${status.authenticated ? "已认证 ✅" : "未认证 / 免密"}`
          )
        ),

        // 2. Access Control Card
        h("div", { style: dshStyles.card },
          h("div", { style: dshStyles.cardHeader }, "🔒 访问控制策略"),
          h("div", { style: dshStyles.cardDesc }, "配置非本机设备访问时的身份鉴权行为。"),
          h("div", { style: { marginBottom: "16px" } },
            h("label", { style: { display: "flex", alignItems: "flex-start", gap: "10px", cursor: "pointer" } },
              h("input", {
                type: "checkbox",
                checked: requireLan,
                style: { marginTop: "3px", cursor: "pointer" },
                onChange: (e) => setRequireLan(e.target.checked)
              }),
              h("div", null,
                h("div", { style: { fontSize: "14px", fontWeight: "500" } }, "局域网/公网访问必须密码验证 (推荐)"),
                h("div", { style: { fontSize: "12px", color: "var(--dsw-alias-label-secondary)", marginTop: "2px" } },
                  "开启后，非本机设备通过局域网 IP 访问时将弹出全屏锁屏门禁，验证通过后方可操作。"
                )
              )
            )
          ),
          h("div", { style: { marginBottom: "8px" } },
            h("label", { style: { display: "flex", alignItems: "flex-start", gap: "10px", cursor: "pointer" } },
              h("input", {
                type: "checkbox",
                checked: authEnabled,
                style: { marginTop: "3px", cursor: "pointer" },
                onChange: (e) => setAuthEnabled(e.target.checked)
              }),
              h("div", null,
                h("div", { style: { fontSize: "14px", fontWeight: "500" } }, "全局强制密码认证 (包含本机 127.0.0.1)"),
                h("div", { style: { fontSize: "12px", color: "var(--dsw-alias-label-secondary)", marginTop: "2px" } },
                  "无论在服务器本机还是局域网，打开页面均需要输入密码登录。"
                )
              )
            )
          )
        ),

        // 3. Admin Credentials Card
        h("div", { style: dshStyles.card },
          h("div", { style: dshStyles.cardHeader }, "🔑 管理员账号密码设置"),
          h("div", { style: dshStyles.cardDesc }, "密码采用加盐安全哈希存储于本地配置中。"),
          h("div", { style: dshStyles.formGroup },
            h("label", { style: dshStyles.label }, "管理员用户名"),
            h("input", {
              type: "text",
              style: dshStyles.input,
              value: username,
              onChange: (e) => setUsername(e.target.value)
            })
          ),
          status.hasPassword && h("div", { style: dshStyles.formGroup },
            h("label", { style: dshStyles.label }, "原密码 (修改密码时必填)"),
            h("input", {
              type: "password",
              style: dshStyles.input,
              value: oldPassword,
              placeholder: "若不修改密码可留空",
              onChange: (e) => setOldPassword(e.target.value)
            })
          ),
          h("div", { style: dshStyles.formGroup },
            h("label", { style: dshStyles.label }, status.hasPassword ? "设置新密码 (留空表示不修改)" : "设置初始密码 (≥6位)"),
            h("input", {
              type: "password",
              style: dshStyles.input,
              value: newPassword,
              placeholder: status.hasPassword ? "输入新密码" : "请设置访问密码 (≥6位)",
              onChange: (e) => setNewPassword(e.target.value)
            })
          ),
          msg && h("div", { style: { color: "var(--dsw-alias-state-success-primary, #3fb950)", fontSize: "13px", marginBottom: "12px" } }, msg),
          err && h("div", { style: { color: "var(--dsw-alias-state-error-primary, #f85149)", fontSize: "13px", marginBottom: "12px" } }, err),
          h("div", { style: { display: "flex", gap: "12px", marginTop: "16px" } },
            h("button", {
              style: { ...dshStyles.primaryButton, width: "auto", padding: "0 22px" },
              onClick: saveSettings
            }, "保存安全配置"),
            status.authenticated && h("button", {
              style: dshStyles.secondaryButton,
              onClick: handleLogout
            }, "退出当前登录")
          )
        )
      );
    }

    exports.apply = function(ctx) {
      // 1. Mount login overlay in shell.overlay
      ctx.slots.inject("shell.overlay", () => {
        ctx.slots.register(
          { name: "shell.overlay", id: "auth-guard-overlay", order: 0 },
          () => h(LoginOverlay, null)
        );
      });

      // 2. Mount settings section in settings.section
      ctx.slots.inject("settings.section", () => {
        ctx.slots.register(
          { name: "settings.section", id: "auth-guard", order: 75, label: "安全与访问" },
          () => h(AuthGuardSettings, null)
        );
      });
    };

    return module.exports;
  }
});
