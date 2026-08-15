# dsh-plugin-auth-guard

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![DeepSeek Harness](https://img.shields.io/badge/DSH-Plugin-blueviolet)](https://github.com/deepseek-ai/deepseek-harness)

**DeepSeek Harness (DSH) 原生企业级零信任安全访问控制与账号密码防护插件**。

一键解决局域网/公网远程访问、特权接口 403 拦截、移动端 Web RPC 崩溃问题，并提供全栈密码防护与零信任安全网关。

---

## 🌟 核心特性

### 1. 全局零信任前置网关（Default-Deny Zero-Trust Gateway）
- **全链路封锁**：在 Node.js `http.Server` 物理套接字层统一拦截 `request` 与 `upgrade` 事件。
- **白名单严格准入**：除静态资源（HTML/CSS/JS/图标）与登录接口外，所有核心 RPC（`/api/*`）及第三方插件自定义路由（如 `/api2/*`、`/sidebar/*`）在未认证时统一阻断（HTTP 401 / WebSocket 断开）。

### 2. 跨平台移动端 Polyfill 动态注入
- 通过 `ctx.webServer.tapIndex` 动态为 Web 前端注水 `crypto.randomUUID`，彻底修复手机端 iOS Safari / Android 在非 HTTPS 局域网环境下因安全上下文缺失导致的 RPC 崩溃。

### 3. 智能特权 RPC 放行（告别 403）
- 为已认证的局域网/远程设备智能代理 `settings.describe`、`llm.providers`、`credentials.*` 等特权接口，移动端可无障碍配置模型与切换提供方。

### 4. 企业级密码学与凭据全生命周期
- **密码安全**：采用加盐 Scrypt（32字节）安全哈希算法存储。
- **时序攻击防御**：密码比对与 Token 签名均采用 `crypto.timingSafeEqual` 恒定时序比对。
- **密码指纹绑定**：Token 载荷与当前密码哈希深度绑定，**管理员一旦修改密码，全网所有已签发的历史 Token 毫秒级即刻作废**。
- **存量长连接熔断**：改密或退出登录时，服务端主动断开所有现存的远程 WebSocket 终端（`/sidebar/ws/terminal`），防止终端逃逸。

### 5. 网络防伪与防爆破
- **防 Host / 代理冒充**：物理 TCP Socket `remoteAddress` 强校验，无法通过伪造 `Host: 127.0.0.1` 绕过密码。
- **防暴力破解**：单 IP 5 次失败封禁 15 分钟 + 全局每分钟 40 次总频次熔断。
- **防 OOM 拒绝服务**：请求体限制 64KB，超大垃圾流量直接熔断。
- **防 CSRF & CSWSH**：严格域名同源比对，防御跨站请求伪造与跨站 WebSocket 劫持。

### 6. 原生 DSH UI 美术风格与跨标签页同步
- 深度适配 DeepSeek Harness 官方设计系统（图标、色彩变量 `--dsw-*`、圆角规范）。
- 锁屏状态采用 `React.createPortal` 顶层挂载并注入全局高斯模糊防护，彻底阻断背景侧边栏穿透点击。
- `BroadcastChannel` 跨标签页状态秒级联动。

---

## 📦 安装与启用

### 方式 1：通过 DSH CLI 安装（推荐）
在终端中执行：
```bash
dsh plugin --profile web add dsh-plugin-auth-guard
```

### 方式 2：本地源码引用（开发者）
1. 将本项目放置在 `~/.dsh/plugins/dsh-plugin-auth-guard`。
2. 在 `~/.dsh/profiles/web/package.json` 的 `dependencies` 中添加：
   ```json
   "dependencies": {
     "dsh-plugin-auth-guard": "link:../../plugins/dsh-plugin-auth-guard"
   }
   ```
3. 在 `dsh.profile.bundles` 中追加 `"dsh-plugin-auth-guard"`。
4. 重启 DSH 服务。

---

## ⚙️ 配置说明

在浏览器打开 DSH，点击左下角 **“设置 (Settings)”** $ightarrow$ **“安全与访问”**：

- **局域网/公网访问必须密码验证 (推荐)**：开启后非本机设备访问强制要求输入密码。
- **全局强制密码认证 (包含本机)**：开启后服务器本机 `127.0.0.1` 访问同样需要密码登录。
- **管理员账号密码**：随时修改用户名与新密码（需 $\ge 6$ 位）。
- **局域网地址速查**：直观展示当前局域网所有活跃 IP，支持一键复制。

---

## 📁 目录结构

```
dsh-plugin-auth-guard/
├── cordis.patch.yml   # Cordis 补丁配置（注入 host 0.0.0.0 及插件挂载）
├── package.json       # 声明 dsh.bundle 与 dsh.client
├── lib/
│   ├── index.js       # Node.js 宿主服务（零信任网关、认证 API、特权 RPC 代理）
│   └── client.js      # 浏览器前端（原生设计风格锁屏门禁、安全设置面板）
├── LICENSE            # MIT 开源协议
├── README.md          # 英文说明文档
└── README_CN.md       # 中文说明文档
```

---

## 📄 开源协议

本项目采用 [MIT License](LICENSE) 开源协议。
