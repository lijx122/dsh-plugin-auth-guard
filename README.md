# dsh-plugin-auth-guard

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![DeepSeek Harness](https://img.shields.io/badge/DSH-Plugin-blueviolet)](https://github.com/deepseek-ai/deepseek-harness)

[中文文档 (README_CN.md)](README_CN.md) | English

**Enterprise-grade Zero-Trust Authentication, LAN/Public Access Control & Security Gate Plugin for DeepSeek Harness (DSH).**

Seamlessly enables secure LAN and remote access, unblocks privileged RPC methods across devices without 403 errors, fixes mobile Safari/Android RPC crashes, and provides a full-stack zero-trust security gate for DeepSeek Harness.

---

## 🌟 Highlights

* **Default-Deny Zero-Trust Gateway**: Intercepts all incoming HTTP and WebSocket connections at the socket level. Blocks unauthenticated access to all core RPCs (`/api/*`) and third-party plugin routes (`/api2/*`, `/sidebar/*`).
* **Cross-Platform Mobile Polyfill**: Dynamically injects `crypto.randomUUID` polyfill via `tapIndex` on the fly, eliminating iOS Safari and mobile browser crashes in non-HTTPS local environments.
* **Privileged RPC Bridge**: Gracefully forwards privileged methods (`settings.describe`, `llm.providers`, etc.) for authenticated LAN clients, resolving the native 403 loopback fence without modifying core files.
* **Cryptographic Security**: Salted Scrypt password hashing + HMAC-SHA256 stateless session tokens bound to password fingerprints (instant revocation across all devices upon password change).
* **Active WebSocket Purge**: Automatically terminates all active remote terminal/event WebSockets upon password change or logout.
* **Anti-Brute-Force & DoS Defense**: Per-IP sliding window rate limiting + global burst throttling + 64KB request body OOM cutoff.
* **CSRF & CSWSH Protection**: Strict hostname matching against cross-origin forgery and Cross-Site WebSocket Hijacking.
* **Native DSH UI Design**: Designed with DSH native tokens (`--dsw-*`), fish logo, top-level lock portal with background blur, and `BroadcastChannel` multi-tab synchronization.

---

## 📦 Installation

### Option 1: Via DSH CLI (Recommended)
```bash
dsh plugin --profile web add dsh-plugin-auth-guard
```

### Option 2: Local Linking (Developer)
1. Place this directory under `~/.dsh/plugins/dsh-plugin-auth-guard`.
2. Add to `~/.dsh/profiles/web/package.json`:
   ```json
   "dependencies": {
     "dsh-plugin-auth-guard": "link:../../plugins/dsh-plugin-auth-guard"
   }
   ```
3. Append `"dsh-plugin-auth-guard"` to `dsh.profile.bundles`.
4. Restart DSH.

---

## ⚙️ Configuration

In DSH Web GUI, navigate to **Settings** $ightarrow$ **Security & Access (安全与访问)**:
* Toggle **Require password for LAN/Remote access** (Recommended).
* Toggle **Enforce password authentication globally** (Including localhost).
* Configure or update administrator credentials ($\ge 6$ characters).
* View and copy active LAN addresses.

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
