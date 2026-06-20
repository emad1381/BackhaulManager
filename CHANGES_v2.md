# BackhaulManager — Security Hardening & Performance Presets

Panel `v2.9.0` · Script `v1.6.0`

## 🔒 Security fixes (web panel)
1. **SSH command injection fixed** — the `sudo` password path now uses `shlex.quote`
   so a password containing `'`, `;`, `` ` `` or `$()` can no longer break out and run
   arbitrary commands.
2. **SSH password no longer leaks in `ps aux`** — switched from `sshpass -p <pw>`
   (visible to every user via the process list) to `sshpass -e` reading the
   password from the `SSHPASS` environment variable.
3. **Removed `/api/debug_ssh`** — this endpoint let any logged-in session run an
   arbitrary command on any remote server (remote-code-execution risk). Deleted.
4. **Brute-force protection** — 5 failed logins per IP within 5 minutes triggers a
   5-minute lockout (HTTP 429). Successful login clears the counter.
5. **Forced default-password change** — login on the built-in `admin/admin` returns
   `must_change_password`; the panel opens Settings and warns until you set a new one.
6. **Security headers on every page** — `Content-Security-Policy`,
   `X-Frame-Options: DENY` (anti-clickjacking), `X-Content-Type-Options: nosniff`,
   `Referrer-Policy: no-referrer`.
7. **Hardened session cookie** — `SameSite=Strict` (was `Lax`) + `HttpOnly` +
   `Secure` (when TLS is on). Session count capped (50) with expiry pruning.
8. **Configurable bind address** — `PANEL_BIND=127.0.0.1` (env or `panel_config.json`)
   to expose the panel only to a local reverse proxy instead of the whole internet.
9. Passwords are scrubbed from any SSH stdout before being returned to the UI.

> Already present and kept: PBKDF2-HMAC-SHA256 password hashing, constant-time
> comparison, `chmod 600` on `servers.json`/`settings.json`, TLS support.

## ⚡ Performance & stability — Tunnel Presets
Four scenario-based profiles, grounded in the official Backhaul config reference,
shared identically between the **web panel** and the **terminal script**:

| Preset | Best for | Best transport | Speed | Stability | Latency |
|---|---|---|---|---|---|
| **Balanced** (default) | General use, browsing, streaming | WSSMUX | 4/5 | 5/5 | 4/5 |
| **Gaming** | Games, calls, remote desktop | TCP | 3/5 | 4/5 | 5/5 |
| **Throughput** | Big downloads/uploads, many users | WSSMUX | 5/5 | 4/5 | 3/5 |
| **Stable** | Lossy / heavily-filtered links | WSSMUX | 3/5 | 5/5 | 3/5 |

Key tuning logic:
- **Gaming**: `nodelay=true`, small buffers (less bufferbloat), `aggressive_pool`,
  fast retry (1s), short keepalive (20s), `mux_con=4`, lighter logs.
- **Throughput**: large buffers (8 MB recv, 1 MB stream), `mux_framesize=64KB`,
  `mux_con=16`, `connection_pool=32`.
- **Stable**: frequent keepalive/heartbeat (15s) to hold NAT open, 1s retry,
  `aggressive_pool`.
- All presets use SMUX **v2** (better flow control) and `nodelay=true`.

### Web panel
- **Performance Preset** dropdown in *New Tunnel* with a live description, the
  recommended transport (auto-selected), and Speed/Stability/Latency bars.
- **Custom** mode reveals every parameter for Iran (server) and Kharej (client)
  with a hover **ℹ tooltip** explaining each field. Inputs are validated and
  sanitized server-side (numbers/booleans/log-level only — no injection).

### Terminal script
- New **performance-profile picker** during tunnel creation (Balanced / Gaming /
  Throughput / Stable), which sets the baseline for both Preset and Advanced modes.
- Profiles mirror the panel exactly (single source of truth kept in sync).

## 🔁 Auto-restart (cache clearing)
Already supported and unchanged:
- **Panel**: per-tunnel cron, interval in **minutes** (1–1440) — set e.g. every
  few minutes to clear cache / refresh the link.
- **Script**: Manage Tunnels → Schedule Auto-Restart (30 min / 1h / 2h / 6h / custom).

## ✅ Validation performed
- `python3 -m py_compile webpanel/server.py` — OK
- `bash -n backhaul-manager.sh` / `linktest.sh` — OK
- Live smoke test: login, brute-force lockout, session cap, security headers,
  presets API, custom-mode injection attempt (sanitized), TOML generation for all
  presets/roles/transports, bash profile values matching the panel.

> Note: tested in an isolated sandbox. Final functional verification (systemctl
> service start, real SSH between two servers) should be done on your servers.
