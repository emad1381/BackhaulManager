# BackhaulManager — Security Hardening & Performance Presets

Panel `v2.11.1` · Script `v1.6.2`

## 🐞 Preset switch "failed to fetch" fix (v2.11.1)
- Applying a preset rebuilds and restarts **both ends** over SSH. Doing it in a
  single synchronous request meant the restart briefly dropped the very
  connection the panel reply travelled over, so the browser showed
  **"Failed to fetch"** even though the change had actually succeeded (hence it
  looked correct after a manual refresh).
- The switch is now **asynchronous**: `POST /api/tunnel/set-preset` starts the
  work in a background thread and returns a `job` id instantly (before anything
  restarts). The UI polls `GET /api/tunnel/preset-status?job=…` and tolerates
  transient poll failures during the restart, then reports a clear
  **success ✓** or the exact **error** per end. Both ends are rebuilt in
  parallel for speed.

## ✨ Centered paired UI + inline preset switch (v2.11.0)
- **Centered layout & polish** — tunnel rows are now centred on the page
  (max-width, auto margins) instead of hugging the left edge. The connector was
  redesigned: an **animated flowing arrow** (Kharej → Iran) that turns red/static
  when an end is down, a clean transport/port pill, and hover lift on the cards.
- **Applied preset is shown** — the preset chosen at creation is stored as a
  `# bhm_preset` marker in the tunnel config and displayed as a chip above the
  arrow. Manually-edited tunnels show **Custom**.
- **One-click preset switch** — click the preset chip to open a picker (with the
  Speed/Stability/Latency bars), choose a new preset and **Apply & Restart**.
  The new `/api/tunnel/set-preset` endpoint rebuilds **both ends** (preserving
  transport, port, token and port-forwarding from the existing config) and
  restarts them.

## ✨ Paired tunnel dashboard + unique ports (v2.10.0)
- **Paired graphical layout** — the two ends of a tunnel (Kharej + Iran) are no
  longer shown as two unrelated cards. They are now grouped by transport+port
  into a single row: **Kharej on the left → arrow (with transport/port and any
  auto-restart interval) → Iran on the right**. Each new tunnel stacks below the
  previous one (Kharej under Kharej, Iran under Iran). The arrow turns red when
  an end is down. Layout collapses to a vertical stack on small screens.
- **"Delete tunnel" removes BOTH ends** — deleting a tunnel now tears down the
  matching Iran *and* Kharej services together, so you never leave one orphaned
  end running and "disconnected". Deleting one tunnel never touches another
  tunnel on a different port (delete was already isolated per service).
- **Random, unique tunnel port** — the New Tunnel form no longer defaults to a
  fixed `9743`. It picks a random free port (20000-60000) that isn't already in
  use, with a re-roll button. The dashboard stat cards now count *tunnels*
  (pairs), not individual ends.
- **Duplicate-port guard (server-side)** — `create-both` now rejects a port that
  already exists on either the Iran or Kharej server (HTTP 409) instead of
  silently overwriting an existing tunnel.

## 🐞 Throughput preset framesize fix (v2.9.4 / script v1.6.2)
- The **Throughput** preset set `mux_framesize = 65536`, but SMUX rejects any
  frame size **larger than 65535** (16-bit length field). Result: every mux
  session failed with `max frame size must not be larger than 65535` and the
  WSSMUX tunnel could not pass traffic. Lowered to **65535** (the true maximum)
  in both the web panel and the terminal script.
- Added a **server-side clamp**: any custom `mux_framesize > 65535` is now capped
  to 65535 so manual input can't reproduce the crash.
- Re-validated all four presets (Balanced / Gaming / Throughput / Stable) for
  both Iran and Kharej against the SMUX rules: `0 < framesize ≤ 65535`,
  `mux_version ∈ {1,2}`, `streambuffer ≤ receivebuffer`. All pass.

## 🐞 Auto-restart & preset fixes (v2.9.3 / script v1.6.1)
1. **Cron interval bug fixed (critical)** — auto-restart used `*/N * * * *`, but
   the cron *minute* field only accepts 0-59. Every interval ≥ 60 min (1h / 2h /
   6h and most custom values) produced an invalid line that `crontab` rejected,
   so **no job was installed** even though the dashboard still showed the tunnel
   as "scheduled". Intervals are now translated to a valid expression:
   `<60` → `*/N * * * *`, exact hours → `0 */H * * *`, 24h → `0 0 * * *`,
   other values snap to the nearest whole hour. Same fix in panel and script.
2. **No more phantom schedules** — the `.conf` marker (and the dashboard badge)
   is written **only after** the crontab actually loads. A failed install now
   reports an error instead of silently showing an inactive "schedule".
3. **Schedule persists & stays editable** — the per-tunnel clock button always
   reopens the modal showing the current interval; change it or press *Disable*
   to remove. Nothing is auto-deleted.
4. **Preset ↔ transport decoupled** — a preset is a *tuning profile* and now
   works with **any** transport. Selecting a preset still pre-fills its
   recommended transport, but changing the transport manually no longer leaves a
   misleading "best transport: WSSMUX" next to a TCP choice — the info box shows
   `Transport: TCP (your choice) · recommended: WSSMUX`. The generated TOML was
   already transport-correct (mux fields only for mux transports).
5. **Light-mode UI fix** — the active auto-restart button (`.cron-on`), rank
   bars and tooltip badge referenced `--accent*`, a variable only defined on the
   login page. In the dashboard that made the gradient invalid, so the white
   clock icon disappeared on light backgrounds. Added `--accent*` aliases to the
   dashboard theme (plus a solid-colour fallback on the button).

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
