#!/usr/bin/env python3
"""
BackhaulManager Web Panel - Multi-Server Edition
Version: 2.11.4 (exact cron match - safe tunnel delete)
Author: emad1381
Manages Iran + Kharej servers from one panel via SSH.
"""

import http.server
import json
import os
import subprocess
import sys
import time
import socketserver
import concurrent.futures
import urllib.parse
from http.cookies import SimpleCookie
import secrets
import socket
import ssl
import hashlib
import hmac
import shlex
import threading
import re as _re

PORT = 54321
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
INSTALL_DIR = "/etc/backhaul"
SERVICE_DIR = "/etc/systemd/system"
BINARY = "/usr/local/bin/backhaul"
CERT_DIR = f"{INSTALL_DIR}/certs"
BACKUP_DIR = f"{INSTALL_DIR}/backups"
CRON_CONFIG_DIR = f"{INSTALL_DIR}/cron"
CRON_MARKER = "# backhaul-auto-restart"
PANEL_DIR = f"{INSTALL_DIR}/webpanel"
SERVERS_FILE = f"{PANEL_DIR}/servers.json"
SETTINGS_FILE = f"{PANEL_DIR}/settings.json"
PANEL_CONFIG_FILE = f"{PANEL_DIR}/panel_config.json"

# Session lifetime in seconds (idle/absolute expiry). Default: 12 hours.
SESSION_TTL = 12 * 3600
# Set to True at startup when the panel is served over HTTPS so the
# session cookie can carry the Secure flag.
SSL_ON = False

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE) as f:
                return json.load(f)
        except:
            pass
    return {"admin_user": ADMIN_USER, "admin_pass": ADMIN_PASS}

def save_settings(data):
    os.makedirs(PANEL_DIR, exist_ok=True)
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(SETTINGS_FILE, 0o600)
    except OSError:
        pass

def load_panel_config():
    """Runtime config (port / TLS) written by the installer (backhaul-manager.sh)."""
    cfg = {"port": PORT, "ssl_enabled": False, "domain": "",
           "ssl_cert": "", "ssl_key": ""}
    if os.path.exists(PANEL_CONFIG_FILE):
        try:
            with open(PANEL_CONFIG_FILE) as f:
                cfg.update(json.load(f) or {})
        except Exception:
            pass
    return cfg

def hash_password(pw, salt=None):
    """Return (salt_hex, hash_hex) using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 100_000).hex()
    return salt, digest

def verify_password(pw, salt, digest):
    if not salt or not digest:
        return False
    try:
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 100_000).hex()
    except Exception:
        return False
    return hmac.compare_digest(calc, digest)

def check_credentials(username, password):
    """Validate login against settings.json. Prefers a stored PBKDF2 hash,
    falls back to a legacy plaintext admin_pass for backward compatibility."""
    settings = load_settings()
    if username != settings.get("admin_user", ADMIN_USER):
        return False
    if settings.get("admin_pass_hash"):
        return verify_password(password, settings.get("admin_salt", ""),
                               settings.get("admin_pass_hash"))
    # Legacy / first-run fallback (plaintext or built-in default).
    return hmac.compare_digest(password, settings.get("admin_pass", ADMIN_PASS))


def is_default_credentials():
    """True while the panel is still using the built-in admin/admin login."""
    settings = load_settings()
    if settings.get("admin_pass_hash"):
        return False
    return (settings.get("admin_user", ADMIN_USER) == ADMIN_USER and
            settings.get("admin_pass", ADMIN_PASS) == ADMIN_PASS)


sessions = {}
_SESSION_LOCK = threading.Lock()
MAX_SESSIONS = 50

# ----- Brute-force protection -----------------------------------------------
# Per-IP sliding window: after MAX_FAILS failures within FAIL_WINDOW seconds the
# IP is locked out for LOCKOUT seconds. Successful login clears the counter.
_login_fails = {}          # ip -> [timestamps]
_login_lock_until = {}     # ip -> epoch when lockout ends
_LOGIN_LOCK = threading.Lock()
MAX_FAILS = 5
FAIL_WINDOW = 300
LOCKOUT = 300


def login_locked(ip):
    with _LOGIN_LOCK:
        until = _login_lock_until.get(ip, 0)
        if until and time.time() < until:
            return int(until - time.time())
    return 0


def record_login_fail(ip):
    now = time.time()
    with _LOGIN_LOCK:
        fails = [t for t in _login_fails.get(ip, []) if now - t < FAIL_WINDOW]
        fails.append(now)
        _login_fails[ip] = fails
        if len(fails) >= MAX_FAILS:
            _login_lock_until[ip] = now + LOCKOUT
            _login_fails[ip] = []


def record_login_ok(ip):
    with _LOGIN_LOCK:
        _login_fails.pop(ip, None)
        _login_lock_until.pop(ip, None)


def new_session(user):
    """Create a session id, enforcing a global cap and pruning expired ones."""
    sid = secrets.token_hex(32)
    now = time.time()
    with _SESSION_LOCK:
        for k in [k for k, v in sessions.items() if now - v.get("time", 0) > SESSION_TTL]:
            sessions.pop(k, None)
        if len(sessions) >= MAX_SESSIONS:
            oldest = sorted(sessions.items(), key=lambda kv: kv[1].get("time", 0))
            for k, _ in oldest[:len(sessions) - MAX_SESSIONS + 1]:
                sessions.pop(k, None)
        sessions[sid] = {"user": user, "time": now}
    return sid

def run_cmd(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "Command timed out", 1
    except Exception as e:
        return str(e), 1

# Cache `which sshpass` so we don't spawn a subprocess on every SSH call.
_SSHPASS_OK = None
def _sshpass_available():
    global _SSHPASS_OK
    if _SSHPASS_OK is None:
        out, _ = run_cmd("command -v sshpass")
        _SSHPASS_OK = bool(out)
    return _SSHPASS_OK

# Short-lived caches so the dashboard renders instantly on re-fetch / tab
# switches instead of re-running an SSH sweep every time. Invalidated on any
# mutating action so the UI always reflects the latest state after a change.
_INFO_CACHE = {}
_TUNNEL_CACHE = {}
_CACHE_TTL = 6  # seconds

# ============================================================================
#  TUNNEL PRESETS  (single source of truth, mirrored in backhaul-manager.sh)
#  Values are grounded in the official Backhaul configuration reference.
#  Each preset carries a full server (iran) + client (kharej) parameter set.
# ============================================================================
PRESETS = {
    "balanced": {
        "label": "Balanced \u2014 Recommended",
        "label_fa": "\u0645\u062a\u0639\u0627\u062f\u0644 (\u067e\u06cc\u0634\u0646\u0647\u0627\u062f\u06cc)",
        "desc": "Best all-round choice. Strong speed and stability for general use, browsing, streaming and downloads.",
        "best_transport": "wssmux",
        "rank_speed": 4, "rank_stability": 5, "rank_latency": 4,
        "iran":   {"keepalive_period": 75, "nodelay": "true", "heartbeat": 30, "channel_size": 4096,
                    "mux_con": 8, "mux_version": 2, "mux_framesize": 32768,
                    "mux_recievebuffer": 4194304, "mux_streambuffer": 262144,
                    "sniffer": "false", "web_port": 0, "log_level": "info",
                    "mss": 1360, "so_rcvbuf": 4194304, "so_sndbuf": 4194304},
        "kharej": {"connection_pool": 16, "aggressive_pool": "false", "keepalive_period": 75,
                    "nodelay": "true", "retry_interval": 3, "dial_timeout": 10,
                    "mux_version": 2, "mux_framesize": 32768,
                    "mux_recievebuffer": 4194304, "mux_streambuffer": 262144,
                    "sniffer": "false", "web_port": 0, "log_level": "info",
                    "mss": 1360, "so_rcvbuf": 4194304, "so_sndbuf": 4194304},
    },
    "gaming": {
        "label": "Gaming \u2014 Low Latency",
        "label_fa": "\u06af\u06cc\u0645\u06cc\u0646\u06af / \u06a9\u0645\u200c\u062a\u0623\u062e\u06cc\u0631",
        "desc": "Lowest ping for online games, calls and remote desktop. Small buffers cut bufferbloat; aggressive pool keeps connections hot.",
        "best_transport": "tcp",
        "rank_speed": 3, "rank_stability": 4, "rank_latency": 5,
        "iran":   {"keepalive_period": 20, "nodelay": "true", "heartbeat": 20, "channel_size": 2048,
                    "mux_con": 4, "mux_version": 2, "mux_framesize": 16384,
                    "mux_recievebuffer": 2097152, "mux_streambuffer": 65536,
                    "sniffer": "false", "web_port": 0, "log_level": "error",
                    "mss": 1360, "so_rcvbuf": 2097152, "so_sndbuf": 2097152},
        "kharej": {"connection_pool": 24, "aggressive_pool": "true", "keepalive_period": 20,
                    "nodelay": "true", "retry_interval": 1, "dial_timeout": 5,
                    "mux_version": 2, "mux_framesize": 16384,
                    "mux_recievebuffer": 2097152, "mux_streambuffer": 65536,
                    "sniffer": "false", "web_port": 0, "log_level": "error",
                    "mss": 1360, "so_rcvbuf": 2097152, "so_sndbuf": 2097152},
    },
    "throughput": {
        "label": "Throughput \u2014 Max Speed",
        "label_fa": "\u062d\u062f\u0627\u06a9\u062b\u0631 \u0633\u0631\u0639\u062a \u062f\u0627\u0646\u0644\u0648\u062f",
        "desc": "Highest bandwidth for big downloads/uploads and many users. Large buffers and more mux connections maximise raw throughput.",
        "best_transport": "wssmux",
        "rank_speed": 5, "rank_stability": 4, "rank_latency": 3,
        "iran":   {"keepalive_period": 75, "nodelay": "true", "heartbeat": 40, "channel_size": 8192,
                    "mux_con": 16, "mux_version": 2, "mux_framesize": 65535,
                    "mux_recievebuffer": 8388608, "mux_streambuffer": 1048576,
                    "sniffer": "false", "web_port": 0, "log_level": "error",
                    "mss": 1360, "so_rcvbuf": 8388608, "so_sndbuf": 8388608},
        "kharej": {"connection_pool": 32, "aggressive_pool": "true", "keepalive_period": 75,
                    "nodelay": "true", "retry_interval": 2, "dial_timeout": 10,
                    "mux_version": 2, "mux_framesize": 65535,
                    "mux_recievebuffer": 8388608, "mux_streambuffer": 1048576,
                    "sniffer": "false", "web_port": 0, "log_level": "error",
                    "mss": 1360, "so_rcvbuf": 8388608, "so_sndbuf": 8388608},
    },
    "stable": {
        "label": "Stable \u2014 Lossy / Filtered Network",
        "label_fa": "\u067e\u0627\u06cc\u062f\u0627\u0631 / \u0634\u0628\u06a9\u0647 \u067e\u0631\u0627\u0641\u062a",
        "desc": "Maximum resistance to drops on unstable or heavily filtered links. Frequent keepalive holds NAT open; quick retries recover fast.",
        "best_transport": "wssmux",
        "rank_speed": 3, "rank_stability": 5, "rank_latency": 3,
        "iran":   {"keepalive_period": 15, "nodelay": "true", "heartbeat": 15, "channel_size": 4096,
                    "mux_con": 8, "mux_version": 2, "mux_framesize": 32768,
                    "mux_recievebuffer": 4194304, "mux_streambuffer": 131072,
                    "sniffer": "false", "web_port": 0, "log_level": "warn",
                    "mss": 1360, "so_rcvbuf": 4194304, "so_sndbuf": 4194304},
        "kharej": {"connection_pool": 16, "aggressive_pool": "true", "keepalive_period": 15,
                    "nodelay": "true", "retry_interval": 1, "dial_timeout": 8,
                    "mux_version": 2, "mux_framesize": 32768,
                    "mux_recievebuffer": 4194304, "mux_streambuffer": 131072,
                    "sniffer": "false", "web_port": 0, "log_level": "warn",
                    "mss": 1360, "so_rcvbuf": 4194304, "so_sndbuf": 4194304},
    },
}

# Per-field help text shown on the (i) tooltips in the custom builder.
PARAM_HELP = {
    "keepalive_period": "Seconds between keep-alive packets that hold the tunnel/NAT open. Lower = faster dead-link detection, slightly more overhead.",
    "nodelay": "TCP_NODELAY. true sends packets immediately (lower latency, best for gaming). false batches them (slightly better for bulk transfer).",
    "heartbeat": "Seconds between health pings on the control channel. Lower reacts faster to a broken tunnel.",
    "channel_size": "Size of the internal connection queue. Larger handles more simultaneous new connections before dropping.",
    "mux_con": "How many TCP connections each mux stream is spread across. More can raise throughput on high-bandwidth links.",
    "mux_version": "SMUX protocol version. 2 is newer with better flow control/keepalive; 1 is the legacy fallback.",
    "mux_framesize": "Max bytes per mux frame. Larger reduces framing overhead (good for downloads); smaller reduces latency.",
    "mux_recievebuffer": "Per-connection receive buffer (bytes). Larger sustains higher throughput; uses more RAM.",
    "mux_streambuffer": "Per-stream buffer (bytes). Larger smooths bursts; smaller reduces bufferbloat/latency.",
    "connection_pool": "Pre-opened client connections kept ready. More removes connect latency under load.",
    "aggressive_pool": "true keeps the pool eagerly refilled for instant connections (great for gaming), at the cost of a few idle connections.",
    "retry_interval": "Seconds to wait before the client reconnects after a drop. Lower recovers faster.",
    "dial_timeout": "Max seconds to wait when establishing a new connection before giving up.",
    "sniffer": "Traffic logging for diagnostics. Keep false in production for best performance.",
    "web_port": "Built-in monitor web port. 0 disables it (recommended).",
    "log_level": "Verbosity: panic/fatal/error/warn/info/debug/trace. error/warn are lightest for production.",
    "mss": "TCP Maximum Segment Size (TCP/TCPMUX). 1360 avoids fragmentation over most tunnels.",
    "so_rcvbuf": "OS socket receive buffer (bytes) for TCP/TCPMUX. Larger helps throughput.",
    "so_sndbuf": "OS socket send buffer (bytes) for TCP/TCPMUX. Larger helps throughput.",
}


def get_preset(name, role):
    """Return a copy of the preset param dict for the given role, or None."""
    p = PRESETS.get(name)
    if not p:
        return None
    return dict(p.get("iran" if role == "iran" else "kharej", {}))

def build_cron_expr(minutes):
    """Translate an interval in *minutes* into a VALID 5-field cron time spec.

    The cron minute field only accepts 0-59, so the old ``*/{minutes}`` form
    silently broke for every interval >= 60 (1h / 2h / 6h and most custom
    values): the line was rejected by crontab, so the job was never installed
    even though the dashboard still showed it as "scheduled". This builds a
    proper expression instead:
        < 60 min            -> every N minutes      ("*/N * * * *")
        exact hour multiple -> every H hours on :00 ("0 */H * * *")
        24h (1440) or more  -> once a day at 00:00  ("0 0 * * *")
        other > 60 values   -> snapped to the nearest whole hour on :00
    Returns None for non-positive intervals.
    """
    try:
        m = int(minutes)
    except (TypeError, ValueError):
        return None
    if m < 1:
        return None
    if m < 60:
        return f"*/{m} * * * *"
    if m % 60 == 0:
        h = m // 60
        return "0 0 * * *" if h >= 24 else f"0 */{h} * * *"
    h = max(1, round(m / 60))
    return "0 0 * * *" if h >= 24 else f"0 */{h} * * *"

# ----- Preset-switch background jobs ----------------------------------------
# Re-applying a preset rebuilds + restarts BOTH ends over SSH, which can take a
# few seconds and briefly drop the very connection the panel is reached through.
# Doing it synchronously made the browser show "Failed to fetch" even though the
# change succeeded. So we ACK instantly with a job id, do the work in a daemon
# thread, and let the client poll /api/tunnel/preset-status for the result.
_PRESET_JOBS = {}
_PRESET_JOBS_LOCK = threading.Lock()

def _apply_preset_to_end(end, preset, servers_data):
    svc = end.get("service", "")
    sid = end.get("server_id", "")
    if not is_safe_svc(svc):
        return {"service": svc, "success": False, "error": "invalid service name"}
    srv = next((s for s in servers_data.get("servers", []) if s.get("id") == sid), None)
    if not srv:
        return {"service": svc, "success": False, "error": "server not found"}
    name = svc.replace("backhaul-", "").replace(".service", "")
    mm = _re.match(r"^(iran|kharej)-(tcp|tcpmux|wsmux|wssmux)-(\d+)$", name)
    if not mm:
        return {"service": svc, "success": False, "error": "cannot parse service name"}
    role, transport, port = mm.group(1), mm.group(2), mm.group(3)
    cfg_path = f"{INSTALL_DIR}/{role}-{transport}-{port}.toml"
    cfg_text, _ = remote_exec(srv, f"cat {cfg_path} 2>/dev/null")
    cfg_text = cfg_text or ""
    tok_m = _re.search(r'token\s*=\s*"([^"]*)"', cfg_text)
    params = {"role": role, "transport": transport, "port": port,
              "token": tok_m.group(1) if tok_m else "", "preset": preset}
    if role == "kharej":
        ra = _re.search(r'remote_addr\s*=\s*"([^"]+):\d+"', cfg_text)
        if ra:
            params["iran_ip"] = ra.group(1)
    else:
        pm = _re.search(r'ports\s*=\s*\[(.*?)\]', cfg_text, _re.S)
        if pm:
            params["ports"] = pm.group(1).strip()
    try:
        res = create_tunnel_on_server(srv, params)
    except Exception as e:
        return {"service": svc, "success": False, "error": str(e)}
    invalidate_cache(sid)
    return {"service": svc, "success": bool(res.get("success")), "error": res.get("error"),
            "server": srv.get("name", "")}

def _run_preset_job(job_id, preset, ends, servers_data):
    results = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            futs = [ex.submit(_apply_preset_to_end, e, preset, servers_data) for e in ends]
            for f in concurrent.futures.as_completed(futs):
                results.append(f.result())
    except Exception as e:
        results.append({"success": False, "error": str(e)})
    ok = bool(results) and all(r.get("success") for r in results)
    invalidate_cache()
    with _PRESET_JOBS_LOCK:
        _PRESET_JOBS[job_id] = {"done": True, "success": ok, "results": results,
                                "preset": preset, "time": time.time()}

def invalidate_cache(server_id=None):
    if server_id:
        _INFO_CACHE.pop(server_id, None)
        _TUNNEL_CACHE.pop(server_id, None)
    else:
        _INFO_CACHE.clear()
        _TUNNEL_CACHE.clear()

def run_ssh(host, user, key_file, cmd, timeout=30, password="", port=22):
    if not is_safe_ip_domain(host):
        return "Invalid SSH host IP/domain name", 1

    if user != "root" and cmd.startswith("sudo "):
        if password:
            # shlex.quote prevents shell injection if the password contains
            # quotes/semicolons/backticks; -p '' silences the sudo prompt.
            cmd = f"printf '%s\\n' {shlex.quote(password)} | sudo -S -p '' {cmd[5:]}"
        else:
            cmd = f"sudo -n {cmd[5:]}"

    ssh_opts = ["-T",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=4",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=2",
        "-o", "GSSAPIAuthentication=no",
        "-o", "Compression=no",
        "-o", "ControlMaster=auto",
        "-o", "ControlPath=/tmp/ssh_mux_%h_%p_%r",
        "-o", "ControlPersist=10m",
        "-p", str(port)
    ]
    run_env = dict(os.environ)
    if password:
        if not _sshpass_available():
            return "sshpass not installed. Run: apt install sshpass", 1
        ssh_opts.extend(["-o", "PubkeyAuthentication=no",
                         "-o", "PreferredAuthentications=password"])
        # `sshpass -e` reads the password from the SSHPASS env var instead of
        # the command line, so it never appears in `ps aux` / process listings.
        run_env["SSHPASS"] = password
        full_cmd = ["sshpass", "-e", "ssh"] + ssh_opts + [f"{user}@{host}", cmd]
    else:
        ssh_opts.extend(["-o", "BatchMode=yes",
                         "-o", "PreferredAuthentications=publickey"])
        if key_file:
            full_cmd = ["ssh", "-i", key_file] + ssh_opts + [f"{user}@{host}", cmd]
        else:
            full_cmd = ["ssh"] + ssh_opts + [f"{user}@{host}", cmd]
    try:
        r = subprocess.run(full_cmd, capture_output=True, text=True,
                           timeout=timeout, env=run_env)
        out = r.stdout.strip()
        # Never echo a leaked password back through stdout/stderr.
        if password and password in out:
            out = out.replace(password, "***")
        return out, r.returncode
    except subprocess.TimeoutExpired:
        return "Command timed out", 1
    except Exception as e:
        return str(e), 1

def is_safe_svc(name):
    if not name:
        return False
    return all(c.isalnum() or c in "-._" for c in name)

def is_safe_ip_domain(target):
    if not target:
        return False
    return all(c.isalnum() or c in ".-:[]" for c in target)

def get_local_ip():
    out, _ = run_cmd("hostname -I 2>/dev/null | awk '{print $1}' || ip route get 1 2>/dev/null | awk '{print $7}'")
    return out if out else "127.0.0.1"

def get_server_role(host=None, user=None, key_file=None, password="", port=22):
    if host and host != "127.0.0.1" and host != "localhost":
        cmd = sudo_cmd(user, "systemctl list-units --type=service --state=running 2>/dev/null | grep -q 'backhaul-iran' && echo iran || (systemctl list-units --type=service --state=running 2>/dev/null | grep -q 'backhaul-kharej' && echo kharej || echo unknown)")
        out, _ = run_ssh(host, user, key_file, cmd, password=password, port=port)
    else:
        out, _ = run_cmd("systemctl list-units --type=service --state=running 2>/dev/null | grep -q 'backhaul-iran' && echo iran || (systemctl list-units --type=service --state=running 2>/dev/null | grep -q 'backhaul-kharej' && echo kharej || echo unknown)")
    return out.strip() if out else "unknown"

def load_servers():
    if os.path.exists(SERVERS_FILE):
        try:
            with open(SERVERS_FILE) as f:
                return json.load(f)
        except:
            pass
    return {"servers": []}

def save_servers(data):
    os.makedirs(PANEL_DIR, exist_ok=True)
    with open(SERVERS_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    # This file holds SSH passwords/keys - keep it root-only.
    try:
        os.chmod(SERVERS_FILE, 0o600)
    except OSError:
        pass
    # Server list changed - drop cached info so the UI reflects it immediately.
    invalidate_cache()

def sudo_cmd(user, cmd):
    if user != "root":
        return f"sudo {cmd}"
    return cmd

def get_binary_version(host=None, user=None, key_file=None, password="", port=22):
    if host and host != "127.0.0.1" and host != "localhost":
        out, _ = run_ssh(host, user, key_file, sudo_cmd(user, f"{BINARY} -v 2>/dev/null"), password=password, port=port)
    else:
        out, _ = run_cmd(f"{BINARY} -v 2>/dev/null")
    return out if out else "not installed"

def get_server_info(srv):
    sid = srv.get("id", "")
    now = time.time()
    c = _INFO_CACHE.get(sid)
    if c and now - c[0] < _CACHE_TTL:
        return c[1]
    res = _get_server_info_uncached(srv)
    if sid:
        _INFO_CACHE[sid] = (now, res)
    return res

def _get_server_info_uncached(srv):
    host = srv.get("ip", "127.0.0.1")
    user = srv.get("ssh_user", "root")
    key = srv.get("ssh_key", "")
    password = srv.get("ssh_password", "")
    port = srv.get("ssh_port", 22)
    name = srv.get("name", "Unknown")
    role = srv.get("role", "unknown")
    is_local = host in ["127.0.0.1", "localhost", get_local_ip()]

    if is_local:
        ip = get_local_ip()
        hostname_out, _ = run_cmd("hostname")
        version = get_binary_version()
        role_actual = get_server_role()
        kernel, _ = run_cmd("uname -r")
        load, _ = run_cmd("cut -d' ' -f1-3 /proc/loadavg")
        mem, _ = run_cmd("free -h | awk '/^Mem:/{print $3 \" used / \" $2}'")
        disk, _ = run_cmd("df -h / | awk 'NR==2{print $3 \" used / \" $2}'")
        uptime_out, _ = run_cmd("uptime -p")
        ssh_ok = True
    else:
        ip = host
        cmd = (
            "echo -n 'HOST:'; hostname; "
            "echo -n 'KERNEL:'; uname -r; "
            "echo -n 'LOAD:'; cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo ''; "
            "echo -n 'MEM:'; free -h 2>/dev/null | awk '/^Mem:/{print $3 \" used / \" $2}' || echo ''; "
            "echo -n 'DISK:'; df -h / 2>/dev/null | awk 'NR==2{print $3 \" used / \" $2}' || echo ''; "
            "echo -n 'UPTIME:'; uptime -p 2>/dev/null || uptime | awk -F', ' '{print $1}' || echo ''; "
            "echo -n 'ROLE:'; systemctl list-units --type=service --state=running 2>/dev/null | grep -q 'backhaul-iran' && echo iran || (systemctl list-units --type=service --state=running 2>/dev/null | grep -q 'backhaul-kharej' && echo kharej || echo unknown); "
            f"echo -n 'VER:'; {BINARY} -v 2>/dev/null || echo 'not installed'"
        )
        out, _ = run_ssh(host, user, key, sudo_cmd(user, cmd), password=password, port=port)
        
        hostname_out, kernel, load, mem, disk, uptime_out, role_actual, version = "", "", "", "", "", "", "unknown", "not installed"
        ssh_ok = False
        
        if out:
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("HOST:"):
                    hostname_out = line[5:].strip()
                elif line.startswith("KERNEL:"):
                    kernel = line[7:].strip()
                elif line.startswith("LOAD:"):
                    load = line[5:].strip()
                elif line.startswith("MEM:"):
                    mem = line[4:].strip()
                elif line.startswith("DISK:"):
                    disk = line[5:].strip()
                elif line.startswith("UPTIME:"):
                    uptime_out = line[7:].strip()
                elif line.startswith("ROLE:"):
                    role_actual = line[5:].strip()
                elif line.startswith("VER:"):
                    version = line[4:].strip()
            
            ssh_ok = (hostname_out != "" and "Permission denied" not in hostname_out and "Connection refused" not in hostname_out and "No route to host" not in hostname_out)

    return {
        "id": srv.get("id", ""),
        "name": name,
        "ip": ip,
        "role": role_actual if role_actual != "unknown" else role,
        "ssh_user": user,
        "version": version,
        "hostname": hostname_out,
        "kernel": kernel,
        "load": load,
        "memory": mem,
        "disk": disk,
        "uptime": uptime_out,
        "ssh_ok": ssh_ok,
        "is_local": is_local
    }

def get_tunnels_from_server(srv):
    sid = srv.get("id", "")
    now = time.time()
    c = _TUNNEL_CACHE.get(sid)
    if c and now - c[0] < _CACHE_TTL:
        return c[1]
    res = _get_tunnels_from_server_uncached(srv)
    if sid:
        _TUNNEL_CACHE[sid] = (now, res)
    return res

def _get_tunnels_from_server_uncached(srv):
    host = srv.get("ip", "127.0.0.1")
    user = srv.get("ssh_user", "root")
    key = srv.get("ssh_key", "")
    password = srv.get("ssh_password", "")
    port = srv.get("ssh_port", 22)
    is_local = host in ["127.0.0.1", "localhost", get_local_ip()]

    tunnels = []

    if is_local:
        out, _ = run_cmd("systemctl list-unit-files --type=service 2>/dev/null | grep -o 'backhaul[^ ]*\\.service' | sort -u")
        if not out:
            return tunnels

        for svc in out.split('\n'):
            svc = svc.strip()
            if not svc:
                continue

            status_out, _ = run_cmd(f"systemctl is-active {svc} 2>/dev/null")
            pid_out, _ = run_cmd(f"systemctl show -p MainPID --value {svc} 2>/dev/null")
            cpu_out, _ = run_cmd(f"ps -p $(systemctl show -p MainPID --value {svc} 2>/dev/null) -o %cpu= 2>/dev/null") if pid_out.strip() not in ["0", ""] else ("", 1)
            mem_out, _ = run_cmd(f"ps -p $(systemctl show -p MainPID --value {svc} 2>/dev/null) -o rss= 2>/dev/null") if pid_out.strip() not in ["0", ""] else ("", 1)
            up_out, _ = run_cmd(f"ps -p $(systemctl show -p MainPID --value {svc} 2>/dev/null) -o etime= 2>/dev/null") if pid_out.strip() not in ["0", ""] else ("", 1)

            cpu = cpu_out.strip() if cpu_out else "—"
            try:
                mem_val = int(mem_out.strip()) if mem_out.strip() else 0
                mem = f"{mem_val/1024:.1f}M"
            except:
                mem = "—"
            uptime_s = up_out.strip() if up_out else "—"

            transport, bind_addr = "?", "?"
            preset = ""
            config_name = svc.replace("backhaul-", "").replace(".service", "")
            config_path = f"{INSTALL_DIR}/{config_name}.toml"

            if os.path.exists(config_path):
                try:
                    with open(config_path) as f:
                        for line in f:
                            if line.startswith("# bhm_preset"):
                                preset = line.split("=", 1)[1].strip()
                            if 'transport' in line and '=' in line:
                                transport = line.split('"')[1] if '"' in line else line.split('=')[1].strip()
                            if 'bind_addr' in line or 'remote_addr' in line:
                                bind_addr = line.split('"')[1] if '"' in line else line.split('=')[1].strip()
                except:
                    pass

            cron_active = False
            cron_interval = ""
            cron_conf = f"{CRON_CONFIG_DIR}/{svc}.conf"
            if os.path.exists(cron_conf):
                try:
                    with open(cron_conf) as f:
                        for line in f:
                            if line.startswith("INTERVAL="):
                                cron_interval = line.strip().split("=", 1)[1]
                                cron_active = True
                except:
                    pass

            tunnels.append({
                "server_id": srv.get("id", ""),
                "server_name": srv.get("name", ""),
                "service": svc,
                "status": "running" if status_out.strip() == "active" else "stopped",
                "cpu": cpu,
                "memory": mem,
                "uptime": uptime_s,
                "transport": transport,
                "bind_addr": bind_addr,
                "cron_active": cron_active,
                "cron_interval": cron_interval,
                "preset": preset
            })

        return tunnels

    # --- REMOTE: single SSH call gathers ALL tunnel data at once ---
    gather_script = f"""bash -c '
SVCS=$(systemctl list-unit-files --type=service 2>/dev/null | grep -o "backhaul[^ ]*\\.service" | sort -u)
[ -z "$SVCS" ] && exit 0
for svc in $SVCS; do
  STATUS=$(systemctl is-active "$svc" 2>/dev/null)
  PID=$(systemctl show -p MainPID --value "$svc" 2>/dev/null)
  CPU=""; MEM=""; UPTIME=""
  if [ "$PID" != "0" ] && [ -n "$PID" ]; then
    CPU=$(ps -p "$PID" -o %cpu= 2>/dev/null)
    MEM=$(ps -p "$PID" -o rss= 2>/dev/null)
    UPTIME=$(ps -p "$PID" -o etime= 2>/dev/null)
  fi
  CFG_NAME=$(echo "$svc" | sed "s/^backhaul-//;s/\\.service$//")
  CFG_PATH="{INSTALL_DIR}/$CFG_NAME.toml"
  TRANSPORT="?"; BIND="?"; PRESET=""
  if [ -f "$CFG_PATH" ]; then
    TRANSPORT=$(grep "transport" "$CFG_PATH" 2>/dev/null | head -1 | sed -n "s/.*\\"\\([^\\"]*\\)\\".*/\\1/p")
    [ -z "$TRANSPORT" ] && TRANSPORT="?"
    BIND=$(grep -E "bind_addr|remote_addr" "$CFG_PATH" 2>/dev/null | head -1 | sed -n "s/.*\\"\\([^\\"]*\\)\\".*/\\1/p")
    [ -z "$BIND" ] && BIND="?"
    PRESET=$(grep "^# bhm_preset" "$CFG_PATH" 2>/dev/null | head -1 | cut -d= -f2 | tr -d " ")
  fi
  CRON_INT=""
  CRON_CONF="{CRON_CONFIG_DIR}/$svc.conf"
  if [ -f "$CRON_CONF" ]; then
    CRON_INT=$(grep "^INTERVAL=" "$CRON_CONF" 2>/dev/null | cut -d= -f2)
  fi
  echo "SVC_DATA:$svc|$STATUS|$CPU|$MEM|$UPTIME|$TRANSPORT|$BIND|$CRON_INT|$PRESET"
done
'"""

    out, _ = run_ssh(host, user, key, sudo_cmd(user, gather_script), password=password, port=port, timeout=30)
    if not out:
        return tunnels

    for line in out.split('\n'):
        line = line.strip()
        if not line.startswith("SVC_DATA:"):
            continue
        parts = line[9:].split("|", 8)
        if len(parts) < 9:
            parts.extend([""] * (9 - len(parts)))

        svc, status_raw, cpu_raw, mem_raw, uptime_raw, transport, bind_addr, cron_int, preset = parts

        cpu = cpu_raw.strip() if cpu_raw.strip() else "—"
        try:
            mem_val = int(mem_raw.strip()) if mem_raw.strip() else 0
            mem = f"{mem_val/1024:.1f}M"
        except:
            mem = "—"
        uptime_s = uptime_raw.strip() if uptime_raw.strip() else "—"
        transport = transport.strip() if transport.strip() else "?"
        bind_addr = bind_addr.strip() if bind_addr.strip() else "?"

        cron_active = bool(cron_int.strip())
        cron_interval = cron_int.strip()

        tunnels.append({
            "server_id": srv.get("id", ""),
            "server_name": srv.get("name", ""),
            "service": svc.strip(),
            "status": "running" if status_raw.strip() == "active" else "stopped",
            "cpu": cpu,
            "memory": mem,
            "uptime": uptime_s,
            "transport": transport,
            "bind_addr": bind_addr,
            "cron_active": cron_active,
            "cron_interval": cron_interval,
            "preset": preset.strip()
        })

    return tunnels

def remote_exec(srv, cmd, timeout=30):
    host = srv.get("ip", "127.0.0.1")
    user = srv.get("ssh_user", "root")
    key = srv.get("ssh_key", "")
    password = srv.get("ssh_password", "")
    port = srv.get("ssh_port", 22)
    is_local = host in ["127.0.0.1", "localhost", get_local_ip()]
    if is_local:
        return run_cmd(cmd, timeout)
    return run_ssh(host, user, key, sudo_cmd(user, cmd), timeout, password=password, port=port)

def create_tunnel_on_server(srv, params):
    role = params.get("role", srv.get("role", "iran"))
    transport = params.get("transport", "wssmux")
    port = params.get("port", "9743")
    token = params.get("token", "")
    iran_ip = params.get("iran_ip", "")
    ports_mapping = params.get("ports", "")

    # Strict validation of inputs
    if role not in ["iran", "kharej"]:
        return {"success": False, "error": f"Invalid role: {role}"}
    if transport not in ["tcp", "tcpmux", "wsmux", "wssmux"]:
        return {"success": False, "error": f"Invalid transport: {transport}"}
    try:
        port_num = int(port)
        if not (1 <= port_num <= 65535):
            raise ValueError
        port = str(port_num)
    except:
        return {"success": False, "error": f"Invalid port: {port}"}
    if token:
        import re
        if not re.match(r"^[a-zA-Z0-9_-]+$", token):
            return {"success": False, "error": "Invalid token format"}
    if role == "kharej" and iran_ip:
        if not is_safe_ip_domain(iran_ip):
            return {"success": False, "error": f"Invalid Iran IP/domain: {iran_ip}"}
    if role == "iran" and ports_mapping:
        import re
        rules = re.findall(r'"([^"]+)"', ports_mapping)
        if not rules:
            rules = [r.strip() for r in ports_mapping.split(",") if r.strip()]
        rule_pattern = re.compile(r"^\d+=[a-zA-Z0-9._\[\]:-]+:\d+$")
        for rule in rules:
            if not rule_pattern.match(rule):
                return {"success": False, "error": f"Invalid port mapping format: {rule}"}


    if not token:
        tok_out, _ = remote_exec(srv, "cat /proc/sys/kernel/random/uuid 2>/dev/null || head -c 32 /dev/urandom | base64")
        token = tok_out[:36] if tok_out else secrets.token_hex(16)

    svc_name = f"backhaul-{role}-{transport}-{port}"
    config_file = f"{INSTALL_DIR}/{role}-{transport}-{port}.toml"
    service_file = f"{SERVICE_DIR}/{svc_name}.service"

    is_local = srv.get("ip", "") in ["127.0.0.1", "localhost", get_local_ip()]

    # --- Resolve tuning parameters from preset / custom overrides ----------
    preset_name = params.get("preset", "balanced")
    if preset_name not in PRESETS and preset_name != "custom":
        return {"success": False, "error": f"Invalid preset: {preset_name}"}

    # Base values come from a known-good preset; "custom" starts from balanced.
    base = get_preset("balanced" if preset_name == "custom" else preset_name, role) or {}
    custom = {}
    if preset_name == "custom":
        raw_custom = params.get("custom", {}) or {}
        # custom may be namespaced per side {"iran":{...},"kharej":{...}} or flat.
        if isinstance(raw_custom, dict) and ("iran" in raw_custom or "kharej" in raw_custom):
            custom = raw_custom.get(role, {}) or {}
        elif isinstance(raw_custom, dict):
            custom = raw_custom

    _BOOL = {"nodelay", "aggressive_pool", "sniffer"}
    _LOGLEVELS = {"panic", "fatal", "error", "warn", "info", "debug", "trace"}

    def _val(key):
        v = custom.get(key, base.get(key))
        if key in _BOOL:
            return "true" if str(v).lower() in ("true", "1", "yes", "on") else "false"
        if key == "log_level":
            return v if v in _LOGLEVELS else "info"
        try:
            n = int(v)
            if n < 0:
                n = 0
            # SMUX rejects a frame size above 65535 (16-bit length field), which
            # crashes every mux session. Clamp it so custom input can't break.
            if key == "mux_framesize" and n > 65535:
                n = 65535
            return n
        except (TypeError, ValueError):
            return base.get(key, 0)

    # --- Build config content (common to local and remote) ---
    if role == "iran":
        config_lines = [
            "[server]",
            f'bind_addr = "0.0.0.0:{port}"',
            f'transport = "{transport}"',
        ]
        if transport == "tcp":
            config_lines.append("accept_udp = false")
        config_lines.extend([
            f'token = "{token}"',
            f'keepalive_period = {_val("keepalive_period")}',
            f'nodelay = {_val("nodelay")}',
            f'heartbeat = {_val("heartbeat")}',
            f'channel_size = {_val("channel_size")}',
        ])
        if transport != "tcp":
            config_lines.extend([
                f'mux_con = {_val("mux_con")}',
                f'mux_version = {_val("mux_version")}',
                f'mux_framesize = {_val("mux_framesize")}',
                f'mux_recievebuffer = {_val("mux_recievebuffer")}',
                f'mux_streambuffer = {_val("mux_streambuffer")}',
            ])
        if transport == "wssmux":
            config_lines.extend([f'tls_cert = "{CERT_DIR}/wssmux.crt"', f'tls_key = "{CERT_DIR}/wssmux.key"'])
        config_lines.extend([f'sniffer = {_val("sniffer")}', f'web_port = {_val("web_port")}', f'log_level = "{_val("log_level")}"'])
        if transport in ("tcp", "tcpmux"):
            config_lines.extend([f'mss = {_val("mss")}', f'so_rcvbuf = {_val("so_rcvbuf")}', f'so_sndbuf = {_val("so_sndbuf")}'])
        if ports_mapping:
            config_lines.append(f"ports = [{ports_mapping}]")
        else:
            config_lines.append('ports = ["443=127.0.0.1:443"]')
    else:
        config_lines = [
            "[client]",
            f'remote_addr = "{iran_ip}:{port}"',
        ]
        if transport in ["wsmux", "wssmux"]:
            config_lines.append('edge_ip = ""')
        config_lines.extend([
            f'transport = "{transport}"',
            f'token = "{token}"',
            f'connection_pool = {_val("connection_pool")}',
            f'aggressive_pool = {_val("aggressive_pool")}',
            f'keepalive_period = {_val("keepalive_period")}',
            f'nodelay = {_val("nodelay")}',
            f'retry_interval = {_val("retry_interval")}',
            f'dial_timeout = {_val("dial_timeout")}',
        ])
        if transport != "tcp":
            config_lines.extend([
                f'mux_version = {_val("mux_version")}',
                f'mux_framesize = {_val("mux_framesize")}',
                f'mux_recievebuffer = {_val("mux_recievebuffer")}',
                f'mux_streambuffer = {_val("mux_streambuffer")}',
            ])
        config_lines.extend([f'sniffer = {_val("sniffer")}', f'web_port = {_val("web_port")}', f'log_level = "{_val("log_level")}"'])
        if transport in ("tcp", "tcpmux"):
            config_lines.extend([f'mss = {_val("mss")}', f'so_rcvbuf = {_val("so_rcvbuf")}', f'so_sndbuf = {_val("so_sndbuf")}'])

    # Persist the chosen preset as a TOML comment so the dashboard can show it
    # and offer one-click switching later. Backhaul ignores '#' comment lines.
    config_content = f"# bhm_preset = {preset_name}\n" + "\n".join(config_lines) + "\n"

    descriptions = {"tcp": "Backhaul TCP Tunnel", "tcpmux": "Backhaul TCPMUX Tunnel", "wsmux": "Backhaul WSMUX Tunnel", "wssmux": "Backhaul WSSMUX Tunnel (TLS)"}
    service_content = f"""[Unit]
Description={descriptions.get(transport, "Backhaul Tunnel")} - {role.capitalize()} port {port}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory={INSTALL_DIR}
ExecStart={BINARY} -c {config_file}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"""

    if is_local:
        # --- LOCAL: keep direct file operations ---
        os.makedirs(INSTALL_DIR, exist_ok=True)
        os.makedirs(BACKUP_DIR, exist_ok=True)

        # Binary check + install
        binary_check, _ = run_cmd(f"test -x {BINARY} && echo ok")
        if binary_check.strip() != "ok":
            arch_out, _ = run_cmd("uname -m")
            arch = arch_out.strip()
            asset = "backhaul_linux_arm64.tar.gz" if ("aarch64" in arch or "arm64" in arch) else "backhaul_linux_amd64.tar.gz"
            urls = [
                f"https://github.com/Musixal/Backhaul/releases/latest/download/{asset}",
                f"https://mirror.ghproxy.com/https://github.com/Musixal/Backhaul/releases/latest/download/{asset}",
                f"https://ghproxy.net/https://github.com/Musixal/Backhaul/releases/latest/download/{asset}"
            ]
            c1 = 1
            out1 = "No download attempt made"
            for idx, url in enumerate(urls):
                out1, c1 = run_cmd(f"wget -q -O /tmp/{asset} '{url}' 2>/dev/null || curl -sL -o /tmp/{asset} '{url}' 2>/dev/null", timeout=120)
                if c1 == 0:
                    break
            if c1 != 0:
                return {"success": False, "error": f"Failed to download Backhaul binary: {out1}"}
            out2, c2 = run_cmd(f"tar -xzf /tmp/{asset} -C /tmp/ 2>/dev/null", timeout=60)
            if c2 != 0:
                return {"success": False, "error": f"Failed to extract Backhaul archive: {out2}"}
            run_cmd(f"cp /tmp/backhaul {BINARY} && chmod +x {BINARY} && rm -rf /tmp/backhaul /tmp/{asset}")

        if transport == "wssmux":
            os.makedirs(CERT_DIR, exist_ok=True)
            cert_check, _ = run_cmd(f"test -f {CERT_DIR}/wssmux.crt && echo ok")
            if cert_check.strip() != "ok":
                run_cmd(f'openssl req -x509 -newkey rsa:2048 -keyout {CERT_DIR}/wssmux.key -out {CERT_DIR}/wssmux.crt -days 3650 -nodes -subj "/CN=backhaul-wssmux" 2>/dev/null')

        # Backup existing config
        if os.path.exists(config_file):
            run_cmd(f"cp {config_file} {BACKUP_DIR}/$(basename {config_file}).bak.$(date +%Y%m%d-%H%M%S)")

        with open(config_file, 'w') as f:
            f.write(config_content)
        with open(service_file, 'w') as f:
            f.write(service_content)

        run_cmd("systemctl daemon-reload")
        run_cmd(f"systemctl enable {svc_name} 2>/dev/null")
        run_cmd(f"systemctl restart {svc_name}")

        time.sleep(1)
        status_out, _ = run_cmd(f"systemctl is-active {svc_name} 2>/dev/null")

    else:
        # --- REMOTE: batch everything into minimal SSH calls ---
        host = srv["ip"]
        user = srv.get("ssh_user", "root")
        key = srv.get("ssh_key", "")
        password = srv.get("ssh_password", "")
        ssh_port = srv.get("ssh_port", 22)

        # Step 1: Binary check + install (single SSH call with fallback URLs built in)
        binary_check, _ = remote_exec(srv, f"test -x {BINARY} && echo ok")
        if binary_check.strip() != "ok":
            # Single SSH call: detect arch, try multiple URLs, extract, install
            install_script = f"""bash -c '
ARCH=$(uname -m)
if echo "$ARCH" | grep -qE "aarch64|arm64"; then ASSET="backhaul_linux_arm64.tar.gz"; else ASSET="backhaul_linux_amd64.tar.gz"; fi
URLS="https://github.com/Musixal/Backhaul/releases/latest/download/$ASSET https://mirror.ghproxy.com/https://github.com/Musixal/Backhaul/releases/latest/download/$ASSET https://ghproxy.net/https://github.com/Musixal/Backhaul/releases/latest/download/$ASSET"
DL_OK=0
for URL in $URLS; do
  wget -q -O /tmp/$ASSET "$URL" 2>/dev/null || curl -sL -o /tmp/$ASSET "$URL" 2>/dev/null
  if [ $? -eq 0 ] && [ -s /tmp/$ASSET ]; then DL_OK=1; break; fi
done
if [ "$DL_OK" -ne 1 ]; then echo "DOWNLOAD_FAILED"; exit 1; fi
tar -xzf /tmp/$ASSET -C /tmp/ 2>/dev/null
if [ $? -ne 0 ]; then echo "EXTRACT_FAILED"; exit 1; fi
cp /tmp/backhaul {BINARY} && chmod +x {BINARY}
rm -rf /tmp/backhaul /tmp/$ASSET
echo "INSTALL_OK"
'"""
            install_out, install_rc = run_ssh(host, user, key, sudo_cmd(user, install_script), password=password, port=ssh_port, timeout=120)
            if install_rc != 0 or "INSTALL_OK" not in install_out:
                err_msg = "Failed to download binary" if "DOWNLOAD_FAILED" in install_out else "Failed to extract binary" if "EXTRACT_FAILED" in install_out else f"Binary installation failed: {install_out}"
                return {"success": False, "error": err_msg}

        # Step 2: Deploy config + service + start (single SSH call)
        delim_cfg = f"DELIM_CFG_{secrets.token_hex(8)}"
        delim_svc = f"DELIM_SVC_{secrets.token_hex(8)}"

        cert_cmds = ""
        if transport == "wssmux":
            cert_cmds = f"""
mkdir -p {CERT_DIR}
if [ ! -f {CERT_DIR}/wssmux.crt ]; then
  openssl req -x509 -newkey rsa:2048 -keyout {CERT_DIR}/wssmux.key -out {CERT_DIR}/wssmux.crt -days 3650 -nodes -subj "/CN=backhaul-wssmux" 2>/dev/null
fi"""

        deploy_script = f"""bash -c '
mkdir -p {INSTALL_DIR} {BACKUP_DIR}
{cert_cmds}
if [ -f {config_file} ]; then
  cp {config_file} {BACKUP_DIR}/$(basename {config_file}).bak.$(date +%Y%m%d-%H%M%S) 2>/dev/null
fi
cat > {config_file} << '"'"'{delim_cfg}'"'"'
{config_content}{delim_cfg}
cat > {service_file} << '"'"'{delim_svc}'"'"'
{service_content}{delim_svc}
systemctl daemon-reload
systemctl enable {svc_name} 2>/dev/null
systemctl restart {svc_name}
sleep 1
systemctl is-active {svc_name} 2>/dev/null
'"""
        deploy_out, _ = run_ssh(host, user, key, sudo_cmd(user, deploy_script), password=password, port=ssh_port, timeout=60)
        status_out = deploy_out.strip().split('\n')[-1] if deploy_out else ""

    return {
        "success": status_out.strip() == "active",
        "service": svc_name,
        "token": token,
        "port": port,
        "transport": transport,
        "role": role,
        "server": srv.get("name", "")
    }


class ReuseAddrHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    allow_reuse_port = True
    block_on_close = False

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        self.socket.settimeout(60)
        super().server_bind()


class PanelHandler(http.server.BaseHTTPRequestHandler):
    timeout = 30

    def log_message(self, format, *args):
        pass

    def handle_one_request(self):
        """Override to catch connection-level errors (broken pipe, reset, etc.)
        before they reach do_GET / do_POST, preventing thread death."""
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception:
            pass

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_html(self, html, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        # All assets are inline; lock the page down so injected/3rd-party
        # script or framing can't run.
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                         "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(html.encode())

    def check_auth(self):
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        sid = cookie.get("session")
        if sid and sid.value in sessions:
            if time.time() - sessions[sid.value].get("time", 0) > SESSION_TTL:
                # Session expired - drop it and force re-login.
                del sessions[sid.value]
                return False
            return True
        return False

    def _safe_respond(self, route_func):
        """Catch and log any exception during request handling so a single
        broken handler never kills the whole server thread pool."""
        try:
            route_func()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass  # client disconnected — nothing to send back
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            err = f"Internal server error in {self.command} {self.path}: {e}"
            print(f"  [PANEL ERROR] {err}")
            for line in tb.rstrip().split("\n"):
                print(f"        {line}")
            try:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Internal server error"}).encode())
            except Exception:
                pass

    def do_GET(self):
        self._safe_respond(self._route_request)

    def _route_request(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            if not self.check_auth():
                self.send_html(get_login_page())
                return
            self.send_html(get_main_page())
            return

        if path == "/login.html":
            self.send_html(get_login_page())
            return

        if path == "/api/auth/status":
            self.send_json({"authenticated": self.check_auth()})
            return

        if not self.check_auth():
            self.send_json({"error": "unauthorized"}, 401)
            return

        # NOTE: the old /api/debug_ssh endpoint (arbitrary remote command
        # execution) was removed - it was a remote-code-execution risk even
        # for an authenticated session.

        if path == "/api/presets":
            out = {}
            for k, p in PRESETS.items():
                out[k] = {kk: p[kk] for kk in
                          ("label", "label_fa", "desc", "best_transport",
                           "rank_speed", "rank_stability", "rank_latency",
                           "iran", "kharej")}
            self.send_json({"presets": out, "help": PARAM_HELP})
            return

        if path == "/api/tunnel/preset-status":
            qs = urllib.parse.parse_qs(parsed.query)
            job = qs.get("job", [""])[0]
            with _PRESET_JOBS_LOCK:
                st = _PRESET_JOBS.get(job)
            if st is None:
                self.send_json({"error": "unknown job"}, 404)
                return
            self.send_json(st)
            return

        if path == "/api/settings/get":
            settings = load_settings()
            self.send_json({"username": settings.get("admin_user", ADMIN_USER)})
            return

        if path == "/api/servers":
            data = load_servers()
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                result = list(executor.map(get_server_info, data.get("servers", [])))
            self.send_json({"servers": result})
            return

        if path == "/api/servers/raw":
            self.send_json(load_servers())
            return

        if path == "/api/tunnels":
            data = load_servers()
            all_tunnels = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                for tunnels in executor.map(get_tunnels_from_server, data.get("servers", [])):
                    all_tunnels.extend(tunnels)
            self.send_json({"tunnels": all_tunnels})
            return

        if path == "/api/tunnel/logs":
            params = urllib.parse.parse_qs(parsed.query)
            svc = params.get("svc", [""])[0]
            server_id = params.get("server_id", [""])[0]
            lines = params.get("lines", ["100"])[0]
            if not is_safe_svc(svc):
                self.send_json({"error": "invalid service name"}, 400)
                return
            try:
                lines_val = int(lines)
                if lines_val < 1 or lines_val > 1000:
                    lines_val = 100
            except:
                lines_val = 100
            if svc:
                data = load_servers()
                srv = next((s for s in data.get("servers", []) if s.get("id") == server_id), None)
                if srv:
                    out, _ = remote_exec(srv, f"journalctl -u {svc} -n {lines_val} --no-pager 2>/dev/null")
                    self.send_json({"logs": out})
                else:
                    self.send_json({"error": "server not found"}, 404)
            else:
                self.send_json({"error": "missing svc"}, 400)
            return

        if path == "/api/tunnel/config":
            params = urllib.parse.parse_qs(parsed.query)
            svc = params.get("svc", [""])[0]
            server_id = params.get("server_id", [""])[0]
            if not is_safe_svc(svc):
                self.send_json({"error": "invalid service name"}, 400)
                return
            if svc:
                data = load_servers()
                srv = next((s for s in data.get("servers", []) if s.get("id") == server_id), None)
                if srv:
                    config_name = svc.replace("backhaul-", "").replace(".service", "")
                    config_path = f"{INSTALL_DIR}/{config_name}.toml"
                    out, _ = remote_exec(srv, f"cat {config_path} 2>/dev/null")
                    self.send_json({"config": out})
                else:
                    self.send_json({"error": "server not found"}, 404)
            else:
                self.send_json({"error": "missing svc"}, 400)
            return

        if path == "/api/token/generate":
            out, _ = run_cmd("cat /proc/sys/kernel/random/uuid 2>/dev/null || head -c 32 /dev/urandom | base64")
            self.send_json({"token": out[:36] if out else secrets.token_hex(16)})
            return

        self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        self._safe_respond(self._route_post)

    def _route_post(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        try:
            data = json.loads(body) if body else {}
        except:
            data = {}

        if path == "/api/auth/login":
            ip = self.client_address[0] if self.client_address else "?"
            locked = login_locked(ip)
            if locked:
                self.send_json({"success": False,
                                "error": f"Too many attempts. Try again in {locked}s."}, 429)
                return
            username = data.get("username", "")
            password = data.get("password", "")
            if check_credentials(username, password):
                record_login_ok(ip)
                sid = new_session(username)
                secure = "; Secure" if SSL_ON else ""
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"session={sid}; Path=/; HttpOnly; SameSite=Strict{secure}")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": True,
                    "must_change_password": is_default_credentials(),
                }).encode())
            else:
                record_login_fail(ip)
                self.send_json({"success": False, "error": "Invalid credentials"}, 401)
            return

        if path == "/api/auth/logout":
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie", ""))
            sid = cookie.get("session")
            if sid and sid.value in sessions:
                del sessions[sid.value]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "session=; Path=/; Max-Age=0")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode())
            return

        if not self.check_auth():
            self.send_json({"error": "unauthorized"}, 401)
            return

        if path == "/api/settings/update":
            new_user = data.get("username", "")
            new_pass = data.get("password", "")
            if new_user and new_pass:
                settings = load_settings()
                salt, digest = hash_password(new_pass)
                settings["admin_user"] = new_user
                settings["admin_salt"] = salt
                settings["admin_pass_hash"] = digest
                # Drop any legacy plaintext password.
                settings.pop("admin_pass", None)
                save_settings(settings)
                # Invalidate existing sessions so the new credentials take effect.
                sessions.clear()
                self.send_json({"success": True})
            else:
                self.send_json({"success": False, "error": "Username and password required"}, 400)
            return

        if path == "/api/server/add":
            servers_data = load_servers()
            new_id = secrets.token_hex(8)
            server_entry = {
                "id": new_id,
                "name": data.get("name", "Server"),
                "ip": data.get("ip", ""),
                "role": data.get("role", "iran"),
                "ssh_user": data.get("ssh_user", "root"),
                "ssh_password": data.get("ssh_password", ""),
                "ssh_port": data.get("ssh_port", 22),
                "ssh_key": data.get("ssh_key", "")
            }
            servers_data["servers"].append(server_entry)
            save_servers(servers_data)
            self.send_json({"success": True, "id": new_id})
            return

        if path == "/api/server/update":
            server_id = data.get("id", "")
            servers_data = load_servers()
            for srv in servers_data.get("servers", []):
                if srv.get("id") == server_id:
                    srv["name"] = data.get("name", srv.get("name"))
                    srv["ip"] = data.get("ip", srv.get("ip"))
                    srv["role"] = data.get("role", srv.get("role"))
                    srv["ssh_user"] = data.get("ssh_user", srv.get("ssh_user"))
                    srv["ssh_password"] = data.get("ssh_password", srv.get("ssh_password", ""))
                    srv["ssh_port"] = data.get("ssh_port", srv.get("ssh_port", 22))
                    srv["ssh_key"] = data.get("ssh_key", srv.get("ssh_key"))
                    break
            save_servers(servers_data)
            self.send_json({"success": True})
            return

        if path == "/api/server/delete":
            server_id = data.get("id", "")
            servers_data = load_servers()
            servers_data["servers"] = [s for s in servers_data.get("servers", []) if s.get("id") != server_id]
            save_servers(servers_data)
            self.send_json({"success": True})
            return

        if path == "/api/server/test":
            host = data.get("ip", "")
            user = data.get("ssh_user", "root")
            key = data.get("ssh_key", "")
            password = data.get("ssh_password", "")
            port = data.get("ssh_port", 22)
            is_local = host in ["127.0.0.1", "localhost", ""]
            if is_local:
                out, code = run_cmd("hostname && echo 'SSH_OK'", timeout=5)
                self.send_json({"success": code == 0, "output": out})
            else:
                out, code = run_ssh(host, user, key, sudo_cmd(user, "hostname && echo SSH_OK"), timeout=5, password=password, port=port)
                self.send_json({"success": "SSH_OK" in out, "output": out})
            return

        if path == "/api/tunnel/ping":
            server_id = data.get("server_id", "")
            target_ip = data.get("target_ip", "")
            if not server_id or not target_ip:
                self.send_json({"error": "missing params"}, 400)
                return
            if not is_safe_ip_domain(target_ip):
                self.send_json({"error": "invalid target IP or domain name"}, 400)
                return
            data_servers = load_servers()
            srv = next((s for s in data_servers.get("servers", []) if s.get("id") == server_id), None)
            if srv:
                out, code = remote_exec(srv, f"ping -c 4 -W 2 {target_ip}", timeout=15)
                # Parse ping output
                loss = "Unknown"
                avg = "Unknown"
                for line in out.split('\\n'):
                    if "packet loss" in line:
                        parts = line.split(',')
                        for p in parts:
                            if "packet loss" in p:
                                loss = p.strip().split(' ')[0]
                    elif line.startswith("rtt min/avg/max/mdev") or line.startswith("round-trip min/avg/max/stddev"):
                        try:
                            avg = line.split('=')[1].split('/')[1] + " ms"
                        except:
                            pass
                self.send_json({"success": True, "output": out, "loss": loss, "avg": avg})
            else:
                self.send_json({"error": "server not found"}, 404)
        if path == "/api/tunnel/diagnostics":
            iran_id = data.get("iran_id", "")
            kharej_id = data.get("kharej_id", "")
            test_port = data.get("test_port", 9999)
            try:
                test_port = int(test_port)
                if not (1 <= test_port <= 65535):
                    test_port = 9999
            except:
                test_port = 9999
            data_servers = load_servers()
            servers = data_servers.get("servers", [])
            iran_srv = next((s for s in servers if s.get("id") == iran_id), None)
            kharej_srv = next((s for s in servers if s.get("id") == kharej_id), None)
            if not iran_srv or not kharej_srv:
                self.send_json({"error": "server not found"}, 404)
                return
            kharej_ip = kharej_srv.get("ip")
            if kharej_ip in ["localhost", "127.0.0.1", ""]:
                kharej_ip = "127.0.0.1"
            if not is_safe_ip_domain(kharej_ip):
                self.send_json({"error": "invalid target IP or domain name"}, 400)
                return
            
            # Start diagnostics server inside an empty isolated temporary directory to prevent directory listing exposure
            start_cmd = (
                f"bash -c \"TEST_DIR=\\$(mktemp -d) && cd \\$TEST_DIR && "
                f"nohup python3 -m http.server {test_port} > /dev/null 2>&1 & echo \\$! > /tmp/test_pid\""
            )
            remote_exec(kharej_srv, start_cmd, timeout=5)
            time.sleep(1)
            curl_out, curl_code = remote_exec(iran_srv, f"curl -m 5 -s http://{kharej_ip}:{test_port} | head -n 1", timeout=10)
            tcp_open = "Directory listing" in curl_out or curl_code == 0
            
            # Kill the background process securely by PID, port, and process pattern
            kill_cmd = (
                f"bash -c \"[ -f /tmp/test_pid ] && kill -9 \\$(cat /tmp/test_pid) 2>/dev/null; "
                f"fuser -k -n tcp {test_port} 2>/dev/null; "
                f"pkill -9 -f 'python3 -m http.server {test_port}' 2>/dev/null; "
                f"rm -f /tmp/test_pid\""
            )
            remote_exec(kharej_srv, kill_cmd, timeout=5)
            ping_out, ping_code = remote_exec(iran_srv, f"ping -c 5 -W 2 {kharej_ip}", timeout=15)
            loss = "100%"
            avg = "N/A"
            for line in ping_out.split('\\n'):
                if "packet loss" in line:
                    parts = line.split(',')
                    for p in parts:
                        if "packet loss" in p:
                            loss = p.strip().split(' ')[0]
                elif line.startswith("rtt min/avg/max/mdev") or line.startswith("round-trip min/avg/max/stddev"):
                    try:
                        avg = line.split('=')[1].split('/')[1] + " ms"
                    except:
                        pass
            try:
                loss_val = float(loss.replace('%', ''))
            except:
                loss_val = 100
            score = 100
            if loss_val > 0:
                score -= loss_val
            if not tcp_open:
                score -= 50
            verdict = "Excellent for Tunneling"
            if score < 50:
                verdict = "Blocked or High Loss - Not Recommended"
            elif score < 80:
                verdict = "Acceptable, but has packet loss"
            if not tcp_open:
                verdict = "TCP Blocked - Tunnel may fail!"
            self.send_json({
                "success": True, 
                "tcp_open": tcp_open, 
                "ping_loss": loss, 
                "ping_avg": avg, 
                "score": max(0, score), 
                "verdict": verdict,
                "ping_raw": ping_out
            })
            return

        if path == "/api/tunnel/action":
            svc = data.get("service", "")
            action = data.get("action", "")
            server_id = data.get("server_id", "")
            if not is_safe_svc(svc):
                self.send_json({"error": "invalid service name"}, 400)
                return
            if svc and action in ["start", "stop", "restart", "force-restart"]:
                data_servers = load_servers()
                srv = next((s for s in data_servers.get("servers", []) if s.get("id") == server_id), None)
                if srv:
                    if action == "force-restart":
                        remote_exec(srv, f"systemctl stop {svc} 2>/dev/null")
                        time.sleep(2)
                        out, code = remote_exec(srv, f"systemctl start {svc} 2>/dev/null")
                    else:
                        out, code = remote_exec(srv, f"systemctl {action} {svc}")
                    invalidate_cache(server_id)
                    self.send_json({"success": code == 0, "output": out})
                else:
                    self.send_json({"error": "server not found"}, 404)
            else:
                self.send_json({"error": "invalid params"}, 400)
            return

        if path == "/api/tunnel/delete":
            svc = data.get("service", "")
            server_id = data.get("server_id", "")
            if not is_safe_svc(svc):
                self.send_json({"error": "invalid service name"}, 400)
                return
            if svc:
                data_servers = load_servers()
                srv = next((s for s in data_servers.get("servers", []) if s.get("id") == server_id), None)
                if srv:
                    remote_exec(srv, f"systemctl stop {svc} 2>/dev/null")
                    remote_exec(srv, f"systemctl disable {svc} 2>/dev/null")
                    config_name = svc.replace("backhaul-", "").replace(".service", "")
                    remote_exec(srv, f"cp {INSTALL_DIR}/{config_name}.toml {BACKUP_DIR}/ 2>/dev/null")
                    remote_exec(srv, f"rm -f {INSTALL_DIR}/{config_name}.toml {SERVICE_DIR}/{svc}")
                    remote_exec(srv, f"bash -c \"crontab -l 2>/dev/null | grep -v '{CRON_MARKER} {svc}$' | crontab -\"")
                    remote_exec(srv, "systemctl daemon-reload")
                    invalidate_cache(server_id)
                    self.send_json({"success": True})
                else:
                    self.send_json({"error": "server not found"}, 404)
            else:
                self.send_json({"error": "missing service"}, 400)
            return

        if path == "/api/tunnel/create":
            data_servers = load_servers()
            servers_list = data_servers.get("servers", [])
            srv_id = data.get("server", {}).get("id")
            srv = next((s for s in servers_list if s.get("id") == srv_id), None)
            if not srv:
                self.send_json({"error": "server not found"}, 404)
                return
            result = create_tunnel_on_server(srv, data)
            invalidate_cache(srv_id)
            self.send_json(result)
            return

        if path == "/api/tunnel/create-both":
            data_servers = load_servers()
            servers_list = data_servers.get("servers", [])
            
            iran_srv_id = data.get("iran_server", {}).get("id")
            kharej_srv_id = data.get("kharej_server", {}).get("id")
            
            iran_srv = next((s for s in servers_list if s.get("id") == iran_srv_id), None)
            kharej_srv = next((s for s in servers_list if s.get("id") == kharej_srv_id), None)
            
            if not iran_srv or not kharej_srv:
                self.send_json({"error": "server not found"}, 404)
                return

            transport = data.get("transport", "wssmux")
            port = data.get("port", "9743")
            token = data.get("token", "")
            ports_mapping = data.get("ports", "")
            preset = data.get("preset", "balanced")
            custom = data.get("custom", {})
            if not isinstance(custom, dict):
                custom = {}

            # Validate transport/port up front so we can safely build paths and
            # reject duplicates before touching either server.
            if transport not in ["tcp", "tcpmux", "wsmux", "wssmux"]:
                self.send_json({"error": f"Invalid transport: {transport}"}, 400)
                return
            try:
                port_int = int(port)
                if not (1 <= port_int <= 65535):
                    raise ValueError
                port = str(port_int)
            except (TypeError, ValueError):
                self.send_json({"error": f"Invalid port: {port}"}, 400)
                return

            # Reject a port already used by an existing tunnel on EITHER side, so
            # creating a new tunnel can never silently overwrite/break another one.
            for chk_srv, chk_role in ((iran_srv, "iran"), (kharej_srv, "kharej")):
                cfg_path = f"{INSTALL_DIR}/{chk_role}-{transport}-{port}.toml"
                ex_out, _ = remote_exec(chk_srv, f"test -f {cfg_path} && echo BHM_EXISTS || true")
                if "BHM_EXISTS" in (ex_out or ""):
                    self.send_json({
                        "error": f"Port {port} ({transport.upper()}) is already in use on the "
                                 f"{chk_role} server \"{chk_srv.get('name', chk_role)}\". "
                                 f"Pick a different (unique) tunnel port."
                    }, 409)
                    return

            if not token:
                tok_out, _ = run_cmd("cat /proc/sys/kernel/random/uuid 2>/dev/null")
                token = tok_out[:36] if tok_out else secrets.token_hex(16)

            kharej_ip = kharej_srv.get("ip", "")
            iran_ip = iran_srv.get("ip", "")

            if iran_ip in ["127.0.0.1", "localhost", ""]:
                iran_ip = get_local_ip()

            iran_result = create_tunnel_on_server(iran_srv, {
                "role": "iran", "transport": transport, "port": port,
                "token": token, "ports": ports_mapping,
                "preset": preset, "custom": custom
            })

            kharej_result = create_tunnel_on_server(kharej_srv, {
                "role": "kharej", "transport": transport, "port": port,
                "token": token, "iran_ip": iran_ip,
                "preset": preset, "custom": custom
            })

            invalidate_cache()
            self.send_json({
                "success": iran_result.get("success") and kharej_result.get("success"),
                "iran": iran_result,
                "kharej": kharej_result,
                "token": token
            })
            return

        if path == "/api/tunnel/cron":
            svc = data.get("service", "")
            interval = data.get("interval", 0)
            action = data.get("action", "set")
            server_id = data.get("server_id", "")
            if not is_safe_svc(svc):
                self.send_json({"error": "invalid service name"}, 400)
                return
            try:
                interval = int(interval)
                if interval < 0 or interval > 1440:
                    interval = 0
            except:
                interval = 0
            data_servers = load_servers()
            srv = next((s for s in data_servers.get("servers", []) if s.get("id") == server_id), None)
            if not srv:
                self.send_json({"error": "server not found"}, 404)
                return
            if action == "remove":
                remote_exec(srv, f"bash -c \"crontab -l 2>/dev/null | grep -v '{CRON_MARKER} {svc}$' | crontab -\"")
                remote_exec(srv, f"rm -f {CRON_CONFIG_DIR}/{svc}.conf")
                invalidate_cache(server_id)
            elif interval > 0:
                expr = build_cron_expr(interval)
                if not expr:
                    self.send_json({"error": "invalid interval"}, 400)
                    return
                # Install the cron job FIRST, and only write the .conf marker if
                # the crontab actually loaded. An invalid line used to leave a
                # phantom "scheduled" badge in the dashboard while no job ran.
                tmpf = f"/tmp/bhm_cron_{svc}.tmp"
                cron_cmd = (
                    f"bash -c \"crontab -l 2>/dev/null | grep -v '{CRON_MARKER} {svc}$' > {tmpf}; "
                    f"echo '{expr} systemctl restart {svc} {CRON_MARKER} {svc}' >> {tmpf}; "
                    f"if crontab {tmpf}; then mkdir -p {CRON_CONFIG_DIR} && "
                    f"printf 'SERVICE={svc}\\nINTERVAL={interval}\\nSCHEDULE={expr}\\n' > {CRON_CONFIG_DIR}/{svc}.conf; "
                    f"echo CRON_OK; else echo CRON_FAIL; fi; rm -f {tmpf}\""
                )
                out, _ = remote_exec(srv, cron_cmd)
                invalidate_cache(server_id)
                if "CRON_OK" not in (out or ""):
                    self.send_json({"error": "failed to install cron job", "output": out}, 500)
                    return
            invalidate_cache(server_id)
            self.send_json({"success": True})
            return

        if path == "/api/tunnel/set-preset":
            # Kick off the rebuild in the background and return immediately so the
            # browser gets a fast reply even though both ends are about to restart.
            preset = data.get("preset", "balanced")
            ends = data.get("ends", [])
            if preset not in PRESETS:
                self.send_json({"error": f"Invalid preset: {preset}"}, 400)
                return
            if not isinstance(ends, list) or not ends:
                self.send_json({"error": "no tunnel ends provided"}, 400)
                return
            servers_data = load_servers()
            job_id = secrets.token_hex(8)
            with _PRESET_JOBS_LOCK:
                for k in [k for k, v in _PRESET_JOBS.items() if time.time() - v.get("time", 0) > 600]:
                    _PRESET_JOBS.pop(k, None)
                _PRESET_JOBS[job_id] = {"done": False, "time": time.time()}
            threading.Thread(target=_run_preset_job,
                             args=(job_id, preset, ends, servers_data), daemon=True).start()
            self.send_json({"success": True, "job": job_id})
            return

        if path == "/api/tunnel/save_config":
            svc = data.get("service", "")
            config = data.get("config", "")
            server_id = data.get("server_id", "")
            if not is_safe_svc(svc):
                self.send_json({"error": "invalid service name"}, 400)
                return
            if svc and config:
                data_servers = load_servers()
                srv = next((s for s in data_servers.get("servers", []) if s.get("id") == server_id), None)
                if srv:
                    config_name = svc.replace("backhaul-", "").replace(".service", "")
                    config_path = f"{INSTALL_DIR}/{config_name}.toml"
                    remote_exec(srv, f"cp {config_path} {BACKUP_DIR}/$(basename {config_path}).bak.$(date +%Y%m%d-%H%M%S) 2>/dev/null")
                    host = srv.get("ip", "127.0.0.1")
                    is_local = host in ["127.0.0.1", "localhost", get_local_ip()]
                    if is_local:
                        with open(config_path, 'w') as f:
                            f.write(config)
                    else:
                        delim = f"DELIM_{secrets.token_hex(8)}"
                        ssh_user = srv.get("ssh_user", "root")
                        cmd_write = f"cat << '{delim}' | {sudo_cmd(ssh_user, f'tee {config_path} >/dev/null')}\n{config}{delim}"
                        run_ssh(host, ssh_user, srv.get("ssh_key", ""), cmd_write, password=srv.get("ssh_password", ""), port=srv.get("ssh_port", 22))
                    remote_exec(srv, f"systemctl restart {svc}")
                    invalidate_cache(server_id)
                    self.send_json({"success": True})
                else:
                    self.send_json({"error": "server not found"}, 404)
            else:
                self.send_json({"error": "missing params"}, 400)
            return

        if path == "/api/install/binary":
            server_id = data.get("server_id", "")
            data_servers = load_servers()
            srv = next((s for s in data_servers.get("servers", []) if s.get("id") == server_id), None)
            if not srv:
                self.send_json({"error": "server not found"}, 404)
                return
            arch_out, _ = remote_exec(srv, "uname -m")
            arch = arch_out.strip()
            if "aarch64" in arch or "arm64" in arch:
                asset = "backhaul_linux_arm64.tar.gz"
            else:
                asset = "backhaul_linux_amd64.tar.gz"
            urls = [
                f"https://github.com/Musixal/Backhaul/releases/latest/download/{asset}",
                f"https://mirror.ghproxy.com/https://github.com/Musixal/Backhaul/releases/latest/download/{asset}",
                f"https://ghproxy.net/https://github.com/Musixal/Backhaul/releases/latest/download/{asset}"
            ]
            remote_exec(srv, f"mkdir -p {INSTALL_DIR} {BACKUP_DIR}")
            remote_exec(srv, f"cp {BINARY} {BACKUP_DIR}/backhaul.bak.$(date +%Y%m%d-%H%M%S) 2>/dev/null")
            c1 = 1
            out1 = "No download attempt made"
            used_mirror = False
            for idx, url in enumerate(urls):
                if idx > 0:
                    used_mirror = True
                    print(f"[{srv.get('ip') or srv.get('name')}] Direct download failed. Trying mirror proxy: {url}")
                out1, c1 = remote_exec(srv, f"wget -q -O /tmp/{asset} '{url}' 2>/dev/null || curl -sL -o /tmp/{asset} '{url}' 2>/dev/null", timeout=120)
                if c1 == 0:
                    break
            if c1 != 0:
                self.send_json({"success": False, "error": f"Download failed: {out1}"})
                return
            out2, c2 = remote_exec(srv, f"tar -xzf /tmp/{asset} -C /tmp/ 2>/dev/null", timeout=60)
            if c2 != 0:
                self.send_json({"success": False, "error": f"Extraction failed: {out2}"})
                return
            remote_exec(srv, f"cp /tmp/backhaul {BINARY}")
            remote_exec(srv, f"chmod +x {BINARY}")
            remote_exec(srv, f"rm -rf /tmp/backhaul /tmp/{asset}")
            ver = get_binary_version(srv.get("ip"), srv.get("ssh_user"), srv.get("ssh_key"), password=srv.get("ssh_password", ""), port=srv.get("ssh_port", 22))
            invalidate_cache(server_id)
            self.send_json({"success": True, "version": ver, "used_mirror": used_mirror})
            return

        self.send_json({"error": "not found"}, 404)


def get_login_page():
    return """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<meta name="color-scheme" content="dark light">
<title>Backhaul Panel — Sign in</title>
<style>
:root{
  --accent:#22d3ee; --accent2:#6366f1; --accent3:#2dd4bf;
  --bg:#070b16; --bg2:#0b1224;
  --text:#e8edf7; --muted:#93a0bd;
  --glass:rgba(20,28,48,.55); --glass-brd:rgba(255,255,255,.10);
  --field:rgba(255,255,255,.05); --field-brd:rgba(255,255,255,.12);
  --danger:#fb7185; --shadow:0 30px 80px -20px rgba(0,0,0,.65);
}
html[data-theme="light"]{
  --bg:#eef2fb; --bg2:#dfe7f6;
  --text:#0f1c33; --muted:#516081;
  --glass:rgba(255,255,255,.65); --glass-brd:rgba(15,28,51,.10);
  --field:rgba(15,28,51,.04); --field-brd:rgba(15,28,51,.14);
  --shadow:0 30px 70px -24px rgba(40,60,120,.40);
}
*{box-sizing:border-box;margin:0;padding:0}
html{scrollbar-gutter:stable}
body{
  font-family:'Segoe UI',system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif;
  min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:20px;
  color:var(--text);background:var(--bg);position:relative;overflow-x:hidden;overflow-y:auto;
}
.aurora{position:fixed;inset:-20%;z-index:0;filter:blur(70px);opacity:.7;pointer-events:none;will-change:auto}
.aurora i{position:absolute;display:block;border-radius:50%;mix-blend-mode:screen}
.aurora .b1{width:40vw;height:40vw;left:-6vw;top:-6vw;background:radial-gradient(circle,#22d3ee,transparent 60%)}
.aurora .b2{width:38vw;height:38vw;right:-8vw;top:6vw;background:radial-gradient(circle,#6366f1,transparent 60%)}
.aurora .b3{width:36vw;height:36vw;left:24vw;bottom:-14vw;background:radial-gradient(circle,#2dd4bf,transparent 60%)}
html[data-theme="light"] .aurora{opacity:.5}
@keyframes float1{50%{transform:translate(6vw,4vh) scale(1.1)}}
@keyframes float2{50%{transform:translate(-5vw,5vh) scale(1.08)}}
@keyframes float3{50%{transform:translate(3vw,-5vh) scale(1.12)}}
.card{
  position:relative;z-index:1;width:100%;max-width:410px;
  background:var(--glass);border:1px solid var(--glass-brd);border-radius:24px;
  backdrop-filter:blur(16px) saturate(150%);-webkit-backdrop-filter:blur(16px) saturate(150%);
  box-shadow:var(--shadow);padding:40px 34px;
  animation:fadein .35s ease both;
}
@keyframes fadein{from{opacity:0}to{opacity:1}}
@media (prefers-reduced-motion: reduce){.card{animation:none}}
.brand{display:flex;flex-direction:column;align-items:center;gap:16px;margin-bottom:26px;text-align:center}
.logo{
  width:64px;height:64px;border-radius:20px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  box-shadow:0 12px 34px -8px var(--accent2);color:#031018;
}
.logo svg{width:34px;height:34px}
.brand h1{font-size:22px;font-weight:800;letter-spacing:-.4px}
.brand p{color:var(--muted);font-size:13px;margin-top:2px}
.field{margin-bottom:16px}
.field label{display:block;font-size:12px;font-weight:600;color:var(--muted);margin:0 0 7px 4px;text-transform:uppercase;letter-spacing:.5px}
.input{position:relative}
.input svg{position:absolute;left:14px;top:50%;transform:translateY(-50%);width:18px;height:18px;color:var(--muted)}
.input input{
  width:100%;padding:14px 14px 14px 44px;border-radius:14px;font-size:15px;
  background:var(--field);border:1px solid var(--field-brd);color:var(--text);
  transition:.18s;outline:none;
}
.input input:focus{border-color:var(--accent);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent) 22%,transparent)}
.toggle-pass{position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--muted);cursor:pointer;padding:8px;border-radius:8px}
.toggle-pass:hover{color:var(--text)}
.btn{
  width:100%;padding:14px;border:none;border-radius:14px;font-size:15px;font-weight:700;cursor:pointer;
  color:#03131a;background:linear-gradient(135deg,var(--accent),var(--accent2));
  box-shadow:0 14px 30px -10px var(--accent2);transition:.18s;margin-top:8px;
  display:flex;align-items:center;justify-content:center;gap:9px;
}
.btn:hover{transform:translateY(-2px);filter:brightness(1.06)}
.btn:active{transform:translateY(0)}
.btn:disabled{opacity:.7;cursor:not-allowed;transform:none}
.spinner{width:18px;height:18px;border:2.5px solid rgba(0,0,0,.25);border-top-color:#03131a;border-radius:50%;animation:spin .7s linear infinite;display:none}
@keyframes spin{to{transform:rotate(360deg)}}
.err{
  background:color-mix(in srgb,var(--danger) 16%,transparent);
  border:1px solid color-mix(in srgb,var(--danger) 40%,transparent);
  color:var(--danger);padding:11px 14px;border-radius:12px;font-size:13px;margin-bottom:16px;
  display:none;align-items:center;gap:8px;animation:shake .4s}
@keyframes shake{25%{transform:translateX(-6px)}75%{transform:translateX(6px)}}
.foot{text-align:center;margin-top:22px;color:var(--muted);font-size:12px}
.theme-btn{position:fixed;top:18px;right:18px;z-index:3;width:42px;height:42px;border-radius:12px;
  background:var(--glass);border:1px solid var(--glass-brd);backdrop-filter:blur(14px);
  color:var(--text);cursor:pointer;display:grid;place-items:center}
.theme-btn:hover{border-color:var(--accent)}
</style>
</head>
<body>
<div class="aurora"><i class="b1"></i><i class="b2"></i><i class="b3"></i></div>
<button class="theme-btn" id="themeBtn" title="Toggle theme" aria-label="Toggle theme"></button>

<form class="card" id="loginForm" autocomplete="on">
  <div class="brand">
    <div class="logo">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M4 7h16M4 7l3-3m-3 3 3 3M20 17H4m16 0-3-3m3 3-3 3"/>
      </svg>
    </div>
    <div>
      <h1>Backhaul Panel</h1>
      <p>Multi-server tunnel manager</p>
    </div>
  </div>

  <div class="err" id="err"></div>

  <div class="field">
    <label for="u">Username</label>
    <div class="input">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
      <input id="u" name="username" type="text" placeholder="admin" autocomplete="username" required autofocus>
    </div>
  </div>

  <div class="field">
    <label for="p">Password</label>
    <div class="input">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      <input id="p" name="password" type="password" placeholder="••••••••" autocomplete="current-password" required>
      <button type="button" class="toggle-pass" id="togglePass" aria-label="Show password">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
      </button>
    </div>
  </div>

  <button class="btn" type="submit" id="submitBtn">
    <span class="spinner" id="spin"></span>
    <span id="btnText">Sign in</span>
  </button>

  <p class="foot">Secured session · Backhaul Manager</p>
</form>

<script>
const SUN='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
const MOON='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>';
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);localStorage.setItem('bh_theme',t);document.getElementById('themeBtn').innerHTML=t==='dark'?SUN:MOON;}
let theme=localStorage.getItem('bh_theme')||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');
applyTheme(theme);
document.getElementById('themeBtn').onclick=()=>applyTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark');

const tp=document.getElementById('togglePass'),pi=document.getElementById('p');
tp.onclick=()=>{pi.type=pi.type==='password'?'text':'password';};

const form=document.getElementById('loginForm'),err=document.getElementById('err'),
      spin=document.getElementById('spin'),btn=document.getElementById('submitBtn'),btnText=document.getElementById('btnText');
form.addEventListener('submit',async(e)=>{
  e.preventDefault();err.style.display='none';
  btn.disabled=true;spin.style.display='inline-block';btnText.textContent='Signing in…';
  try{
    const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:document.getElementById('u').value,password:pi.value})});
    const d=await r.json();
    if(d.success){btnText.textContent='Welcome!';if(d.must_change_password){try{sessionStorage.setItem('bh_must_change','1');}catch(e){}}location.href='/';}
    else{throw new Error(d.error||'Invalid credentials');}
  }catch(ex){
    err.textContent='⚠ '+ex.message;err.style.display='flex';
    btn.disabled=false;spin.style.display='none';btnText.textContent='Sign in';
    pi.value='';pi.focus();
  }
});
</script>
</body>
</html>
"""

def get_main_page():
    return """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark light">
<title>Backhaul Panel</title>
<style>
:root{
  --acc:#22d3ee; --acc-h:#06b6d4; --acc2:#6366f1; --acc3:#2dd4bf;
  /* Aliases: several dashboard rules (cron-on button, rank bars, tooltip "i"
     badge, preset text) referenced --accent*, which is only defined on the
     login page. Without these, those gradients/colors were invalid and the
     white-on-transparent auto-restart icon vanished in light mode. */
  --accent:var(--acc); --accent2:var(--acc2); --accent3:var(--acc3);
  --bg:#060a14; --bg2:#0e1626; --card:rgba(20,29,51,.55); --card-solid:#0e1626;
  --brd:rgba(255,255,255,.09); --brd2:rgba(255,255,255,.06);
  --text:#e6edf8; --mut:#8d9ab8;
  --succ:#10b981; --err:#fb7185; --warn:#f59e0b;
  --ring:0 0 0 4px color-mix(in srgb,var(--acc) 22%,transparent);
  --shadow:0 24px 60px -24px rgba(0,0,0,.7);
}
html[data-theme="light"]{
  --bg:#eef2fb; --bg2:#e3eaf6; --card:rgba(255,255,255,.7); --card-solid:#ffffff;
  --brd:rgba(15,28,51,.10); --brd2:rgba(15,28,51,.06);
  --text:#0f1c33; --mut:#5a6a88;
  --shadow:0 24px 50px -24px rgba(40,60,120,.35);
}
*{box-sizing:border-box;margin:0;padding:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
html{scrollbar-gutter:stable}
body{background:var(--bg);color:var(--text);min-height:100vh;min-height:100dvh;transition:background .25s,color .25s}
.aurora{position:fixed;inset:-18%;z-index:0;filter:blur(72px);opacity:.55;pointer-events:none}
.aurora i{position:absolute;display:block;border-radius:50%;mix-blend-mode:screen}
.aurora .b1{width:38vw;height:38vw;left:-5vw;top:-8vw;background:radial-gradient(circle,#22d3ee,transparent 62%)}
.aurora .b2{width:34vw;height:34vw;right:-6vw;top:0;background:radial-gradient(circle,#6366f1,transparent 62%)}
.aurora .b3{width:32vw;height:32vw;left:30vw;bottom:-16vw;background:radial-gradient(circle,#2dd4bf,transparent 62%)}
html[data-theme="light"] .aurora{opacity:.4}
@keyframes fl1{50%{transform:translate(5vw,4vh) scale(1.1)}}
@keyframes fl2{50%{transform:translate(-4vw,5vh) scale(1.08)}}
@keyframes fl3{50%{transform:translate(3vw,-5vh) scale(1.12)}}

nav{position:sticky;top:0;z-index:100;display:flex;align-items:center;justify-content:space-between;
  padding:14px 22px;border-bottom:1px solid var(--brd);
  background:color-mix(in srgb,var(--bg) 78%,transparent);backdrop-filter:blur(18px) saturate(160%)}
.brand{display:flex;align-items:center;gap:12px;font-weight:800;font-size:18px;letter-spacing:-.3px}
.logo{width:38px;height:38px;border-radius:11px;background:linear-gradient(135deg,var(--acc),var(--acc2));
  display:grid;place-items:center;color:#04121a;box-shadow:0 10px 26px -8px var(--acc2)}
.logo svg{width:21px;height:21px}
.nav-actions{display:flex;gap:10px}

.icon-btn{width:40px;height:40px;border-radius:11px;display:grid;place-items:center;cursor:pointer;
  background:var(--card);border:1px solid var(--brd);color:var(--text);transition:.18s;backdrop-filter:blur(12px)}
.icon-btn:hover{border-color:var(--acc);transform:translateY(-1px)}
.icon-btn.danger:hover{border-color:var(--err);color:var(--err)}

.btn{padding:9px 16px;border-radius:11px;border:1px solid var(--brd);background:var(--card);color:var(--text);
  cursor:pointer;font-weight:600;font-size:13px;display:inline-flex;align-items:center;gap:8px;transition:.18s;backdrop-filter:blur(10px)}
.btn:hover{border-color:var(--acc);transform:translateY(-1px)}
.btn-primary{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#04121a;border:none;box-shadow:0 12px 26px -10px var(--acc2)}
.btn-primary:hover{filter:brightness(1.06)}
.btn-danger{color:var(--err);border-color:color-mix(in srgb,var(--err) 30%,transparent);background:color-mix(in srgb,var(--err) 10%,transparent)}
.btn-danger:hover{background:var(--err);color:#fff;border-color:var(--err)}
.btn-icon{padding:9px;width:40px;justify-content:center}

.container{max-width:1380px;margin:0 auto;padding:24px;position:relative;z-index:1}

.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--card);border:1px solid var(--brd);border-radius:16px;padding:18px 20px;backdrop-filter:blur(16px);position:relative;overflow:hidden}
.stat-card::after{content:"";position:absolute;right:-20px;top:-20px;width:80px;height:80px;border-radius:50%;background:var(--accClr,var(--acc));opacity:.14;filter:blur(8px)}
.stat-card .lbl{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.6px;font-weight:600}
.stat-card .val{font-size:30px;font-weight:800;margin-top:6px;line-height:1}

.tabs{display:flex;gap:6px;background:var(--card);border:1px solid var(--brd);padding:6px;border-radius:14px;margin-bottom:22px;backdrop-filter:blur(12px);width:fit-content;flex-wrap:wrap}
.tab{padding:9px 20px;border-radius:10px;cursor:pointer;font-size:13px;font-weight:700;color:var(--mut);transition:.18s}
.tab:hover{color:var(--text)}
.tab.active{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#04121a}

.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:14px}
.header h2{font-size:22px;font-weight:800;letter-spacing:-.4px}
.refreshing{font-size:12px;color:var(--mut);display:flex;align-items:center;gap:6px}

.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:18px}
.card{background:var(--card);border:1px solid var(--brd);border-radius:18px;padding:20px;backdrop-filter:blur(18px) saturate(150%);transition:.2s;box-shadow:var(--shadow)}
.card:hover{border-color:color-mix(in srgb,var(--acc) 35%,transparent);transform:translateY(-3px)}

.srv-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.srv-name{display:flex;align-items:center;gap:9px;font-size:16px;font-weight:700}
.badge{padding:3px 9px;border-radius:7px;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.4px}
.b-iran{background:color-mix(in srgb,var(--succ) 16%,transparent);color:var(--succ)}
.b-kharej{background:color-mix(in srgb,var(--acc2) 18%,transparent);color:var(--acc2)}
.ip-line{font-size:12px;color:var(--mut);margin-bottom:16px;font-family:ui-monospace,monospace}
.srv-stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px}
.stat{background:var(--bg2);padding:11px 12px;border-radius:11px;border:1px solid var(--brd2)}
.stat span{display:block;color:var(--mut);font-size:11px;margin-bottom:4px;text-transform:uppercase;letter-spacing:.4px}
.stat b{font-size:14px;font-weight:700}
.srv-actions{display:flex;gap:8px}
.srv-actions .btn{flex:1;justify-content:center}
.online{color:var(--succ);font-size:12px;font-weight:700;display:flex;align-items:center;gap:6px}
.offline{color:var(--err);font-size:12px;font-weight:700;display:flex;align-items:center;gap:6px}
.pulse{width:8px;height:8px;border-radius:50%;background:currentColor;box-shadow:0 0 0 0 currentColor;animation:pulse 2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,currentColor 60%,transparent)}70%{box-shadow:0 0 0 7px transparent}}

.tun-card{border-left:4px solid var(--acc2)}
.tun-card.running{border-left-color:var(--succ)}
.tun-card.stopped{border-left-color:var(--err)}
.tun-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;gap:10px}
.tun-title{font-weight:700;font-family:ui-monospace,monospace;font-size:13px;word-break:break-all}
.tun-status{display:flex;align-items:center;gap:6px;font-size:11px;font-weight:800;white-space:nowrap}
.dot{width:9px;height:9px;border-radius:50%}
.running .dot{background:var(--succ);box-shadow:0 0 10px var(--succ)}
.running .tun-status{color:var(--succ)}
.stopped .dot{background:var(--err)}
.stopped .tun-status{color:var(--err)}
.tun-info{display:flex;flex-wrap:wrap;gap:8px;font-size:11px;color:var(--mut);margin-bottom:16px}
.tun-info div{display:flex;align-items:center;gap:5px;background:var(--bg2);padding:5px 9px;border-radius:8px;border:1px solid var(--brd2)}
/* ---- Paired tunnel layout: Kharej (left) -> Iran (right) ---- */
#tunnelsGrid{display:flex;flex-direction:column;align-items:center;gap:8px}
.tunnel-pair{display:grid;grid-template-columns:1fr 190px 1fr;align-items:stretch;gap:0;width:100%;max-width:960px;margin:0 auto 14px}
.tun-end{border-left:4px solid var(--acc2);display:flex;flex-direction:column;gap:13px;height:100%;transition:transform .15s,box-shadow .15s}
.tun-end:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.tun-end.running{border-left-color:var(--succ)}
.tun-end.stopped{border-left-color:var(--err)}
.tun-end.empty-end{border-left-color:var(--brd);align-items:center;justify-content:center;color:var(--mut);font-size:12px;text-align:center;min-height:140px}
.tun-role{font-size:10px;font-weight:800;letter-spacing:.6px;padding:3px 8px;border-radius:6px;text-transform:uppercase;margin-right:7px}
.role-iran{background:color-mix(in srgb,var(--succ) 16%,transparent);color:var(--succ)}
.role-kharej{background:color-mix(in srgb,var(--acc2) 18%,transparent);color:var(--acc2)}
.tp-link{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:9px;padding:0 14px}
.tp-preset{display:inline-flex;align-items:center;gap:6px;cursor:pointer;font-size:11px;font-weight:800;color:#04121a;background:linear-gradient(135deg,var(--acc),var(--acc2));border:none;padding:6px 11px;border-radius:999px;box-shadow:0 8px 20px -8px var(--acc2);transition:transform .12s,filter .12s;white-space:nowrap}
.tp-preset:hover{transform:translateY(-1px);filter:brightness(1.08)}
.tp-preset.custom{background:var(--bg2);color:var(--text);border:1px dashed var(--brd)}
.tp-preset svg{opacity:.85}
.tp-pill{font-family:ui-monospace,monospace;font-size:11px;font-weight:700;color:var(--text);background:var(--bg2);border:1px solid var(--brd2);padding:5px 11px;border-radius:8px;text-align:center;white-space:nowrap;line-height:1.45}
.tp-flow{position:relative;width:100%;min-width:54px;height:22px;display:flex;align-items:center}
.tp-flow .line{position:relative;flex:1;height:3px;border-radius:3px;background:linear-gradient(90deg,var(--acc2),var(--acc));overflow:hidden}
.tp-flow .line::before{content:"";position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.9),transparent);width:40%;animation:tpflow 1.6s linear infinite}
@keyframes tpflow{0%{transform:translateX(-120%)}100%{transform:translateX(320%)}}
.tp-flow .head{width:0;height:0;border-left:9px solid var(--acc);border-top:6px solid transparent;border-bottom:6px solid transparent;margin-left:-1px}
.tp-flow.dead .line{background:var(--err);opacity:.5}
.tp-flow.dead .line::before{display:none}
.tp-flow.dead .head{border-left-color:var(--err);opacity:.6}
.tp-cron{font-size:10px;color:var(--acc);display:flex;align-items:center;gap:4px;font-weight:700}
.ps-opt{display:flex;gap:11px;align-items:flex-start;padding:13px;border:1px solid var(--brd);border-radius:13px;cursor:pointer;margin-bottom:10px;transition:.15s}
.ps-opt:hover{border-color:var(--acc)}
.ps-opt.sel{border-color:var(--acc);background:color-mix(in srgb,var(--acc) 8%,transparent)}
.ps-opt:has(input:checked){border-color:var(--acc);background:color-mix(in srgb,var(--acc) 8%,transparent)}
.ps-opt input{margin-top:4px;accent-color:var(--acc)}
.ps-t{font-weight:800;font-size:13px;margin-bottom:3px}
.ps-d{font-size:11px;color:var(--mut);line-height:1.5;margin-bottom:9px}
@media(max-width:840px){
  .tunnel-pair{grid-template-columns:1fr;max-width:480px}
  .tp-link{flex-direction:row;flex-wrap:wrap;justify-content:center;padding:14px 0}
  .tp-flow{width:auto;min-width:0;height:40px;flex-direction:column}
  .tp-flow .line{width:3px;height:100%;flex:1}
  .tp-flow .line::before{width:100%;height:40%;background:linear-gradient(180deg,transparent,rgba(255,255,255,.9),transparent);animation:tpflowv 1.6s linear infinite}
  @keyframes tpflowv{0%{transform:translateY(-120%)}100%{transform:translateY(320%)}}
  .tp-flow .head{border-left:6px solid transparent;border-right:6px solid transparent;border-top:9px solid var(--acc);border-bottom:none;margin:-1px 0 0}
  .tp-flow.dead .head{border-top-color:var(--err)}
}

.modal{position:fixed;inset:0;background:rgba(2,6,15,.65);backdrop-filter:blur(6px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:16px;opacity:0;pointer-events:none;transition:.2s}
.modal.show{opacity:1;pointer-events:auto}
.m-box{background:var(--card-solid);border:1px solid var(--brd);border-radius:22px;width:100%;max-width:520px;max-height:92vh;display:flex;flex-direction:column;transform:scale(.96) translateY(8px);transition:.2s;box-shadow:var(--shadow);overflow:hidden}
.modal.show .m-box{transform:scale(1) translateY(0)}
.m-head{padding:20px 22px;border-bottom:1px solid var(--brd);display:flex;justify-content:space-between;align-items:center}
.m-head h3{font-size:18px;font-weight:800}
.m-close{background:none;border:none;color:var(--mut);cursor:pointer;display:grid;place-items:center}
.m-close:hover{color:var(--text)}
.m-body{padding:22px;overflow-y:auto}
.m-foot{padding:18px 22px;border-top:1px solid var(--brd);display:flex;justify-content:flex-end;gap:12px}

.field{margin-bottom:15px}
.field label{display:block;font-size:12px;font-weight:700;color:var(--mut);margin-bottom:7px}
.field input,.field select{width:100%;padding:11px 14px;background:var(--bg2);border:1px solid var(--brd);color:var(--text);border-radius:11px;outline:none;font-size:14px;transition:.16s}
.field input:focus,.field select:focus{border-color:var(--acc);box-shadow:var(--ring)}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.input-group{display:flex;gap:8px}
.input-group input{flex:1}

.port-row{display:grid;grid-template-columns:1fr auto 1fr auto;align-items:center;gap:8px;margin-bottom:10px}
.port-row .arrow{color:var(--mut);font-weight:800}
.port-row input{width:100%;padding:10px 12px;background:var(--bg2);border:1px solid var(--brd);color:var(--text);border-radius:10px;outline:none;font-size:14px}
.port-row input:focus{border-color:var(--acc);box-shadow:var(--ring)}
.rm-row{width:38px;height:38px;border-radius:10px;border:1px solid color-mix(in srgb,var(--err) 30%,transparent);background:color-mix(in srgb,var(--err) 10%,transparent);color:var(--err);cursor:pointer;display:grid;place-items:center}
.rm-row:hover{background:var(--err);color:#fff}
.add-row{margin-top:4px;font-size:13px}
.hint{font-size:11px;color:var(--mut);margin-top:6px}

.term{background:#05080f;color:#5eead4;font-family:ui-monospace,monospace;padding:16px;border-radius:13px;overflow:auto;font-size:12.5px;line-height:1.55;max-height:55vh;white-space:pre-wrap;border:1px solid var(--brd)}
textarea.code{width:100%;height:48vh;background:#05080f;color:#5eead4;font-family:ui-monospace,monospace;padding:14px;border-radius:13px;border:1px solid var(--brd);outline:none;font-size:13px;resize:vertical}
textarea.code:focus{border-color:var(--acc)}

#toast{position:fixed;bottom:24px;left:50%;transform:translate(-50%,120px);background:var(--card-solid);backdrop-filter:blur(12px);border:1px solid var(--brd);padding:13px 22px;border-radius:13px;box-shadow:var(--shadow);opacity:0;transition:.3s cubic-bezier(.2,.85,.25,1);z-index:9999;display:flex;align-items:center;gap:10px;font-weight:600;font-size:14px;max-width:90vw}
#toast.show{transform:translate(-50%,0);opacity:1}
#toast.succ{border-left:4px solid var(--succ)}
#toast.err{border-left:4px solid var(--err)}

.loader{border:3px solid var(--brd);border-top-color:var(--acc);border-radius:50%;width:26px;height:26px;animation:spin .8s linear infinite;margin:30px auto}
.mini-loader{border:2px solid var(--brd);border-top-color:var(--acc);border-radius:50%;width:14px;height:14px;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.empty{grid-column:1/-1;text-align:center;color:var(--mut);padding:50px 20px;font-size:14px}
.btn-icon.cron-on{color:#fff;background:var(--acc2);background:linear-gradient(135deg,var(--acc2),var(--acc));border-color:transparent}
.btn-force{color:var(--accent);background:var(--glass);border-color:var(--accent)}
.btn-force:hover{color:#fff;background:var(--accent);border-color:var(--accent)}
/* ---- Preset selector / custom builder ---- */
.preset-info{margin:-4px 0 14px;padding:14px 16px;border-radius:14px;
  background:var(--glass);border:1px solid var(--glass-brd);display:none}
.preset-info.show{display:block;animation:fadein .25s}
@keyframes fadein{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.preset-info .pi-desc{font-size:13.5px;color:var(--text);line-height:1.6;margin-bottom:10px}
.preset-info .pi-best{font-size:12.5px;color:var(--mut);margin-bottom:12px}
.preset-info .pi-best b{color:var(--accent)}
.bars{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.bar-item .bar-lbl{font-size:11px;color:var(--mut);margin-bottom:5px;display:flex;justify-content:space-between}
.bar-track{height:7px;border-radius:6px;background:var(--glass-brd);overflow:hidden}
.bar-fill{height:100%;border-radius:6px;background:linear-gradient(90deg,var(--acc2),var(--accent));transition:width .4s}
.custom-box{margin:0 0 16px;padding:16px;border-radius:14px;border:1px dashed var(--glass-brd);background:var(--glass)}
.custom-head{font-size:13px;font-weight:700;margin-bottom:4px}
.custom-head .mut{font-weight:500;color:var(--mut)}
.custom-sub{font-size:11.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--mut);margin:14px 0 8px}
.custom-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px 14px}
@media(max-width:560px){.custom-grid{grid-template-columns:1fr}}
.cf{display:flex;flex-direction:column;gap:4px}
.cf label{font-size:11.5px;color:var(--mut);display:flex;align-items:center;gap:6px}
.cf input,.cf select{padding:8px 10px;border-radius:9px;border:1px solid var(--glass-brd);
  background:var(--bg);color:var(--text);font-size:13px;width:100%}
.ic-i{display:inline-grid;place-items:center;width:15px;height:15px;border-radius:50%;
  background:var(--accent);color:#fff;font-size:10px;font-weight:700;font-style:normal;cursor:help;position:relative}
.ic-i:hover::after{content:attr(data-tip);position:absolute;left:50%;bottom:140%;transform:translateX(-50%);
  width:230px;padding:9px 11px;border-radius:10px;background:#111827;color:#f3f4f6;font-size:11.5px;
  font-weight:500;line-height:1.5;text-align:left;box-shadow:0 8px 24px rgba(0,0,0,.4);z-index:50;white-space:normal}
.ic-i:hover::before{content:"";position:absolute;left:50%;bottom:128%;transform:translateX(-50%);
  border:6px solid transparent;border-top-color:#111827;z-index:50}
@media(max-width:520px){.row2{grid-template-columns:1fr}.container{padding:16px}.bars{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="aurora"><i class="b1"></i><i class="b2"></i><i class="b3"></i></div>

<nav>
  <div class="brand">
    <div class="logo"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M4 7h16M4 7l3-3m-3 3 3 3M20 17H4m16 0-3-3m3 3-3 3"/></svg></div>
    Backhaul Panel
  </div>
  <div class="nav-actions">
    <button class="icon-btn" id="themeBtn" title="Toggle theme"></button>
    <button class="icon-btn" onclick="openModal('m-settings')" title="Settings"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg></button>
    <button class="icon-btn danger" onclick="logout()" title="Logout"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg></button>
  </div>
</nav>

<div class="container">
  <div class="stats">
    <div class="stat-card" style="--accClr:var(--acc)"><div class="lbl">Servers</div><div class="val" id="st-srv">—</div></div>
    <div class="stat-card" style="--accClr:var(--succ)"><div class="lbl">Online</div><div class="val" id="st-online">—</div></div>
    <div class="stat-card" style="--accClr:var(--acc2)"><div class="lbl">Tunnels</div><div class="val" id="st-tun">—</div></div>
    <div class="stat-card" style="--accClr:var(--acc3)"><div class="lbl">Running</div><div class="val" id="st-run">—</div></div>
  </div>

  <div class="tabs">
    <div class="tab active" onclick="switchTab('servers',this)">Servers</div>
    <div class="tab" onclick="switchTab('tunnels',this)">Tunnels</div>
    <div class="tab" onclick="switchTab('create',this)">New Tunnel</div>
  </div>

  <div id="tab-servers">
    <div class="header">
      <h2>Servers</h2>
      <button class="btn btn-primary" onclick="openModal('m-add-server')">＋ Add Server</button>
    </div>
    <div class="grid" id="serversGrid"><div class="loader"></div></div>
  </div>

  <div id="tab-tunnels" style="display:none">
    <div class="header">
      <h2>Active Tunnels</h2>
      <button class="btn" onclick="fetchTunnels(true)"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2v6h-6M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M21 12a9 9 0 0 1-15 6.7L3 16"/></svg> Refresh</button>
    </div>
    <div class="grid" id="tunnelsGrid"><div class="loader"></div></div>
  </div>

  <div id="tab-create" style="display:none">
    <div class="header" style="justify-content:center;text-align:center"><h2>Create Matching Tunnel (Iran ⇄ Kharej)</h2></div>
    <div class="card" style="max-width:760px;margin:0 auto;box-shadow:var(--shadow)">
      <form id="createBothForm" onsubmit="createBothTunnel(event)">
        <div class="row2">
          <div class="field"><label>Iran Server (entry)</label><select id="cb-iran" required></select></div>
          <div class="field"><label>Kharej Server (exit)</label><select id="cb-kharej" required></select></div>
        </div>
        <div class="row2">
          <div class="field"><label>Transport</label><select id="cb-trans" onchange="onTransportChange()"><option value="wssmux">WSSMUX (recommended)</option><option value="wsmux">WSMUX</option><option value="tcpmux">TCPMUX</option><option value="tcp">TCP</option></select></div>
          <div class="field"><label>Tunnel Port <span style="color:var(--mut);font-weight:500">(random &amp; unique)</span></label>
            <div class="input-group">
              <input id="cb-port" type="number" min="1" max="65535" value="9743" required>
              <button type="button" class="btn btn-icon" title="Random free port" onclick="randomizeTunnelPort()"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2v6h-6M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M21 12a9 9 0 0 1-15 6.7L3 16"/></svg></button>
            </div>
          </div>
        </div>
        <div class="field">
          <label>Performance Preset</label>
          <select id="cb-preset" onchange="onPresetChange()"></select>
        </div>
        <div id="preset-info" class="preset-info"></div>
        <div id="custom-box" class="custom-box" style="display:none">
          <div class="custom-head">Custom parameters
            <span class="mut">— hover the <span class="ic-i">i</span> for an explanation of each field</span>
          </div>
          <div class="custom-sub">Server side (Iran)</div>
          <div id="custom-iran" class="custom-grid"></div>
          <div class="custom-sub">Client side (Kharej)</div>
          <div id="custom-kharej" class="custom-grid"></div>
        </div>

        <div class="field"><label>Custom Token <span style="color:var(--mut);font-weight:500">(blank = auto-generate)</span></label>
          <div class="input-group">
            <input id="cb-token" placeholder="Optional secure token">
            <button type="button" class="btn btn-icon" title="Generate" onclick="genToken()"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2v6h-6M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M21 12a9 9 0 0 1-15 6.7L3 16"/></svg></button>
          </div>
        </div>

        <div class="field">
          <label>Port Forwarding (Iran port → Kharej port)</label>
          <div id="portRows"></div>
          <button type="button" class="btn add-row" onclick="addPortRow()">＋ Add another port</button>
          <div class="hint">Users connect to the <b>Iran port</b>; traffic is tunneled to the matching <b>Kharej port</b>. Add as many pairs as you need.</div>
        </div>

        <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center;margin-top:8px" id="cb-btn">Create &amp; Connect Tunnel</button>
      </form>
    </div>
  </div>
</div>

<!-- Add Server Modal -->
<div class="modal" id="m-add-server">
  <div class="m-box">
    <div class="m-head"><h3>Add Server</h3><button class="m-close" onclick="closeModal('m-add-server')"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
    <form onsubmit="addServer(event)">
      <div class="m-body">
        <div class="field"><label>Server Name</label><input id="as-name" required placeholder="e.g. Tehran DC"></div>
        <div class="row2">
          <div class="field"><label>IP / Domain</label><input id="as-ip" required placeholder="IP or 127.0.0.1"></div>
          <div class="field"><label>Role</label><select id="as-role"><option value="iran">Iran</option><option value="kharej">Kharej</option></select></div>
        </div>
        <div class="row2">
          <div class="field"><label>SSH User</label><input id="as-user" value="root"></div>
          <div class="field"><label>SSH Port</label><input id="as-port" type="number" value="22"></div>
        </div>
        <div class="field"><label>SSH Password <span style="color:var(--mut);font-weight:500">(or use key below)</span></label><input id="as-pass" type="password"></div>
        <div class="field"><label>SSH Key path <span style="color:var(--mut);font-weight:500">(optional)</span></label><input id="as-key" placeholder="/root/.ssh/id_rsa"></div>
      </div>
      <div class="m-foot">
        <button type="button" class="btn" onclick="closeModal('m-add-server')">Cancel</button>
        <button type="submit" class="btn btn-primary" id="as-btn">Save Server</button>
      </div>
    </form>
  </div>
</div>

<!-- Logs Modal -->
<div class="modal" id="m-term">
  <div class="m-box" style="max-width:820px">
    <div class="m-head"><h3 id="term-title">Logs</h3><button class="m-close" onclick="closeModal('m-term')"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
    <div class="m-body"><div class="term" id="term-out">Loading…</div></div>
  </div>
</div>

<!-- Config Editor Modal -->
<div class="modal" id="m-edit">
  <div class="m-box" style="max-width:820px">
    <div class="m-head"><h3 id="edit-title">Config</h3><button class="m-close" onclick="closeModal('m-edit')"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
    <div class="m-body"><textarea id="edit-text" class="code" spellcheck="false"></textarea></div>
    <div class="m-foot">
      <button class="btn" onclick="closeModal('m-edit')">Cancel</button>
      <button class="btn btn-primary" onclick="saveConfig()">Save &amp; Restart</button>
    </div>
  </div>
</div>

<!-- Auto-Restart (cron) Modal -->
<div class="modal" id="m-cron">
  <div class="m-box" style="max-width:460px">
    <div class="m-head"><h3>Auto-Restart Schedule</h3><button class="m-close" onclick="closeModal('m-cron')"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
    <div class="m-body">
      <p style="color:var(--mut);font-size:13px;line-height:1.6;margin-bottom:14px">
        Periodically restart this tunnel to clear cache and keep the link fast.
        The tunnel disconnects for ~1 second on each restart.</p>
      <div id="cron-current" style="font-size:13px;margin-bottom:14px"></div>
      <div class="field"><label>Restart every</label>
        <select id="cron-preset" onchange="cronPreset()">
          <option value="0">Off (no auto-restart)</option>
          <option value="5">5 minutes</option>
          <option value="15">15 minutes</option>
          <option value="30" selected>30 minutes</option>
          <option value="60">1 hour</option>
          <option value="120">2 hours</option>
          <option value="360">6 hours</option>
          <option value="custom">Custom (minutes)…</option>
        </select>
      </div>
      <div class="field" id="cron-custom-wrap" style="display:none"><label>Custom interval (minutes, 1-1440)</label>
        <input id="cron-custom" type="number" min="1" max="1440" placeholder="e.g. 10"></div>
      <p style="color:var(--mut);font-size:12px;line-height:1.6;margin-top:4px">
        Set this on <b>one side only</b> (Iran or Kharej) \u2014 restarting either end refreshes the whole tunnel.
        Intervals under an hour run every N minutes; 1h/2h/6h (or custom values \u2265 60) run on the hour.
        The schedule is saved and stays editable here until you press <b>Disable</b>.</p>
    </div>
    <div class="m-foot">
      <button class="btn btn-danger" onclick="removeCron()">Disable</button>
      <button class="btn btn-primary" onclick="saveCron()">Save schedule</button>
    </div>
  </div>
</div>

<!-- Change Preset Modal -->
<div class="modal" id="m-preset">
  <div class="m-box" style="max-width:520px">
    <div class="m-head"><h3>Change Performance Preset</h3><button class="m-close" onclick="closeModal('m-preset')"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
    <div class="m-body">
      <div id="preset-switch-cur" style="font-size:13px;margin-bottom:14px"></div>
      <div id="preset-switch-list"></div>
      <p style="color:var(--mut);font-size:12px;line-height:1.6;margin-top:4px">Applies the new tuning values to <b>both ends</b> (Iran + Kharej) and restarts them. Transport, port and token stay the same. The tunnel disconnects for ~1 second.</p>
    </div>
    <div class="m-foot">
      <button class="btn" onclick="closeModal('m-preset')">Cancel</button>
      <button class="btn btn-primary" id="preset-apply-btn" onclick="applyPreset()">Apply &amp; Restart</button>
    </div>
  </div>
</div>

<!-- Settings Modal -->
<div class="modal" id="m-settings">
  <div class="m-box">
    <div class="m-head"><h3>Settings</h3><button class="m-close" onclick="closeModal('m-settings')"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
    <form onsubmit="saveSettings(event)">
      <div class="m-body">
        <div class="field"><label>Admin Username</label><input id="set-u" required></div>
        <div class="field"><label>New Password <span style="color:var(--mut);font-weight:500">(blank = keep current)</span></label><input id="set-p" type="password" placeholder="••••••••"></div>
        <div class="hint">Changing credentials signs out all active sessions.</div>
      </div>
      <div class="m-foot"><button type="submit" class="btn btn-primary">Update</button></div>
    </form>
  </div>
</div>

<div id="toast"></div>

<script>
/* ---------- Theme ---------- */
const SUN='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
const MOON='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>';
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);localStorage.setItem('bh_theme',t);document.getElementById('themeBtn').innerHTML=t==='dark'?SUN:MOON;}
applyTheme(localStorage.getItem('bh_theme')||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'));
document.getElementById('themeBtn').onclick=()=>applyTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark');

/* ---------- Helpers ---------- */
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const api=async(path,body=null)=>{
  const opt=body?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{};
  const r=await fetch(path,opt);
  if(r.status===401){location.href='/login.html';return null;}
  const d=await r.json();
  if(d&&d.success===false&&d.error) throw new Error(d.error);
  return d;
};
let toastTimer;
const showToast=(msg,isErr=false)=>{
  const t=$('toast');t.textContent=msg;t.className='show '+(isErr?'err':'succ');
  clearTimeout(toastTimer);toastTimer=setTimeout(()=>t.className='',3200);
};

let SERVERS=[],editSvc='',editSid='';

function openModal(id){$(id).classList.add('show');}
function closeModal(id){$(id).classList.remove('show');}
document.querySelectorAll('.modal').forEach(m=>m.addEventListener('click',function(e){if(e.target===this)this.classList.remove('show')}));
document.addEventListener('keydown',e=>{if(e.key==='Escape')document.querySelectorAll('.modal.show').forEach(m=>m.classList.remove('show'))});

function switchTab(id,el){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  ['servers','tunnels','create'].forEach(t=>$('tab-'+t).style.display='none');
  $('tab-'+id).style.display='block';
  if(id==='servers')fetchServers();
  if(id==='tunnels')fetchTunnels();
  if(id==='create'){populateServerSelects();randomizeTunnelPort();}
}

/* ---------- Servers ---------- */
function populateServerSelects(){
  const s1=$('cb-iran'),s2=$('cb-kharej');
  s1.innerHTML='';s2.innerHTML='';
  SERVERS.forEach(s=>{
    const opt=`<option value="${s.id}">${esc(s.name)} (${esc(s.ip)})</option>`;
    if(s.role==='kharej') s2.innerHTML+=opt; else s1.innerHTML+=opt;
  });
}
async function fetchServers(){
  try{
    const d=await api('/api/servers'); if(!d)return;
    SERVERS=d.servers||[];
    $('st-srv').textContent=SERVERS.length;
    $('st-online').textContent=SERVERS.filter(s=>s.ssh_ok).length;
    populateServerSelects();
    const g=$('serversGrid');
    if(!SERVERS.length){g.innerHTML='<div class="empty">No servers yet. Click “Add Server” to begin.</div>';return;}
    g.innerHTML=SERVERS.map(s=>{
      const badge=s.role==='iran'?'<span class="badge b-iran">IRAN</span>':'<span class="badge b-kharej">KHAREJ</span>';
      const stat=s.ssh_ok?'<span class="online"><span class="pulse"></span>Online</span>':'<span class="offline"><span class="pulse"></span>Offline</span>';
      return `<div class="card">
        <div class="srv-head"><div class="srv-name">${esc(s.name)} ${badge}</div>${stat}</div>
        <div class="ip-line">${esc(s.ip)} · ${esc(s.ssh_user||'root')}</div>
        <div class="srv-stats">
          <div class="stat"><span>CPU Load</span><b>${esc(s.load||'—')}</b></div>
          <div class="stat"><span>Memory</span><b>${esc(s.memory||'—')}</b></div>
          <div class="stat"><span>Binary</span><b>${esc(s.version||'—')}</b></div>
          <div class="stat"><span>Uptime</span><b>${esc(s.uptime||'—')}</b></div>
        </div>
        <div class="srv-actions">
          <button class="btn" onclick="installBin('${s.id}')"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg> Install</button>
          <button class="btn btn-danger btn-icon" onclick="delServer('${s.id}','${esc(s.name)}')"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>
        </div></div>`;
    }).join('');
  }catch(e){showToast(e.message,true)}
}
async function addServer(e){
  e.preventDefault();
  const btn=$('as-btn');btn.disabled=true;
  try{
    await api('/api/server/add',{
      name:$('as-name').value,ip:$('as-ip').value,role:$('as-role').value,
      ssh_user:$('as-user').value,ssh_port:parseInt($('as-port').value)||22,
      ssh_password:$('as-pass').value,ssh_key:$('as-key').value
    });
    closeModal('m-add-server');showToast('Server added');
    e.target.reset();$('as-user').value='root';$('as-port').value='22';
    fetchServers();
  }catch(ex){showToast(ex.message,true)}finally{btn.disabled=false}
}
async function delServer(id,name){
  if(!confirm('Delete server "'+name+'"?'))return;
  try{await api('/api/server/delete',{id});showToast('Server deleted');fetchServers();}catch(e){showToast(e.message,true)}
}
async function installBin(id){
  if(!confirm('Install / update the Backhaul binary on this server?'))return;
  showToast('Installing binary…');
  try{const r=await api('/api/install/binary',{server_id:id});showToast('Binary installed: '+(r.version||'done'));fetchServers();}
  catch(e){showToast(e.message,true)}
}

/* ---------- Tunnels ---------- */
async function fetchTunnels(force){
  try{
    const d=await api('/api/tunnels'); if(!d)return;
    const tuns=d.tunnels||[];
    // Group the two ends (iran + kharej) of a tunnel into one pair, keyed by
    // transport+port, so the dashboard shows one tunnel = one row.
    const groups={};
    tuns.forEach(t=>{
      const name=t.service.replace('backhaul-','').replace('.service','');
      const m=name.match(/^(iran|kharej)-(.+)-([0-9]+)$/);
      t.role=m?m[1]:'?'; t.tp=m?m[2]:(t.transport||'?'); t.port=m?m[3]:'?';
      const key=t.tp+':'+t.port;
      groups[key]=groups[key]||{key:key,transport:t.tp,port:t.port,iran:null,kharej:null};
      if(t.role==='kharej')groups[key].kharej=t; else groups[key].iran=t;
    });
    const pairs=Object.values(groups);
    window.TUNNEL_PAIRS=pairs;
    window.TUNNEL_PORTS=tuns.map(t=>t.port).filter(Boolean);
    $('st-tun').textContent=pairs.length;
    $('st-run').textContent=pairs.filter(p=>{
      const ends=[p.iran,p.kharej].filter(Boolean);
      return ends.length && ends.every(e=>e.status==='running');
    }).length;
    const g=$('tunnelsGrid');
    if(!pairs.length){g.innerHTML='<div class="empty">No active tunnels. Use \u201cNew Tunnel\u201d to create one.</div>';return;}
    g.innerHTML=pairs.map(p=>{
      const cron=(p.iran&&p.iran.cron_active)||(p.kharej&&p.kharej.cron_active);
      const cronInt=(p.iran&&p.iran.cron_interval)||(p.kharej&&p.kharej.cron_interval)||'';
      const ends=[p.iran,p.kharej].filter(Boolean);
      const alive=ends.length&&ends.every(e=>e.status==='running');
      return `<div class="tunnel-pair">
        ${endCard(p.kharej,'kharej')}
        <div class="tp-link">
          ${presetChip(p)}
          <div class="tp-pill">${esc((p.transport||'').toUpperCase())}<br>:${esc(p.port)}</div>
          <div class="tp-flow ${alive?'':'dead'}"><div class="line"></div><div class="head"></div></div>
          ${cron?`<div class="tp-cron"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg> ${esc(cronInt)}m</div>`:''}
          <button class="btn btn-danger btn-icon" title="Delete tunnel (both ends)" onclick="delPair('${esc(p.key)}')"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>
        </div>
        ${endCard(p.iran,'iran')}
      </div>`;
    }).join('');
  }catch(e){showToast(e.message,true)}
}
function endCard(t,role){
  if(!t)return `<div class="card tun-end empty-end">No <b>${role}</b> end found for this tunnel</div>`;
  const cls=t.status==='running'?'running':'stopped';
  return `<div class="card tun-end ${cls}">
    <div class="tun-head">
      <div><span class="tun-role role-${role}">${role}</span><span class="tun-title">${esc(t.server_name)}</span></div>
      <div class="tun-status"><div class="dot"></div>${t.status.toUpperCase()}</div>
    </div>
    <div class="tun-info">
      <div><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> ${esc(t.uptime)}</div>
      <div>CPU ${esc(t.cpu)}</div>
      <div>RAM ${esc(t.memory)}</div>
    </div>
    <div class="srv-actions">
      <button class="btn btn-icon" title="${t.status==='running'?'Restart':'Start'}" onclick="tunAction('${esc(t.service)}','${t.server_id}','${t.status==='running'?'restart':'start'}')"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg></button>
      <button class="btn btn-icon" title="Stop" onclick="tunAction('${esc(t.service)}','${t.server_id}','stop')"><svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" stroke="none"><rect x="6" y="6" width="12" height="12" rx="2"/></svg></button>
      <button class="btn btn-icon btn-force" title="Force Restart — stop + start" onclick="forceRestart('${esc(t.service)}','${t.server_id}','${esc(t.server_name)}')"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2v6h-6M21 8l-4-4M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M3 16l4 4M21 12a9 9 0 0 1-15 6.7L3 16"/></svg></button>
      <button class="btn btn-icon" title="Logs" onclick="showLogs('${esc(t.service)}','${t.server_id}')"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 4H3m18 8H8m13 8H3"/></svg></button>
      <button class="btn btn-icon" title="Edit config" onclick="editConf('${esc(t.service)}','${t.server_id}')"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg></button>
      <button class="btn btn-icon${t.cron_active?' cron-on':''}" title="Auto-restart schedule" onclick="openCron('${esc(t.service)}','${t.server_id}',${t.cron_active?1:0},'${esc(t.cron_interval||'')}')"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></button>
    </div>
  </div>`;
}
async function delPair(key){
  const p=(window.TUNNEL_PAIRS||[]).find(x=>x.key===key); if(!p)return;
  if(!confirm('Delete this tunnel? This removes BOTH ends (Iran + Kharej) on port '+p.port+'. Other tunnels are not affected.'))return;
  try{
    const tasks=[];
    if(p.kharej)tasks.push(api('/api/tunnel/delete',{service:p.kharej.service,server_id:p.kharej.server_id}));
    if(p.iran)tasks.push(api('/api/tunnel/delete',{service:p.iran.service,server_id:p.iran.server_id}));
    await Promise.all(tasks);
    showToast('Tunnel deleted (both ends)');fetchTunnels();
  }catch(e){showToast(e.message,true)}
}
function presetChip(p){
  const key=(p.iran&&p.iran.preset)||(p.kharej&&p.kharej.preset)||'';
  const known=window.PRESETS&&window.PRESETS[key];
  const lbl=known?known.label:(key==='custom'?'Custom':(key||'Custom'));
  const short=(lbl.split('\u2014')[0]||lbl).trim();
  const cls=(known&&key!=='custom')?'':'custom';
  return `<button class="tp-preset ${cls}" title="Change performance preset" onclick="openPresetSwitch('${esc(p.key)}')"><svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M13 2 4 14h6l-1 8 9-12h-6z"/></svg>${esc(short)} <span style="opacity:.7">\u25be</span></button>`;
}
var presetSwitchKey='';
function openPresetSwitch(key){
  const p=(window.TUNNEL_PAIRS||[]).find(x=>x.key===key); if(!p)return;
  presetSwitchKey=key;
  const cur=(p.iran&&p.iran.preset)||(p.kharej&&p.kharej.preset)||'';
  const list=$('preset-switch-list');
  list.innerHTML=['balanced','gaming','throughput','stable'].map(k=>{
    const pr=window.PRESETS[k]; if(!pr)return '';
    return `<label class="ps-opt${k===cur?' sel':''}"><input type="radio" name="psw" value="${k}" ${k===cur?'checked':''}>
      <div style="flex:1"><div class="ps-t">${esc(pr.label)}</div><div class="ps-d">${esc(pr.desc)}</div>
      <div class="bars">${rankBar('Speed',pr.rank_speed)}${rankBar('Stability',pr.rank_stability)}${rankBar('Low latency',pr.rank_latency)}</div></div></label>`;
  }).join('');
  $('preset-switch-cur').innerHTML='Current: <b>'+(window.PRESETS[cur]?esc(window.PRESETS[cur].label):(cur?esc(cur):'Custom / manual'))+'</b> \u00b7 transport <b>'+esc((p.transport||'').toUpperCase())+'</b> \u00b7 port <b>:'+esc(p.port)+'</b>';
  openModal('m-preset');
}
async function applyPreset(){
  const sel=document.querySelector('input[name=psw]:checked'); if(!sel){showToast('Pick a preset',true);return;}
  const p=(window.TUNNEL_PAIRS||[]).find(x=>x.key===presetSwitchKey); if(!p)return;
  const ends=[];
  if(p.iran)ends.push({service:p.iran.service,server_id:p.iran.server_id});
  if(p.kharej)ends.push({service:p.kharej.service,server_id:p.kharej.server_id});
  const btn=$('preset-apply-btn');btn.disabled=true;btn.textContent='Applying\u2026';
  try{
    const r=await api('/api/tunnel/set-preset',{preset:sel.value,ends:ends});
    const job=r&&r.job; if(!job)throw new Error('Could not start the change');
    // Poll for the result. The rebuild restarts both ends and can briefly drop
    // this connection, so individual polls may fail \u2014 we just keep retrying.
    let done=null;
    for(let i=0;i<40 && !done;i++){
      await new Promise(s=>setTimeout(s,1500));
      try{
        const st=await fetch('/api/tunnel/preset-status?job='+encodeURIComponent(job),{cache:'no-store'}).then(x=>x.json());
        if(st&&st.done)done=st;
      }catch(e){/* transient during restart \u2014 keep polling */}
    }
    closeModal('m-preset');
    if(done){
      if(done.success){showToast('Preset applied & tunnel restarted \u2713');}
      else{
        const errs=(done.results||[]).filter(x=>!x.success).map(x=>(x.server?x.server+': ':'')+(x.error||'error')).join(' \u00b7 ');
        showToast('Could not apply preset \u2014 '+(errs||'unknown error'),true);
      }
    }else{
      showToast('Still applying\u2026 the tunnel is restarting. Refresh in a moment to confirm.',true);
    }
    setTimeout(fetchTunnels,800);
  }catch(e){showToast(e.message,true)}
  finally{btn.disabled=false;btn.textContent='Apply & Restart';}
}
async function tunAction(svc,sid,act){
  try{await api('/api/tunnel/action',{service:svc,server_id:sid,action:act});showToast('Tunnel '+act+'ed');fetchTunnels();}
  catch(e){showToast(e.message,true)}
}
async function forceRestart(svc,sid,name){
  if(!confirm('Force restart '+name+' ('+svc+')? This does a complete stop + start.'))return;
  try{
    await api('/api/tunnel/action',{service:svc,server_id:sid,action:'force-restart'});
    showToast('Tunnel force-restarted ✓');
    fetchTunnels();
  }catch(e){showToast(e.message,true)}
}
async function delTun(svc,sid){
  if(!confirm('Permanently delete this tunnel end?'))return;
  try{await api('/api/tunnel/delete',{service:svc,server_id:sid});showToast('Tunnel deleted');fetchTunnels();}
  catch(e){showToast(e.message,true)}
}
var cronSvc='',cronSid='';
function cronPreset(){
  $('cron-custom-wrap').style.display=$('cron-preset').value==='custom'?'block':'none';
}
function openCron(svc,sid,active,interval){
  cronSvc=svc;cronSid=sid;
  const cur=$('cron-current');
  if(active&&interval){cur.innerHTML='Current: <b style="color:var(--succ)">every '+esc(interval)+' min</b>';}
  else{cur.innerHTML='Current: <span style="color:var(--mut)">disabled</span>';}
  const opts=['5','15','30','60','120','360'];
  const sel=$('cron-preset');
  if(interval&&opts.indexOf(String(interval))>-1){sel.value=String(interval);$('cron-custom').value='';}
  else if(interval){sel.value='custom';$('cron-custom').value=interval;}
  else{sel.value='30';$('cron-custom').value='';}
  cronPreset();openModal('m-cron');
}
async function saveCron(){
  let iv=$('cron-preset').value;
  if(iv==='custom'){iv=parseInt($('cron-custom').value,10);
    if(!iv||iv<1||iv>1440){showToast('Enter a custom interval between 1 and 1440 minutes',true);return;}}
  iv=parseInt(iv,10)||0;
  if(iv<=0){removeCron();return;}
  try{await api('/api/tunnel/cron',{service:cronSvc,server_id:cronSid,interval:iv,action:'set'});
    closeModal('m-cron');showToast('Auto-restart set: every '+iv+' min');fetchTunnels();}
  catch(e){showToast(e.message,true)}
}
async function removeCron(){
  try{await api('/api/tunnel/cron',{service:cronSvc,server_id:cronSid,interval:0,action:'remove'});
    closeModal('m-cron');showToast('Auto-restart disabled');fetchTunnels();}
  catch(e){showToast(e.message,true)}
}
async function showLogs(svc,sid){
  $('term-title').textContent='Logs · '+svc;$('term-out').textContent='Loading…';openModal('m-term');
  try{const r=await api('/api/tunnel/logs?svc='+encodeURIComponent(svc)+'&server_id='+sid);
    $('term-out').textContent=r.logs||'No logs found.';$('term-out').scrollTop=$('term-out').scrollHeight;}
  catch(e){$('term-out').textContent='Error: '+e.message}
}
async function editConf(svc,sid){
  editSvc=svc;editSid=sid;$('edit-title').textContent='Config · '+svc;$('edit-text').value='Loading…';openModal('m-edit');
  try{const r=await api('/api/tunnel/config?svc='+encodeURIComponent(svc)+'&server_id='+sid);$('edit-text').value=r.config||'';}
  catch(e){$('edit-text').value='Error: '+e.message}
}
async function saveConfig(){
  try{await api('/api/tunnel/save_config',{service:editSvc,server_id:editSid,config:$('edit-text').value});
    closeModal('m-edit');showToast('Config saved · tunnel restarted');fetchTunnels();}
  catch(e){showToast(e.message,true)}
}

/* ---------- Create Tunnel ---------- */
function addPortRow(iran,kharej){
  const div=document.createElement('div');div.className='port-row';
  div.innerHTML=`<input type="number" class="pr-iran" placeholder="Iran port" value="${iran||''}">
    <span class="arrow">→</span>
    <input type="number" class="pr-kharej" placeholder="Kharej port" value="${kharej||''}">
    <button type="button" class="rm-row" onclick="this.parentElement.remove()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button>`;
  $('portRows').appendChild(div);
}
function buildPorts(){
  const rules=[];
  document.querySelectorAll('#portRows .port-row').forEach(r=>{
    const i=r.querySelector('.pr-iran').value.trim(),k=r.querySelector('.pr-kharej').value.trim();
    if(i&&k) rules.push('"'+i+'=127.0.0.1:'+k+'"');
  });
  return rules.join(',');
}
async function genToken(){
  try{const r=await api('/api/token/generate');if(r&&r.token)$('cb-token').value=r.token;}catch(e){}
}
async function randomizeTunnelPort(){
  // Pick a random free port (20000-60000) that isn't already used by a tunnel,
  // so the default is never the same fixed 9743 and never collides.
  let used=window.TUNNEL_PORTS;
  if(!used){
    try{const d=await api('/api/tunnels');
      used=(d.tunnels||[]).map(t=>{const m=t.service.match(/-([0-9]+)[.]service$/);return m?m[1]:'';});
      window.TUNNEL_PORTS=used;
    }catch(e){used=[];}
  }
  const set=new Set((used||[]).map(String));
  let p,tries=0;
  do{p=Math.floor(20000+Math.random()*40000);tries++;}while(set.has(String(p))&&tries<60);
  $('cb-port').value=p;
}
async function createBothTunnel(e){
  e.preventDefault();
  const ports=buildPorts();
  if(!ports){showToast('Add at least one Iran→Kharej port pair',true);return;}
  const btn=$('cb-btn');btn.disabled=true;btn.textContent='Creating…';
  try{
    await api('/api/tunnel/create-both',{
      iran_server:{id:$('cb-iran').value},kharej_server:{id:$('cb-kharej').value},
      transport:$('cb-trans').value,port:$('cb-port').value,ports:ports,token:$('cb-token').value,
      preset:$('cb-preset').value,custom:($('cb-preset').value==='custom'?collectCustom():{})
    });
    showToast('Tunnel created on both servers!');
    $('createBothForm').reset();$('portRows').innerHTML='';addPortRow();randomizeTunnelPort();
    switchTab('tunnels',document.querySelectorAll('.tab')[1]);
  }catch(ex){showToast(ex.message,true)}
  finally{btn.disabled=false;btn.textContent='Create & Connect Tunnel';}
}

/* ---------- Settings ---------- */
async function saveSettings(e){
  e.preventDefault();
  try{await api('/api/settings/update',{username:$('set-u').value,password:$('set-p').value});
    closeModal('m-settings');showToast('Settings updated · signing out…');setTimeout(()=>location.reload(),1100);}
  catch(ex){showToast(ex.message,true)}
}
async function logout(){try{await api('/api/auth/logout',{});}catch(e){}location.href='/login.html';}

/* ---------- Presets ---------- */
var PRESETS={},PHELP={};
var ORDER=['balanced','gaming','throughput','stable','custom'];
var IRAN_KEYS=['keepalive_period','nodelay','heartbeat','channel_size','mux_con','mux_version','mux_framesize','mux_recievebuffer','mux_streambuffer','sniffer','web_port','log_level','mss','so_rcvbuf','so_sndbuf'];
var KHAREJ_KEYS=['connection_pool','aggressive_pool','keepalive_period','nodelay','retry_interval','dial_timeout','mux_version','mux_framesize','mux_recievebuffer','mux_streambuffer','sniffer','web_port','log_level','mss','so_rcvbuf','so_sndbuf'];
var BOOLF=['nodelay','aggressive_pool','sniffer'];
var LL=['panic','fatal','error','warn','info','debug','trace'];
async function loadPresets(){
  try{const r=await api('/api/presets');PRESETS=r.presets||{};PHELP=r.help||{};}catch(e){return;}
  const sel=$('cb-preset');sel.innerHTML='';
  ORDER.forEach(k=>{
    if(k==='custom'){sel.insertAdjacentHTML('beforeend','<option value="custom">Custom — full manual control</option>');return;}
    const p=PRESETS[k];if(!p)return;
    sel.insertAdjacentHTML('beforeend','<option value="'+k+'">'+p.label+'</option>');
  });
  sel.value='balanced';onPresetChange();
}
function rankBar(lbl,v){
  return '<div class="bar-item"><div class="bar-lbl"><span>'+lbl+'</span><span>'+v+'/5</span></div>'+
    '<div class="bar-track"><div class="bar-fill" style="width:'+(v*20)+'%"></div></div></div>';
}
function renderPresetInfo(){
  const k=$('cb-preset').value,info=$('preset-info');
  const p=PRESETS[k];if(!p){info.classList.remove('show');return;}
  const sel=$('cb-trans').value,best=(p.best_transport||'');
  let tline;
  if(best&&sel!==best){
    // The preset is a TUNING profile and works with ANY transport. When the
    // user overrides the recommended transport we say so plainly instead of
    // leaving a misleading "best transport" claim next to a different choice.
    tline='<div class="pi-best">Transport: <b>'+sel.toUpperCase()+'</b> (your choice) \u00b7 recommended for this preset: <b>'+best.toUpperCase()+'</b>.<br><span style="color:var(--mut)">The preset only sets performance values \u2014 it applies on top of whichever transport you pick.</span></div>';
  }else{
    tline='<div class="pi-best">Best transport for this preset: <b>'+best.toUpperCase()+'</b></div>';
  }
  info.innerHTML='<div class="pi-desc">'+p.desc+'</div>'+tline+
    '<div class="bars">'+rankBar('Speed',p.rank_speed)+rankBar('Stability',p.rank_stability)+rankBar('Low latency',p.rank_latency)+'</div>';
  info.classList.add('show');
}
function onPresetChange(){
  const k=$('cb-preset').value,info=$('preset-info'),cbox=$('custom-box');
  if(k==='custom'){
    info.classList.remove('show');
    cbox.style.display='block';renderCustom();return;
  }
  cbox.style.display='none';
  const p=PRESETS[k];if(!p){info.classList.remove('show');return;}
  // Picking a preset pre-fills its recommended transport for convenience, but
  // the two are independent: the user can freely change the transport after.
  if(p.best_transport)$('cb-trans').value=p.best_transport;
  renderPresetInfo();
}
function onTransportChange(){
  // Keep the preset selected (its tuning still applies) and just refresh the
  // info box so a manual transport change no longer looks like a conflict.
  if($('cb-preset').value!=='custom')renderPresetInfo();
}
function fieldHtml(side,key,val){
  const tip=(PHELP[key]||'').replace(/"/g,'&quot;');
  let input;
  if(BOOLF.indexOf(key)>-1){
    input='<select data-side="'+side+'" data-key="'+key+'">'+
      '<option value="true"'+(String(val)==='true'?' selected':'')+'>true</option>'+
      '<option value="false"'+(String(val)==='false'?' selected':'')+'>false</option></select>';
  }else if(key==='log_level'){
    input='<select data-side="'+side+'" data-key="'+key+'">'+LL.map(l=>'<option'+(l===val?' selected':'')+'>'+l+'</option>').join('')+'</select>';
  }else{
    input='<input type="number" data-side="'+side+'" data-key="'+key+'" value="'+val+'">';
  }
  return '<div class="cf"><label>'+key+' <span class="ic-i" data-tip="'+tip+'">i</span></label>'+input+'</div>';
}
function renderCustom(){
  const base=PRESETS['balanced']||{iran:{},kharej:{}};
  $('custom-iran').innerHTML=IRAN_KEYS.map(k=>fieldHtml('iran',k,base.iran[k])).join('');
  $('custom-kharej').innerHTML=KHAREJ_KEYS.map(k=>fieldHtml('kharej',k,base.kharej[k])).join('');
}
function collectCustom(){
  const out={iran:{},kharej:{}};
  document.querySelectorAll('#custom-box [data-key]').forEach(el=>{
    const side=el.dataset.side||'iran';out[side][el.dataset.key]=el.value;
  });
  return out;
}

/* ---------- Init ---------- */
addPortRow(443,443);
api('/api/settings/get').then(d=>{if(d&&d.username)$('set-u').value=d.username});
loadPresets();
fetchServers();
fetchTunnels();
try{if(sessionStorage.getItem('bh_must_change')==='1'){sessionStorage.removeItem('bh_must_change');
  showToast('Security: you are still using the default password. Please set a new one now.',true);
  setTimeout(()=>{try{openModal('m-settings');}catch(e){}},900);}}catch(e){}
setInterval(()=>{const t=document.querySelector('#tab-servers');if(t&&t.style.display!=='none')fetchServers();const u=document.querySelector('#tab-tunnels');if(u&&u.style.display!=='none')fetchTunnels();},15000);
</script>
</body>
</html>
"""

if __name__ == "__main__":
    os.makedirs(INSTALL_DIR, exist_ok=True)
    os.makedirs(CRON_CONFIG_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    os.makedirs(PANEL_DIR, exist_ok=True)

    cfg = load_panel_config()
    # Port: env override > config file > built-in default.
    try:
        port = int(os.environ.get("PANEL_PORT", cfg.get("port", PORT)))
    except (TypeError, ValueError):
        port = PORT

    # Bind address: env override > config file > all-interfaces default.
    # Set PANEL_BIND=127.0.0.1 to expose the panel only to a local reverse
    # proxy (recommended when running plain HTTP).
    bind_host = os.environ.get("PANEL_BIND", cfg.get("bind", "0.0.0.0"))
    server = ReuseAddrHTTPServer((bind_host, port), PanelHandler)

    scheme = "http"
    cert, key = cfg.get("ssl_cert", ""), cfg.get("ssl_key", "")
    if cfg.get("ssl_enabled") and cert and key and os.path.exists(cert) and os.path.exists(key):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            # Modern TLS only.
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            SSL_ON = True
            scheme = "https"
        except Exception as e:
            print(f"  [!] TLS setup failed ({e}). Falling back to HTTP.")

    local_ip = get_local_ip()
    host = cfg.get("domain") or local_ip
    print("")
    print("  BackhaulManager Web Panel v2.9.2")
    print("  Multi-Server Edition by emad1381 (hardened + presets)")
    print("")
    print(f"  URL:      {scheme}://{host}:{port}")
    if SSL_ON:
        print("  TLS:      enabled")
    else:
        print("  TLS:      DISABLED - credentials are sent in clear text!")
    settings_now = load_settings()
    if not settings_now.get("admin_pass_hash") and settings_now.get("admin_pass", ADMIN_PASS) == ADMIN_PASS:
        print("  [!] WARNING: default password is still 'admin'. Change it in Settings now.")
    print("")
    print("  Manage Iran + Kharej servers from one panel!")
    print("  Press Ctrl+C to stop")
    print("")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.server_close()
