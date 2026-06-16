#!/usr/bin/env python3
"""
BackhaulManager Web Panel
Version: 1.2.0
Author: emad1381
"""

import http.server
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
from http.cookies import SimpleCookie
import secrets
import hashlib

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

sessions = {}

def run_cmd(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "Command timed out", 1
    except Exception as e:
        return str(e), 1

def get_local_ip():
    out, _ = run_cmd("hostname -I 2>/dev/null | awk '{print $1}'")
    return out if out else "unknown"

def get_role():
    out, _ = run_cmd("systemctl list-units --type=service --state=running 2>/dev/null | grep -q 'backhaul-iran' && echo iran")
    if out == "iran":
        return "iran"
    out, _ = run_cmd("systemctl list-units --type=service --state=running 2>/dev/null | grep -q 'backhaul-kharej' && echo kharej")
    if out == "kharej":
        return "kharej"
    out, _ = run_cmd(f'ls {INSTALL_DIR}/iran-*.toml 2>/dev/null | head -1')
    if out:
        return "iran"
    out, _ = run_cmd(f'ls {INSTALL_DIR}/kharej-*.toml 2>/dev/null | head -1')
    if out:
        return "kharej"
    return "unknown"

def get_binary_version():
    out, _ = run_cmd(f"{BINARY} --version 2>/dev/null | head -1")
    return out if out else "not installed"

def get_tunnels():
    tunnels = []
    out, _ = run_cmd("systemctl list-unit-files --type=service 2>/dev/null | grep -o 'backhaul[^ ]*\\.service' | sort -u")
    if not out:
        return tunnels
    for svc in out.split('\n'):
        svc = svc.strip()
        if not svc:
            continue
        status_out, _ = run_cmd(f"systemctl is-active {svc} 2>/dev/null")
        pid_out, _ = run_cmd(f"systemctl show -p MainPID --value {svc} 2>/dev/null")
        cpu, mem, uptime_s = "—", "—", "—"
        pid = pid_out.strip() if pid_out else "0"
        if pid and pid != "0":
            cpu_out, _ = run_cmd(f"ps -p {pid} -o %cpu= 2>/dev/null")
            mem_out, _ = run_cmd(f"ps -p {pid} -o rss= 2>/dev/null")
            up_out, _ = run_cmd(f"ps -p {pid} -o etime= 2>/dev/null")
            cpu = cpu_out.strip() if cpu_out else "—"
            mem_kb = mem_out.strip() if mem_out else "0"
            try:
                mem = f"{int(mem_kb)/1024:.1f}M"
            except:
                mem = "—"
            uptime_s = up_out.strip() if up_out else "—"

        config_path = f"{INSTALL_DIR}/{svc.replace('backhaul-', '').replace('.service', '')}.toml"
        transport, bind_addr = "?", "?"
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    for line in f:
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
            "service": svc,
            "status": "running" if status_out.strip() == "active" else "stopped",
            "cpu": cpu,
            "memory": mem,
            "uptime": uptime_s,
            "transport": transport,
            "bind_addr": bind_addr,
            "config": config_path if os.path.exists(config_path) else "",
            "cron_active": cron_active,
            "cron_interval": cron_interval
        })
    return tunnels

def get_tunnel_logs(svc, lines=100):
    out, _ = run_cmd(f"journalctl -u {svc} -n {lines} --no-pager 2>/dev/null")
    return out

def get_tunnel_config(svc):
    config_name = svc.replace("backhaul-", "").replace(".service", "")
    config_path = f"{INSTALL_DIR}/{config_name}.toml"
    if os.path.exists(config_path):
        with open(config_path) as f:
            return f.read()
    return ""

def backup_config(filepath):
    if os.path.exists(filepath):
        ts = time.strftime("%Y%m%d-%H%M%S")
        os.makedirs(BACKUP_DIR, exist_ok=True)
        subprocess.run(f"cp '{filepath}' '{BACKUP_DIR}/$(basename {filepath}).bak.{ts}'", shell=True)

def get_system_info():
    ip = get_local_ip()
    role = get_role()
    version = get_binary_version()
    hostname_out, _ = run_cmd("hostname")
    kernel_out, _ = run_cmd("uname -r")
    load_out, _ = run_cmd("cut -d' ' -f1-3 /proc/loadavg")
    mem_out, _ = run_cmd("free -h | awk '/^Mem:/{print $3 \" used / \" $2}'")
    disk_out, _ = run_cmd("df -h / | awk 'NR==2{print $3 \" used / \" $2}'")
    uptime_out, _ = run_cmd("uptime -p")
    return {
        "ip": ip, "role": role, "version": version,
        "hostname": hostname_out, "kernel": kernel_out,
        "load": load_out, "memory": mem_out, "disk": disk_out,
        "uptime": uptime_out
    }

def create_tunnel(params):
    role = params.get("role", "iran")
    transport = params.get("transport", "wssmux")
    port = params.get("port", "9743")
    token = params.get("token", "")
    iran_ip = params.get("iran_ip", "")
    ports_mapping = params.get("ports", "")

    if not token:
        token_out, _ = run_cmd("cat /proc/sys/kernel/random/uuid 2>/dev/null || head -c 32 /dev/urandom | base64")
        token = token_out[:36] if token_out else "auto-generated"

    svc_name = f"backhaul-{role}-{transport}-{port}"
    config_file = f"{INSTALL_DIR}/{role}-{transport}-{port}.toml"
    service_file = f"{SERVICE_DIR}/{svc_name}.service"

    os.makedirs(INSTALL_DIR, exist_ok=True)

    if os.path.exists(config_file):
        backup_config(config_file)

    if transport == "wssmux" and not os.path.exists(f"{CERT_DIR}/wssmux.crt"):
        os.makedirs(CERT_DIR, exist_ok=True)
        run_cmd(f'openssl req -x509 -newkey rsa:2048 -keyout {CERT_DIR}/wssmux.key -out {CERT_DIR}/wssmux.crt -days 3650 -nodes -subj "/CN=backhaul-wssmux" 2>/dev/null')

    if role == "iran":
        config_content = f'''[server]
bind_addr = "0.0.0.0:{port}"
transport = "{transport}"
{"accept_udp = False" if transport == "tcp" else ""}
token = "{token}"
keepalive_period = 75
nodelay = True
heartbeat = 40
channel_size = 4096
{"mux_con = 8" if transport != "tcp" else ""}
{"mux_version = 1" if transport != "tcp" else ""}
{"mux_framesize = 32768" if transport != "tcp" else ""}
{"mux_recievebuffer = 4194304" if transport != "tcp" else ""}
{"mux_streambuffer = 65536" if transport != "tcp" else ""}
{"tls_cert = \"" + CERT_DIR + "/wssmux.crt\"" if transport == "wssmux" else ""}
{"tls_key = \"" + CERT_DIR + "/wssmux.key\"" if transport == "wssmux" else ""}
sniffer = False
web_port = 0
log_level = "info"
ports = [{ports_mapping}]
'''
    else:
        config_content = f'''[client]
remote_addr = "{iran_ip}:{port}"
{"edge_ip = \"\"" if transport in ["wsmux", "wssmux"] else ""}
transport = "{transport}"
token = "{token}"
connection_pool = 8
aggressive_pool = False
keepalive_period = 75
nodelay = True
retry_interval = 3
dial_timeout = 10
{"mux_version = 1" if transport != "tcp" else ""}
{"mux_framesize = 32768" if transport != "tcp" else ""}
{"mux_recievebuffer = 4194304" if transport != "tcp" else ""}
{"mux_streambuffer = 65536" if transport != "tcp" else ""}
sniffer = False
web_port = 0
log_level = "info"
'''

    with open(config_file, 'w') as f:
        f.write(config_content)

    descriptions = {
        "tcp": "Backhaul TCP Tunnel",
        "tcpmux": "Backhaul TCPMUX Tunnel",
        "wsmux": "Backhaul WSMUX Tunnel",
        "wssmux": "Backhaul WSSMUX Tunnel (TLS)"
    }

    service_content = f'''[Unit]
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
'''

    with open(service_file, 'w') as f:
        f.write(service_content)

    run_cmd("systemctl daemon-reload")
    run_cmd(f"systemctl enable {svc_name} 2>/dev/null")
    run_cmd(f"systemctl restart {svc_name}")

    time.sleep(1)
    status_out, _ = run_cmd(f"systemctl is-active {svc_name} 2>/dev/null")

    return {
        "success": status_out.strip() == "active",
        "service": svc_name,
        "config": config_file,
        "token": token,
        "port": port,
        "transport": transport,
        "role": role
    }

def delete_tunnel(svc):
    run_cmd(f"systemctl stop {svc} 2>/dev/null")
    run_cmd(f"systemctl disable {svc} 2>/dev/null")
    config_name = svc.replace("backhaul-", "").replace(".service", "")
    config_path = f"{INSTALL_DIR}/{config_name}.toml"
    if os.path.exists(config_path):
        backup_config(config_path)
        os.remove(config_path)
    service_path = f"{SERVICE_DIR}/{svc}"
    if os.path.exists(service_path):
        os.remove(service_path)
    cron_conf = f"{CRON_CONFIG_DIR}/{svc}.conf"
    if os.path.exists(cron_conf):
        run_cmd(f"crontab -l 2>/dev/null | grep -v '{CRON_MARKER}.*{svc}' | crontab -")
        os.remove(cron_conf)
    run_cmd("systemctl daemon-reload")
    return {"success": True}

def set_cron_restart(svc, interval_min):
    os.makedirs(CRON_CONFIG_DIR, exist_ok=True)
    conf_path = f"{CRON_CONFIG_DIR}/{svc}.conf"
    with open(conf_path, 'w') as f:
        f.write(f"SERVICE={svc}\nINTERVAL={interval_min}\n")
    cron_line = f"*/{interval_min} * * * * systemctl restart {svc} {CRON_MARKER} {svc}"
    run_cmd(f"crontab -l 2>/dev/null | grep -v '{CRON_MARKER}.*{svc}' > /tmp/cron_tmp")
    with open("/tmp/cron_tmp", "a") as f:
        f.write(cron_line + "\n")
    run_cmd("crontab /tmp/cron_tmp")
    run_cmd("rm -f /tmp/cron_tmp")
    return {"success": True}

def remove_cron_restart(svc):
    cron_conf = f"{CRON_CONFIG_DIR}/{svc}.conf"
    run_cmd(f"crontab -l 2>/dev/null | grep -v '{CRON_MARKER}.*{svc}' | crontab -")
    if os.path.exists(cron_conf):
        os.remove(cron_conf)
    return {"success": True}

def generate_token():
    out, _ = run_cmd("cat /proc/sys/kernel/random/uuid 2>/dev/null || head -c 32 /dev/urandom | base64")
    return out[:36] if out else secrets.token_hex(16)


class PanelHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_html(self, html, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def check_auth(self):
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        sid = cookie.get("session")
        if sid and sid.value in sessions:
            return True
        return False

    def do_GET(self):
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

        if path == "/api/system":
            self.send_json(get_system_info())
            return

        if path == "/api/tunnels":
            self.send_json({"tunnels": get_tunnels()})
            return

        if path == "/api/tunnel/logs":
            params = urllib.parse.parse_qs(parsed.query)
            svc = params.get("svc", [""])[0]
            lines = params.get("lines", ["100"])[0]
            if svc:
                self.send_json({"logs": get_tunnel_logs(svc, lines)})
            else:
                self.send_json({"error": "missing svc parameter"}, 400)
            return

        if path == "/api/tunnel/config":
            params = urllib.parse.parse_qs(parsed.query)
            svc = params.get("svc", [""])[0]
            if svc:
                self.send_json({"config": get_tunnel_config(svc)})
            else:
                self.send_json({"error": "missing svc parameter"}, 400)
            return

        if path == "/api/token/generate":
            self.send_json({"token": generate_token()})
            return

        self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        try:
            data = json.loads(body) if body else {}
        except:
            data = {}

        if path == "/api/auth/login":
            username = data.get("username", "")
            password = data.get("password", "")
            if username == ADMIN_USER and password == ADMIN_PASS:
                sid = secrets.token_hex(32)
                sessions[sid] = {"user": username, "time": time.time()}
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"session={sid}; Path=/; HttpOnly; SameSite=Strict")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True}).encode())
            else:
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

        if path == "/api/tunnel/start":
            svc = data.get("service", "")
            if svc:
                out, code = run_cmd(f"systemctl start {svc}")
                self.send_json({"success": code == 0, "output": out})
            else:
                self.send_json({"error": "missing service"}, 400)
            return

        if path == "/api/tunnel/stop":
            svc = data.get("service", "")
            if svc:
                out, code = run_cmd(f"systemctl stop {svc}")
                self.send_json({"success": code == 0, "output": out})
            else:
                self.send_json({"error": "missing service"}, 400)
            return

        if path == "/api/tunnel/restart":
            svc = data.get("service", "")
            if svc:
                out, code = run_cmd(f"systemctl restart {svc}")
                self.send_json({"success": code == 0, "output": out})
            else:
                self.send_json({"error": "missing service"}, 400)
            return

        if path == "/api/tunnel/delete":
            svc = data.get("service", "")
            if svc:
                result = delete_tunnel(svc)
                self.send_json(result)
            else:
                self.send_json({"error": "missing service"}, 400)
            return

        if path == "/api/tunnel/create":
            result = create_tunnel(data)
            self.send_json(result)
            return

        if path == "/api/tunnel/cron":
            svc = data.get("service", "")
            interval = data.get("interval", 0)
            action = data.get("action", "set")
            if action == "remove":
                result = remove_cron_restart(svc)
            elif interval > 0:
                result = set_cron_restart(svc, interval)
            else:
                self.send_json({"error": "invalid params"}, 400)
                return
            self.send_json(result)
            return

        if path == "/api/tunnel/save_config":
            svc = data.get("service", "")
            config = data.get("config", "")
            if svc and config:
                config_name = svc.replace("backhaul-", "").replace(".service", "")
                config_path = f"{INSTALL_DIR}/{config_name}.toml"
                if os.path.exists(config_path):
                    backup_config(config_path)
                with open(config_path, 'w') as f:
                    f.write(config)
                run_cmd(f"systemctl restart {svc}")
                self.send_json({"success": True})
            else:
                self.send_json({"error": "missing params"}, 400)
            return

        if path == "/api/install/binary":
            arch_out, _ = run_cmd("uname -m")
            arch = arch_out.strip()
            if "aarch64" in arch or "arm64" in arch:
                asset = "backhaul_linux_arm64.tar.gz"
            else:
                asset = "backhaul_linux_amd64.tar.gz"
            url = f"https://github.com/Musixal/Backhaul/releases/latest/download/{asset}"
            tmp_archive = f"/tmp/{asset}"
            os.makedirs(INSTALL_DIR, exist_ok=True)
            out1, c1 = run_cmd(f"wget -q -O {tmp_archive} '{url}' 2>&1 || curl -L -o {tmp_archive} '{url}' 2>&1", timeout=120)
            if c1 != 0:
                self.send_json({"success": False, "error": f"Download failed: {out1}"})
                return
            run_cmd(f"cp {BINARY} {BACKUP_DIR}/backhaul.bak.$(date +%Y%m%d-%H%M%S) 2>/dev/null")
            out2, c2 = run_cmd(f"tar -xzf {tmp_archive} -C /tmp/ 2>/dev/null", timeout=60)
            if c2 != 0:
                self.send_json({"success": False, "error": f"Extraction failed: {out2}"})
                return
            out3, c3 = run_cmd(f"cp /tmp/backhaul {BINARY} && chmod +x {BINARY}")
            run_cmd(f"rm -rf /tmp/backhaul /tmp/{asset}")
            ver = get_binary_version()
            self.send_json({"success": True, "version": ver})
            return

        self.send_json({"error": "not found"}, 404)


def get_login_page():
    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BackhaulManager - Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0a0e1a;min-height:100vh;display:flex;align-items:center;justify-content:center;color:#e0e0e0}
.login-container{background:linear-gradient(135deg,#111827 0%,#1a1f35 50%,#0f172a 100%);border:1px solid rgba(99,179,237,0.2);border-radius:20px;padding:48px 40px;width:420px;box-shadow:0 25px 60px rgba(0,0,0,0.5),0 0 40px rgba(59,130,246,0.1)}
.logo{text-align:center;margin-bottom:32px}
.logo h1{font-size:28px;font-weight:800;background:linear-gradient(135deg,#3b82f6,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:-0.5px}
.logo p{color:#64748b;font-size:13px;margin-top:6px}
.form-group{margin-bottom:20px}
.form-group label{display:block;font-size:13px;color:#94a3b8;margin-bottom:8px;font-weight:500}
.form-group input{width:100%;padding:14px 16px;background:#0f172a;border:1px solid #1e293b;border-radius:12px;color:#e2e8f0;font-size:15px;transition:all 0.3s;outline:none}
.form-group input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,0.15)}
.form-group input::placeholder{color:#475569}
.btn-login{width:100%;padding:14px;background:linear-gradient(135deg,#3b82f6,#2563eb);border:none;border-radius:12px;color:white;font-size:15px;font-weight:600;cursor:pointer;transition:all 0.3s;margin-top:8px}
.btn-login:hover{transform:translateY(-2px);box-shadow:0 8px 25px rgba(59,130,246,0.35)}
.btn-login:active{transform:translateY(0)}
.error-msg{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:10px;padding:12px;color:#f87171;font-size:13px;text-align:center;display:none;margin-bottom:16px}
.footer{text-align:center;margin-top:24px;color:#475569;font-size:12px}
</style>
</head>
<body>
<div class="login-container">
<div class="logo">
<h1>BACKHAUL</h1>
<p>Web Panel Manager v1.2.0</p>
</div>
<div class="error-msg" id="error"></div>
<form onsubmit="doLogin(event)">
<div class="form-group">
<label>Username</label>
<input type="text" id="username" placeholder="Enter username" autocomplete="username" required>
</div>
<div class="form-group">
<label>Password</label>
<input type="password" id="password" placeholder="Enter password" autocomplete="current-password" required>
</div>
<button type="submit" class="btn-login">Sign In</button>
</form>
<div class="footer">emad1381</div>
</div>
<script>
async function doLogin(e){
e.preventDefault();
const u=document.getElementById("username").value;
const p=document.getElementById("password").value;
const r=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});
const d=await r.json();
if(d.success){window.location.href="/"}
else{const er=document.getElementById("error");er.textContent=d.error||"Invalid credentials";er.style.display="block"}
}
</script>
</body>
</html>'''


def get_main_page():
    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BackhaulManager - Panel</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0e1a;--card:#111827;--card2:#1a2035;--border:#1e293b;--blue:#3b82f6;--cyan:#06b6d4;--green:#10b981;--yellow:#f59e0b;--red:#ef4444;--purple:#8b5cf6;--text:#e2e8f0;--text2:#94a3b8;--text3:#64748b}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.topbar{background:linear-gradient(90deg,#0f172a,#1a1f35);border-bottom:1px solid var(--border);padding:14px 28px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;backdrop-filter:blur(10px)}
.topbar-left{display:flex;align-items:center;gap:14px}
.topbar-logo{font-size:20px;font-weight:800;background:linear-gradient(135deg,var(--blue),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.topbar-badge{background:rgba(59,130,246,0.15);border:1px solid rgba(59,130,246,0.3);border-radius:20px;padding:3px 10px;font-size:11px;color:var(--blue)}
.topbar-right{display:flex;align-items:center;gap:16px}
.topbar-info{font-size:12px;color:var(--text3)}
.topbar-info span{color:var(--cyan);font-weight:600}
.btn-logout{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:8px;padding:7px 14px;color:var(--red);font-size:12px;cursor:pointer;transition:all 0.2s}
.btn-logout:hover{background:rgba(239,68,68,0.2)}
.container{max-width:1200px;margin:0 auto;padding:24px}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat-card{background:linear-gradient(135deg,var(--card),var(--card2));border:1px solid var(--border);border-radius:14px;padding:20px;transition:all 0.3s}
.stat-card:hover{border-color:rgba(59,130,246,0.3);transform:translateY(-2px)}
.stat-card .label{font-size:12px;color:var(--text3);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px}
.stat-card .value{font-size:22px;font-weight:700}
.stat-card .value.blue{color:var(--blue)}
.stat-card .value.green{color:var(--green)}
.stat-card .value.cyan{color:var(--cyan)}
.stat-card .value.yellow{color:var(--yellow)}
.section{background:linear-gradient(135deg,var(--card),var(--card2));border:1px solid var(--border);border-radius:14px;margin-bottom:24px;overflow:hidden}
.section-header{padding:18px 22px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.section-header h2{font-size:16px;font-weight:600;display:flex;align-items:center;gap:10px}
.section-header h2 .icon{width:32px;height:32px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:16px}
.section-body{padding:20px 22px}
.tabs{display:flex;gap:4px;padding:4px;background:var(--bg);border-radius:10px;margin-bottom:20px}
.tab{padding:10px 20px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:500;color:var(--text3);transition:all 0.2s;border:none;background:transparent}
.tab:hover{color:var(--text2)}
.tab.active{background:var(--blue);color:white}
.tunnel-list{display:flex;flex-direction:column;gap:10px}
.tunnel-item{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:16px 18px;display:flex;align-items:center;justify-content:space-between;transition:all 0.2s}
.tunnel-item:hover{border-color:rgba(59,130,246,0.3)}
.tunnel-left{display:flex;align-items:center;gap:14px}
.tunnel-status{width:10px;height:10px;border-radius:50%}
.tunnel-status.running{background:var(--green);box-shadow:0 0 8px rgba(16,185,129,0.5)}
.tunnel-status.stopped{background:var(--red);box-shadow:0 0 8px rgba(239,68,68,0.5)}
.tunnel-name{font-weight:600;font-size:14px}
.tunnel-meta{font-size:12px;color:var(--text3);margin-top:3px;display:flex;gap:12px}
.tunnel-meta span{display:flex;align-items:center;gap:4px}
.tunnel-actions{display:flex;gap:6px}
.tunnel-actions button{padding:7px 12px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text2);font-size:12px;cursor:pointer;transition:all 0.2s}
.tunnel-actions button:hover{border-color:var(--blue);color:var(--blue)}
.tunnel-actions button.start{border-color:rgba(16,185,129,0.3);color:var(--green)}
.tunnel-actions button.start:hover{background:rgba(16,185,129,0.1)}
.tunnel-actions button.stop{border-color:rgba(245,158,11,0.3);color:var(--yellow)}
.tunnel-actions button.stop:hover{background:rgba(245,158,11,0.1)}
.tunnel-actions button.restart{border-color:rgba(59,130,246,0.3);color:var(--blue)}
.tunnel-actions button.restart:hover{background:rgba(59,130,246,0.1)}
.tunnel-actions button.delete{border-color:rgba(239,68,68,0.3);color:var(--red)}
.tunnel-actions button.delete:hover{background:rgba(239,68,68,0.1)}
.modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);z-index:200;display:none;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal{background:linear-gradient(135deg,var(--card),var(--card2));border:1px solid var(--border);border-radius:16px;width:560px;max-height:85vh;overflow-y:auto;box-shadow:0 25px 60px rgba(0,0,0,0.5)}
.modal-header{padding:20px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.modal-header h3{font-size:17px;font-weight:600}
.modal-close{background:none;border:none;color:var(--text3);font-size:20px;cursor:pointer;padding:4px 8px;border-radius:6px;transition:all 0.2s}
.modal-close:hover{background:rgba(239,68,68,0.1);color:var(--red)}
.modal-body{padding:24px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:12px;color:var(--text2);margin-bottom:6px;font-weight:500}
.form-group input,.form-group select,.form-group textarea{width:100%;padding:11px 14px;background:var(--bg);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:14px;outline:none;transition:all 0.2s;font-family:inherit}
.form-group input:focus,.form-group select:focus,.form-group textarea:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(59,130,246,0.1)}
.form-group select{cursor:pointer;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center}
.form-group textarea{min-height:200px;resize:vertical;font-family:'Cascadia Code','Fira Code',monospace;font-size:13px;line-height:1.5}
.modal-footer{padding:16px 24px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:10px}
.btn{padding:10px 20px;border-radius:10px;font-size:13px;font-weight:500;cursor:pointer;transition:all 0.2s;border:none}
.btn-primary{background:linear-gradient(135deg,var(--blue),#2563eb);color:white}
.btn-primary:hover{box-shadow:0 6px 20px rgba(59,130,246,0.3);transform:translateY(-1px)}
.btn-secondary{background:var(--bg);border:1px solid var(--border);color:var(--text2)}
.btn-secondary:hover{border-color:var(--text3);color:var(--text)}
.btn-danger{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:var(--red)}
.btn-danger:hover{background:rgba(239,68,68,0.2)}
.logs-box{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:14px;font-family:'Cascadia Code','Fira Code',monospace;font-size:12px;line-height:1.6;max-height:400px;overflow-y:auto;color:var(--text2);white-space:pre-wrap;word-break:break-all}
.toast{position:fixed;bottom:24px;right:24px;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 20px;font-size:13px;z-index:300;transform:translateY(100px);opacity:0;transition:all 0.3s;box-shadow:0 10px 30px rgba(0,0,0,0.3)}
.toast.show{transform:translateY(0);opacity:1}
.toast.success{border-color:rgba(16,185,129,0.4);color:var(--green)}
.toast.error{border-color:rgba(239,68,68,0.4);color:var(--red)}
.toast.info{border-color:rgba(59,130,246,0.4);color:var(--blue)}
.empty{text-align:center;padding:40px;color:var(--text3)}
.empty .icon{font-size:40px;margin-bottom:12px}
.empty p{font-size:14px}
.cron-badge{background:rgba(139,92,246,0.15);border:1px solid rgba(139,92,246,0.3);border-radius:6px;padding:2px 8px;font-size:10px;color:var(--purple);margin-left:8px}
.cron-select{display:flex;gap:8px;flex-wrap:wrap}
.cron-option{padding:8px 16px;border:1px solid var(--border);border-radius:8px;cursor:pointer;font-size:13px;transition:all 0.2s;background:var(--bg);color:var(--text2)}
.cron-option:hover{border-color:var(--purple);color:var(--purple)}
.cron-option.active{background:rgba(139,92,246,0.15);border-color:var(--purple);color:var(--purple)}
@media(max-width:768px){.stats-grid{grid-template-columns:repeat(2,1fr)}.form-row{grid-template-columns:1fr}.tunnel-item{flex-direction:column;align-items:flex-start;gap:12px}.tunnel-actions{width:100%;justify-content:flex-end}}
</style>
</head>
<body>
<div class="topbar">
<div class="topbar-left">
<div class="topbar-logo">BACKHAUL</div>
<div class="topbar-badge">Web Panel v1.2.0</div>
</div>
<div class="topbar-right">
<div class="topbar-info">IP: <span id="sys-ip">...</span></div>
<div class="topbar-info">Role: <span id="sys-role">...</span></div>
<button class="btn-logout" onclick="doLogout()">Logout</button>
</div>
</div>

<div class="container">
<div class="stats-grid">
<div class="stat-card"><div class="label">Status</div><div class="value green" id="stat-status">...</div></div>
<div class="stat-card"><div class="label">Tunnels</div><div class="value blue" id="stat-tunnels">0</div></div>
<div class="stat-card"><div class="label">Binary</div><div class="value cyan" id="stat-version">...</div></div>
<div class="stat-card"><div class="label">Uptime</div><div class="value yellow" id="stat-uptime">...</div></div>
</div>

<div class="section">
<div class="section-header">
<h2><span class="icon" style="background:rgba(59,130,246,0.15)"> </span> Tunnels</h2>
<div style="display:flex;gap:8px">
<button class="btn btn-secondary" onclick="refreshTunnels()" style="font-size:12px;padding:7px 14px"> Refresh</button>
<button class="btn btn-primary" onclick="showCreateModal()" style="font-size:12px;padding:7px 14px">+ Create Tunnel</button>
<button class="btn btn-secondary" onclick="showInstallModal()" style="font-size:12px;padding:7px 14px"> Install Binary</button>
</div>
</div>
<div class="section-body">
<div class="tunnel-list" id="tunnel-list">
<div class="empty"><div class="icon"> </div><p>Loading...</p></div>
</div>
</div>
</div>
</div>

<div class="modal-overlay" id="modal-create">
<div class="modal">
<div class="modal-header"><h3>Create New Tunnel</h3><button class="modal-close" onclick="closeModal('modal-create')">&times;</button></div>
<div class="modal-body">
<div class="form-row">
<div class="form-group"><label>Role</label><select id="cr-role"><option value="iran">IRAN (Server)</option><option value="kharej">KHAREJ (Client)</option></select></div>
<div class="form-group"><label>Transport</label><select id="cr-transport"><option value="wssmux">WSSMUX (TLS)</option><option value="wsmux">WSMUX</option><option value="tcpmux">TCPMUX</option><option value="tcp">TCP</option></select></div>
</div>
<div class="form-row">
<div class="form-group"><label>Port</label><input id="cr-port" value="9743" placeholder="9743"></div>
<div class="form-group"><label>Token</label><input id="cr-token" placeholder="Auto-generated"><small style="color:var(--text3);font-size:11px">Leave empty for auto-generate</small></div>
</div>
<div class="form-group" id="cr-iranip-group"><label>Iran Server IP</label><input id="cr-iranip" placeholder="e.g. 1.2.3.4"></div>
<div class="form-group" id="cr-ports-group"><label>Port Forwarding (Iran only)</label><textarea id="cr-ports" placeholder="443=127.0.0.1:443&#10;9191=127.0.0.1:9191"></textarea><small style="color:var(--text3);font-size:11px">Format: listen_port=target_ip:target_port (one per line)</small></div>
</div>
<div class="modal-footer">
<button class="btn btn-secondary" onclick="closeModal('modal-create')">Cancel</button>
<button class="btn btn-primary" onclick="doCreate()">Create Tunnel</button>
</div>
</div>
</div>

<div class="modal-overlay" id="modal-logs">
<div class="modal" style="width:700px">
<div class="modal-header"><h3>Logs</h3><button class="modal-close" onclick="closeModal('modal-logs')">&times;</button></div>
<div class="modal-body"><div class="logs-box" id="logs-content">Loading...</div></div>
<div class="modal-footer"><button class="btn btn-secondary" onclick="closeModal('modal-logs')">Close</button></div>
</div>
</div>

<div class="modal-overlay" id="modal-config">
<div class="modal" style="width:700px">
<div class="modal-header"><h3>Edit Config</h3><button class="modal-close" onclick="closeModal('modal-config')">&times;</button></div>
<div class="modal-body"><div class="form-group"><textarea id="config-content" style="min-height:350px"></textarea></div></div>
<div class="modal-footer">
<button class="btn btn-secondary" onclick="closeModal('modal-config')">Cancel</button>
<button class="btn btn-primary" onclick="doSaveConfig()">Save & Restart</button>
</div>
</div>
</div>

<div class="modal-overlay" id="modal-cron">
<div class="modal" style="width:440px">
<div class="modal-header"><h3>Schedule Auto-Restart</h3><button class="modal-close" onclick="closeModal('modal-cron')">&times;</button></div>
<div class="modal-body">
<p style="font-size:13px;color:var(--text2);margin-bottom:16px">Select restart interval for <strong id="cron-svc-name"></strong>:</p>
<div class="cron-select" id="cron-options">
<div class="cron-option" data-min="30">30 min</div>
<div class="cron-option" data-min="60">1 hour</div>
<div class="cron-option" data-min="120">2 hours</div>
<div class="cron-option" data-min="360">6 hours</div>
<div class="cron-option" data-min="720">12 hours</div>
</div>
<p style="font-size:12px;color:var(--text3);margin-top:14px">The tunnel will briefly disconnect during restart.</p>
</div>
<div class="modal-footer">
<button class="btn btn-danger" onclick="doRemoveCron()" id="btn-remove-cron" style="margin-right:auto;display:none">Disable</button>
<button class="btn btn-secondary" onclick="closeModal('modal-cron')">Cancel</button>
<button class="btn btn-primary" onclick="doSetCron()">Apply</button>
</div>
</div>
</div>

<div class="modal-overlay" id="modal-install">
<div class="modal" style="width:440px">
<div class="modal-header"><h3>Install / Update Binary</h3><button class="modal-close" onclick="closeModal('modal-install')">&times;</button></div>
<div class="modal-body">
<p style="font-size:13px;color:var(--text2);margin-bottom:10px">Download and install the latest Backhaul binary from GitHub.</p>
<div id="install-progress" style="display:none;text-align:center;padding:20px">
<div style="font-size:14px;color:var(--blue);margin-bottom:8px">Installing...</div>
<div style="font-size:12px;color:var(--text3)">Please wait, this may take a minute.</div>
</div>
</div>
<div class="modal-footer">
<button class="btn btn-secondary" onclick="closeModal('modal-install')">Cancel</button>
<button class="btn btn-primary" onclick="doInstall()" id="btn-install">Install Now</button>
</div>
</div>
</div>

<div class="toast" id="toast"></div>

<script>
let currentCronSvc="";
let currentConfigSvc="";

function showToast(msg,type="info"){
const t=document.getElementById("toast");
t.textContent=msg;
t.className="toast "+type+" show";
setTimeout(()=>t.classList.remove("show"),3500);
}

function closeModal(id){document.getElementById(id).classList.remove("show")}

async function api(url,body){
const opts=body?{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}:{};
const r=await fetch(url,opts);
if(r.status===401){window.location.href="/login.html";return null}
return r.json();
}

async function doLogout(){
await api("/api/auth/logout");
window.location.href="/login.html";
}

async function loadSystem(){
const d=await api("/api/system");
if(!d)return;
document.getElementById("sys-ip").textContent=d.ip;
document.getElementById("sys-role").textContent=d.role.toUpperCase();
document.getElementById("stat-status").textContent=d.role.toUpperCase();
document.getElementById("stat-version").textContent=d.version;
document.getElementById("stat-uptime").textContent=d.uptime||"—";
}

async function refreshTunnels(){
const d=await api("/api/tunnels");
if(!d)return;
const list=document.getElementById("tunnel-list");
const tunnels=d.tunnels||[];
document.getElementById("stat-tunnels").textContent=tunnels.length;
if(tunnels.length===0){
list.innerHTML='<div class="empty"><div class="icon"> </div><p>No tunnels found. Create one to get started.</p></div>';
return;
}
list.innerHTML=tunnels.map(t=>{
const statusClass=t.status==="running"?"running":"stopped";
const statusText=t.status==="running"?"RUNNING":"STOPPED";
const cronBadge=t.cron_active?`<span class="cron-badge">  ${t.cron_interval}m</span>`:"";
return `
<div class="tunnel-item">
<div class="tunnel-left">
<div class="tunnel-status ${statusClass}"></div>
<div>
<div class="tunnel-name">${t.service}${cronBadge}</div>
<div class="tunnel-meta">
<span> ${t.transport.toUpperCase()}</span>
<span> ${t.bind_addr}</span>
<span>  ${t.cpu}%</span>
<span>  ${t.memory}</span>
<span> ⏱ ${t.uptime}</span>
</div>
</div>
</div>
<div class="tunnel-actions">
<button class="start" onclick="tunnelAction('start','${t.service}')" title="Start">▶</button>
<button class="stop" onclick="tunnelAction('stop','${t.service}')" title="Stop">⏹</button>
<button class="restart" onclick="tunnelAction('restart','${t.service}')" title="Restart">🔄</button>
<button onclick="showLogs('${t.service}')" title="Logs"> </button>
<button onclick="showConfig('${t.service}')" title="Config">✏️</button>
<button onclick="showCron('${t.service}',${t.cron_active},'${t.cron_interval}')" title="Auto-Restart"></button>
<button class="delete" onclick="doDelete('${t.service}')" title="Delete">🗑</button>
</div>
</div>`;
}).join("");
}

async function tunnelAction(action,svc){
showToast(action.charAt(0).toUpperCase()+action.slice(1)+"ing "+svc+"...","info");
await api("/api/tunnel/"+action,{service:svc});
setTimeout(()=>{refreshTunnels();showToast(svc+" "+action+"ed","success")},1500);
}

async function doDelete(svc){
if(!confirm("Delete "+svc+"? This will also remove its config file."))return;
await api("/api/tunnel/delete",{service:svc});
showToast(svc+" deleted","success");
refreshTunnels();
}

function showCreateModal(){
document.getElementById("modal-create").classList.add("show");
}

document.getElementById("cr-role").onchange=function(){
const iran=document.getElementById("cr-iranip-group");
const ports=document.getElementById("cr-ports-group");
if(this.value==="iran"){iran.style.display="none";ports.style.display="block"}
else{iran.style.display="block";ports.style.display="none"}
};
document.getElementById("cr-role").onchange();

document.getElementById("cr-transport").onchange=function(){
const defaults={"tcp":"8443","tcpmux":"9443","wsmux":"9643","wssmux":"9743"};
document.getElementById("cr-port").value=defaults[this.value]||"9743";
};
document.getElementById("cr-transport").onchange();

async function doCreate(){
const portsRaw=document.getElementById("cr-ports").value.trim();
let portsArr=[];
if(portsRaw){
portsArr=portsRaw.split("\\n").filter(l=>l.trim()).map(l=>{
l=l.trim();
if(/^\\d+$/.test(l))return l+"=127.0.0.1:"+l;
return l;
});
}
const params={
role:document.getElementById("cr-role").value,
transport:document.getElementById("cr-transport").value,
port:document.getElementById("cr-port").value,
token:document.getElementById("cr-token").value,
iran_ip:document.getElementById("cr-iranip").value,
ports:portsArr.map(p=>'"'+p+'"').join(",")
};
showToast("Creating tunnel...","info");
const r=await api("/api/tunnel/create",params);
if(r&&r.success){
showToast("Tunnel created: "+r.service,"success");
closeModal("modal-create");
refreshTunnels();
}else{
showToast("Failed to create tunnel","error");
}
}

async function showLogs(svc){
document.getElementById("modal-logs").classList.add("show");
document.getElementById("logs-content").textContent="Loading logs...";
const d=await api("/api/tunnel/logs?svc="+encodeURIComponent(svc)+"&lines=200");
if(d)document.getElementById("logs-content").textContent=d.logs||"No logs found.";
}

async function showConfig(svc){
document.getElementById("modal-config").classList.add("show");
currentConfigSvc=svc;
const d=await api("/api/tunnel/config?svc="+encodeURIComponent(svc));
if(d)document.getElementById("config-content").value=d.config||"";
}

async function doSaveConfig(){
showToast("Saving config and restarting...","info");
await api("/api/tunnel/save_config",{service:currentConfigSvc,config:document.getElementById("config-content").value});
closeModal("modal-config");
showToast("Config saved & service restarted","success");
refreshTunnels();
}

function showCron(svc,active,interval){
currentCronSvc=svc;
document.getElementById("modal-cron").classList.add("show");
document.getElementById("cron-svc-name").textContent=svc;
document.getElementById("btn-remove-cron").style.display=active?"inline-block":"none";
document.querySelectorAll(".cron-option").forEach(o=>{
o.classList.toggle("active",active&&o.dataset.min===String(interval));
});
}

document.querySelectorAll(".cron-option").forEach(o=>{
o.onclick=function(){
document.querySelectorAll(".cron-option").forEach(x=>x.classList.remove("active"));
this.classList.add("active");
};
});

async function doSetCron(){
const active=document.querySelector(".cron-option.active");
if(!active){showToast("Select an interval first","error");return}
const min=parseInt(active.dataset.min);
showToast("Setting auto-restart to every "+min+" min...","info");
await api("/api/tunnel/cron",{service:currentCronSvc,interval:min,action:"set"});
closeModal("modal-cron");
showToast("Auto-restart enabled","success");
refreshTunnels();
}

async function doRemoveCron(){
showToast("Removing auto-restart...","info");
await api("/api/tunnel/cron",{service:currentCronSvc,action:"remove"});
closeModal("modal-cron");
showToast("Auto-restart disabled","success");
refreshTunnels();
}

function showInstallModal(){
document.getElementById("modal-install").classList.add("show");
document.getElementById("install-progress").style.display="none";
document.getElementById("btn-install").style.display="inline-block";
}

async function doInstall(){
document.getElementById("install-progress").style.display="block";
document.getElementById("btn-install").style.display="none";
showToast("Installing binary...","info");
const r=await api("/api/install/binary");
if(r&&r.success){
showToast("Installed: "+r.version,"success");
closeModal("modal-install");
loadSystem();
}else{
showToast("Install failed: "+(r?r.error:"unknown"),"error");
closeModal("modal-install");
}
}

loadSystem();
refreshTunnels();
setInterval(()=>{loadSystem();refreshTunnels()},15000);

document.querySelectorAll(".modal-overlay").forEach(m=>{
m.addEventListener("click",function(e){if(e.target===this)this.classList.remove("show")});
});
</script>
</body>
</html>'''


if __name__ == "__main__":
    os.makedirs(INSTALL_DIR, exist_ok=True)
    os.makedirs(CRON_CONFIG_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)

    server = http.server.HTTPServer(("0.0.0.0", PORT), PanelHandler)
    print(f"")
    print(f"  BackhaulManager Web Panel v1.2.0")
    print(f"  by emad1381")
    print(f"")
    print(f"  URL:      http://{get_local_ip()}:{PORT}")
    print(f"  Login:    {ADMIN_USER} / {ADMIN_PASS}")
    print(f"")
    print(f"  Press Ctrl+C to stop")
    print(f"")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.server_close()
