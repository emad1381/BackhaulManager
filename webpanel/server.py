#!/usr/bin/env python3
"""
BackhaulManager Web Panel - Multi-Server Edition
Version: 2.3.0
Author: emad1381
Manages Iran + Kharej servers from one panel via SSH.
"""

import http.server
import json
import os
import subprocess
import sys
import time
import urllib.parse
from http.cookies import SimpleCookie
import secrets
import socket

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

sessions = {}

def run_cmd(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "Command timed out", 1
    except Exception as e:
        return str(e), 1

def run_ssh(host, user, key_file, cmd, timeout=30, password="", port=22):
    ssh_opts = f"-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes -p {port}"
    if password:
        full_cmd = f'sshpass -p "{password}" ssh {ssh_opts} {user}@{host} "{cmd}"'
    else:
        key_opt = f"-i {key_file}" if key_file else ""
        full_cmd = f"ssh {ssh_opts} {key_opt} {user}@{host} '{cmd}'"
    return run_cmd(full_cmd, timeout)

def get_local_ip():
    out, _ = run_cmd("hostname -I 2>/dev/null | awk '{print $1}'")
    return out if out else "unknown"

def get_server_role(host=None, user=None, key_file=None, password="", port=22):
    if host and host != "127.0.0.1" and host != "localhost":
        out, _ = run_ssh(host, user, key_file, "systemctl list-units --type=service --state=running 2>/dev/null | grep -q 'backhaul-iran' && echo iran || (systemctl list-units --type=service --state=running 2>/dev/null | grep -q 'backhaul-kharej' && echo kharej || echo unknown)", password=password, port=port)
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

def get_binary_version(host=None, user=None, key_file=None, password="", port=22):
    if host and host != "127.0.0.1" and host != "localhost":
        out, _ = run_ssh(host, user, key_file, f"{BINARY} --version 2>/dev/null | head -1", password=password, port=port)
    else:
        out, _ = run_cmd(f"{BINARY} --version 2>/dev/null | head -1")
    return out if out else "not installed"

def get_server_info(srv):
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
        hostname_out, _ = run_ssh(host, user, key, "hostname", password=password, port=port)
        version = get_binary_version(host, user, key, password=password, port=port)
        role_actual = get_server_role(host, user, key, password=password, port=port)
        kernel, _ = run_ssh(host, user, key, "uname -r", password=password, port=port)
        load, _ = run_ssh(host, user, key, "cut -d' ' -f1-3 /proc/loadavg", password=password, port=port)
        mem, _ = run_ssh(host, user, key, "free -h | awk '/^Mem:/{print $3 \" used / \" $2}'", password=password, port=port)
        disk, _ = run_ssh(host, user, key, "df -h / | awk 'NR==2{print $3 \" used / \" $2}'", password=password, port=port)
        uptime_out, _ = run_ssh(host, user, key, "uptime -p", password=password, port=port)
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
    host = srv.get("ip", "127.0.0.1")
    user = srv.get("ssh_user", "root")
    key = srv.get("ssh_key", "")
    password = srv.get("ssh_password", "")
    port = srv.get("ssh_port", 22)
    is_local = host in ["127.0.0.1", "localhost", get_local_ip()]

    tunnels = []
    if is_local:
        out, _ = run_cmd("systemctl list-unit-files --type=service 2>/dev/null | grep -o 'backhaul[^ ]*\\.service' | sort -u")
    else:
        out, _ = run_ssh(host, user, key, "systemctl list-unit-files --type=service 2>/dev/null | grep -o 'backhaul[^ ]*\\.service' | sort -u", password=password, port=port)

    if not out:
        return tunnels

    for svc in out.split('\n'):
        svc = svc.strip()
        if not svc:
            continue

        if is_local:
            status_out, _ = run_cmd(f"systemctl is-active {svc} 2>/dev/null")
            pid_out, _ = run_cmd(f"systemctl show -p MainPID --value {svc} 2>/dev/null")
            cpu_out, _ = run_cmd(f"ps -p $(systemctl show -p MainPID --value {svc} 2>/dev/null) -o %cpu= 2>/dev/null") if pid_out.strip() not in ["0", ""] else ("", 1)
            mem_out, _ = run_cmd(f"ps -p $(systemctl show -p MainPID --value {svc} 2>/dev/null) -o rss= 2>/dev/null") if pid_out.strip() not in ["0", ""] else ("", 1)
            up_out, _ = run_cmd(f"ps -p $(systemctl show -p MainPID --value {svc} 2>/dev/null) -o etime= 2>/dev/null") if pid_out.strip() not in ["0", ""] else ("", 1)
        else:
            status_out, _ = run_ssh(host, user, key, f"systemctl is-active {svc} 2>/dev/null", password=password, port=port)
            pid_out, _ = run_ssh(host, user, key, f"systemctl show -p MainPID --value {svc} 2>/dev/null", password=password, port=port)
            cpu_out, _ = run_ssh(host, user, key, f"ps -p $(systemctl show -p MainPID --value {svc} 2>/dev/null) -o %cpu= 2>/dev/null", password=password, port=port) if pid_out.strip() not in ["0", ""] else ("", 1)
            mem_out, _ = run_ssh(host, user, key, f"ps -p $(systemctl show -p MainPID --value {svc} 2>/dev/null) -o rss= 2>/dev/null", password=password, port=port) if pid_out.strip() not in ["0", ""] else ("", 1)
            up_out, _ = run_ssh(host, user, key, f"ps -p $(systemctl show -p MainPID --value {svc} 2>/dev/null) -o etime= 2>/dev/null", password=password, port=port) if pid_out.strip() not in ["0", ""] else ("", 1)

        cpu = cpu_out.strip() if cpu_out else "—"
        try:
            mem_val = int(mem_out.strip()) if mem_out.strip() else 0
            mem = f"{mem_val/1024:.1f}M"
        except:
            mem = "—"
        uptime_s = up_out.strip() if up_out else "—"

        transport, bind_addr = "?", "?"
        config_name = svc.replace("backhaul-", "").replace(".service", "")
        config_path = f"{INSTALL_DIR}/{config_name}.toml"

        if is_local:
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
        else:
            cfg_out, _ = run_ssh(host, user, key, f"cat {config_path} 2>/dev/null", password=password, port=port)
            if cfg_out:
                for line in cfg_out.split('\n'):
                    if 'transport' in line and '=' in line:
                        transport = line.split('"')[1] if '"' in line else line.split('=')[1].strip()
                    if 'bind_addr' in line or 'remote_addr' in line:
                        bind_addr = line.split('"')[1] if '"' in line else line.split('=')[1].strip()

        cron_active = False
        cron_interval = ""
        cron_conf = f"{CRON_CONFIG_DIR}/{svc}.conf"
        if is_local:
            if os.path.exists(cron_conf):
                try:
                    with open(cron_conf) as f:
                        for line in f:
                            if line.startswith("INTERVAL="):
                                cron_interval = line.strip().split("=", 1)[1]
                                cron_active = True
                except:
                    pass
        else:
            cron_out, _ = run_ssh(host, user, key, f"cat {cron_conf} 2>/dev/null | grep INTERVAL", password=password, port=port)
            if cron_out:
                cron_interval = cron_out.split("=")[1].strip() if "=" in cron_out else ""
                cron_active = bool(cron_interval)

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
            "cron_interval": cron_interval
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
    return run_ssh(host, user, key, cmd, timeout, password=password, port=port)

def create_tunnel_on_server(srv, params):
    role = params.get("role", srv.get("role", "iran"))
    transport = params.get("transport", "wssmux")
    port = params.get("port", "9743")
    token = params.get("token", "")
    iran_ip = params.get("iran_ip", "")
    ports_mapping = params.get("ports", "")

    if not token:
        tok_out, _ = remote_exec(srv, "cat /proc/sys/kernel/random/uuid 2>/dev/null || head -c 32 /dev/urandom | base64")
        token = tok_out[:36] if tok_out else secrets.token_hex(16)

    svc_name = f"backhaul-{role}-{transport}-{port}"
    config_file = f"{INSTALL_DIR}/{role}-{transport}-{port}.toml"
    service_file = f"{SERVICE_DIR}/{svc_name}.service"

    remote_exec(srv, f"mkdir -p {INSTALL_DIR} {BACKUP_DIR}")

    if transport == "wssmux":
        remote_exec(srv, f"mkdir -p {CERT_DIR}")
        cert_check, _ = remote_exec(srv, f"test -f {CERT_DIR}/wssmux.crt && echo ok")
        if cert_check != "ok":
            remote_exec(srv, f'openssl req -x509 -newkey rsa:2048 -keyout {CERT_DIR}/wssmux.key -out {CERT_DIR}/wssmux.crt -days 3650 -nodes -subj "/CN=backhaul-wssmux" 2>/dev/null')

    remote_exec(srv, f"test -f {config_file} && cp {config_file} {BACKUP_DIR}/$(basename {config_file}).bak.$(date +%Y%m%d-%H%M%S) 2>/dev/null")

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
            "keepalive_period = 75",
            "nodelay = true",
            "heartbeat = 40",
            "channel_size = 4096",
        ])
        if transport != "tcp":
            config_lines.extend(["mux_con = 8", "mux_version = 1", "mux_framesize = 32768", "mux_recievebuffer = 4194304", "mux_streambuffer = 65536"])
        if transport == "wssmux":
            config_lines.extend([f'tls_cert = "{CERT_DIR}/wssmux.crt"', f'tls_key = "{CERT_DIR}/wssmux.key"'])
        config_lines.extend(["sniffer = false", "web_port = 0", 'log_level = "info"'])
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
            "connection_pool = 8",
            "aggressive_pool = false",
            "keepalive_period = 75",
            "nodelay = true",
            "retry_interval = 3",
            "dial_timeout = 10",
        ])
        if transport != "tcp":
            config_lines.extend(["mux_version = 1", "mux_framesize = 32768", "mux_recievebuffer = 4194304", "mux_streambuffer = 65536"])
        config_lines.extend(["sniffer = false", "web_port = 0", 'log_level = "info"'])

    config_content = "\n".join(config_lines) + "\n"

    is_local = srv.get("ip", "") in ["127.0.0.1", "localhost", get_local_ip()]
    if is_local:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        with open(config_file, 'w') as f:
            f.write(config_content)
    else:
        host = srv["ip"]
        user = srv.get("ssh_user", "root")
        key = srv.get("ssh_key", "")
        password = srv.get("ssh_password", "")
        ssh_port = srv.get("ssh_port", 22)
        escaped = config_content.replace("'", "'\\''")
        run_ssh(host, user, key, f"mkdir -p {INSTALL_DIR} && cat > {config_file} << 'ENDOFFILE'\n{config_content}ENDOFFILE", password=password, port=ssh_port)

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
        with open(service_file, 'w') as f:
            f.write(service_content)
    else:
        host = srv["ip"]
        user = srv.get("ssh_user", "root")
        key = srv.get("ssh_key", "")
        password = srv.get("ssh_password", "")
        ssh_port = srv.get("ssh_port", 22)
        run_ssh(host, user, key, f"cat > {service_file} << 'ENDOFFILE'\n{service_content}ENDOFFILE", password=password, port=ssh_port)

    remote_exec(srv, "systemctl daemon-reload")
    remote_exec(srv, f"systemctl enable {svc_name} 2>/dev/null")
    remote_exec(srv, f"systemctl restart {svc_name}")

    time.sleep(2)
    status_out, _ = remote_exec(srv, f"systemctl is-active {svc_name} 2>/dev/null")

    return {
        "success": status_out.strip() == "active",
        "service": svc_name,
        "token": token,
        "port": port,
        "transport": transport,
        "role": role,
        "server": srv.get("name", "")
    }


class ReuseAddrHTTPServer(http.server.HTTPServer):
    allow_reuse_address = True
    allow_reuse_port = True

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        super().server_bind()


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

        if path == "/api/servers":
            data = load_servers()
            result = []
            for srv in data.get("servers", []):
                info = get_server_info(srv)
                result.append(info)
            self.send_json({"servers": result})
            return

        if path == "/api/servers/raw":
            self.send_json(load_servers())
            return

        if path == "/api/tunnels":
            data = load_servers()
            all_tunnels = []
            for srv in data.get("servers", []):
                tunnels = get_tunnels_from_server(srv)
                all_tunnels.extend(tunnels)
            self.send_json({"tunnels": all_tunnels})
            return

        if path == "/api/tunnel/logs":
            params = urllib.parse.parse_qs(parsed.query)
            svc = params.get("svc", [""])[0]
            server_id = params.get("server_id", [""])[0]
            lines = params.get("lines", ["100"])[0]
            if svc:
                data = load_servers()
                srv = next((s for s in data.get("servers", []) if s.get("id") == server_id), None)
                if srv:
                    out, _ = remote_exec(srv, f"journalctl -u {svc} -n {lines} --no-pager 2>/dev/null")
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
                self.send_header("Set-Cookie", f"session={sid}; Path=/; HttpOnly; SameSite=Lax")
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
                out, code = run_cmd("hostname && echo 'SSH_OK'")
                self.send_json({"success": code == 0, "output": out})
            else:
                out, code = run_ssh(host, user, key, "hostname && echo SSH_OK", timeout=10, password=password, port=port)
                self.send_json({"success": "SSH_OK" in out, "output": out})
            return

        if path == "/api/tunnel/action":
            svc = data.get("service", "")
            action = data.get("action", "")
            server_id = data.get("server_id", "")
            if svc and action in ["start", "stop", "restart"]:
                data_servers = load_servers()
                srv = next((s for s in data_servers.get("servers", []) if s.get("id") == server_id), None)
                if srv:
                    out, code = remote_exec(srv, f"systemctl {action} {svc}")
                    self.send_json({"success": code == 0, "output": out})
                else:
                    self.send_json({"error": "server not found"}, 404)
            else:
                self.send_json({"error": "invalid params"}, 400)
            return

        if path == "/api/tunnel/delete":
            svc = data.get("service", "")
            server_id = data.get("server_id", "")
            if svc:
                data_servers = load_servers()
                srv = next((s for s in data_servers.get("servers", []) if s.get("id") == server_id), None)
                if srv:
                    remote_exec(srv, f"systemctl stop {svc} 2>/dev/null")
                    remote_exec(srv, f"systemctl disable {svc} 2>/dev/null")
                    config_name = svc.replace("backhaul-", "").replace(".service", "")
                    remote_exec(srv, f"cp {INSTALL_DIR}/{config_name}.toml {BACKUP_DIR}/ 2>/dev/null")
                    remote_exec(srv, f"rm -f {INSTALL_DIR}/{config_name}.toml {SERVICE_DIR}/{svc}")
                    remote_exec(srv, f"crontab -l 2>/dev/null | grep -v '{CRON_MARKER}.*{svc}' | crontab -")
                    remote_exec(srv, "systemctl daemon-reload")
                    self.send_json({"success": True})
                else:
                    self.send_json({"error": "server not found"}, 404)
            else:
                self.send_json({"error": "missing service"}, 400)
            return

        if path == "/api/tunnel/create":
            result = create_tunnel_on_server(data.get("server", {}), data)
            self.send_json(result)
            return

        if path == "/api/tunnel/create-both":
            iran_srv = data.get("iran_server", {})
            kharej_srv = data.get("kharej_server", {})
            transport = data.get("transport", "wssmux")
            port = data.get("port", "9743")
            token = data.get("token", "")
            ports_mapping = data.get("ports", "")

            if not token:
                tok_out, _ = run_cmd("cat /proc/sys/kernel/random/uuid 2>/dev/null")
                token = tok_out[:36] if tok_out else secrets.token_hex(16)

            kharej_ip = kharej_srv.get("ip", "")
            iran_ip = iran_srv.get("ip", "")

            if iran_ip in ["127.0.0.1", "localhost", ""]:
                iran_ip = get_local_ip()

            iran_result = create_tunnel_on_server(iran_srv, {
                "role": "iran", "transport": transport, "port": port,
                "token": token, "ports": ports_mapping
            })

            kharej_result = create_tunnel_on_server(kharej_srv, {
                "role": "kharej", "transport": transport, "port": port,
                "token": token, "iran_ip": iran_ip
            })

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
            data_servers = load_servers()
            srv = next((s for s in data_servers.get("servers", []) if s.get("id") == server_id), None)
            if not srv:
                self.send_json({"error": "server not found"}, 404)
                return
            if action == "remove":
                remote_exec(srv, f"crontab -l 2>/dev/null | grep -v '{CRON_MARKER}.*{svc}' | crontab -")
                remote_exec(srv, f"rm -f {CRON_CONFIG_DIR}/{svc}.conf")
            elif interval > 0:
                remote_exec(srv, f"mkdir -p {CRON_CONFIG_DIR}")
                remote_exec(srv, f"echo -e 'SERVICE={svc}\\nINTERVAL={interval}' > {CRON_CONFIG_DIR}/{svc}.conf")
                remote_exec(srv, f"crontab -l 2>/dev/null | grep -v '{CRON_MARKER}.*{svc}' > /tmp/cron_tmp; echo '*/{interval} * * * * systemctl restart {svc} {CRON_MARKER} {svc}' >> /tmp/cron_tmp; crontab /tmp/cron_tmp; rm -f /tmp/cron_tmp")
            self.send_json({"success": True})
            return

        if path == "/api/tunnel/save_config":
            svc = data.get("service", "")
            config = data.get("config", "")
            server_id = data.get("server_id", "")
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
                        run_ssh(host, srv.get("ssh_user", "root"), srv.get("ssh_key", ""), f"cat > {config_path} << 'ENDOFFILE'\n{config}ENDOFFILE", password=srv.get("ssh_password", ""), port=srv.get("ssh_port", 22))
                    remote_exec(srv, f"systemctl restart {svc}")
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
            url = f"https://github.com/Musixal/Backhaul/releases/latest/download/{asset}"
            remote_exec(srv, f"mkdir -p {INSTALL_DIR} {BACKUP_DIR}")
            remote_exec(srv, f"cp {BINARY} {BACKUP_DIR}/backhaul.bak.$(date +%Y%m%d-%H%M%S) 2>/dev/null")
            out1, c1 = remote_exec(srv, f"wget -q -O /tmp/{asset} '{url}' 2>/dev/null || curl -sL -o /tmp/{asset} '{url}' 2>/dev/null", timeout=120)
            if c1 != 0:
                self.send_json({"success": False, "error": f"Download failed: {out1}"})
                return
            out2, c2 = remote_exec(srv, f"tar -xzf /tmp/{asset} -C /tmp/ 2>/dev/null", timeout=60)
            remote_exec(srv, f"cp /tmp/backhaul {BINARY} && chmod +x {BINARY}")
            remote_exec(srv, f"rm -rf /tmp/backhaul /tmp/{asset}")
            ver = get_binary_version(srv.get("ip"), srv.get("ssh_user"), srv.get("ssh_key"))
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
.logo h1{font-size:32px;font-weight:800;background:linear-gradient(135deg,#3b82f6,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:-0.5px}
.logo p{color:#64748b;font-size:13px;margin-top:6px}
.form-group{margin-bottom:20px}
.form-group label{display:block;font-size:13px;color:#94a3b8;margin-bottom:8px;font-weight:500}
.form-group input{width:100%;padding:14px 16px;background:#0f172a;border:1px solid #1e293b;border-radius:12px;color:#e2e8f0;font-size:15px;transition:all 0.3s;outline:none}
.form-group input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,0.15)}
.form-group input::placeholder{color:#475569}
.btn-login{width:100%;padding:14px;background:linear-gradient(135deg,#3b82f6,#2563eb);border:none;border-radius:12px;color:white;font-size:15px;font-weight:600;cursor:pointer;transition:all 0.3s;margin-top:8px}
.btn-login:hover{transform:translateY(-2px);box-shadow:0 8px 25px rgba(59,130,246,0.35)}
.error-msg{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:10px;padding:12px;color:#f87171;font-size:13px;text-align:center;display:none;margin-bottom:16px}
.footer{text-align:center;margin-top:24px;color:#475569;font-size:12px}
</style>
</head>
<body>
<div class="login-container">
<div class="logo"><h1>BACKHAUL</h1><p>Multi-Server Panel v2.3.0</p></div>
<div class="error-msg" id="error"></div>
<form onsubmit="doLogin(event)">
<div class="form-group"><label>Username</label><input type="text" id="username" placeholder="admin" autocomplete="username" required></div>
<div class="form-group"><label>Password</label><input type="password" id="password" placeholder="admin" autocomplete="current-password" required></div>
<button type="submit" class="btn-login">Sign In</button>
</form>
<div class="footer">emad1381</div>
</div>
<script>
async function doLogin(e){e.preventDefault();const u=document.getElementById("username").value;const p=document.getElementById("password").value;const r=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});const d=await r.json();if(d.success){window.location.href="/"}else{const er=document.getElementById("error");er.textContent=d.error||"Invalid credentials";er.style.display="block"}}
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
.topbar{background:linear-gradient(90deg,#0f172a,#1a1f35);border-bottom:1px solid var(--border);padding:14px 28px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.topbar-left{display:flex;align-items:center;gap:14px}
.topbar-logo{font-size:22px;font-weight:800;background:linear-gradient(135deg,var(--blue),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.topbar-badge{background:rgba(139,92,246,0.15);border:1px solid rgba(139,92,246,0.3);border-radius:20px;padding:3px 10px;font-size:11px;color:var(--purple)}
.topbar-right{display:flex;align-items:center;gap:16px}
.btn-logout{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:8px;padding:7px 14px;color:var(--red);font-size:12px;cursor:pointer;transition:all 0.2s}
.btn-logout:hover{background:rgba(239,68,68,0.2)}
.container{max-width:1400px;margin:0 auto;padding:24px}
.tabs{display:flex;gap:4px;padding:4px;background:var(--card);border-radius:12px;margin-bottom:24px;border:1px solid var(--border)}
.tab{padding:12px 24px;border-radius:10px;cursor:pointer;font-size:14px;font-weight:500;color:var(--text3);transition:all 0.2s;border:none;background:transparent}
.tab:hover{color:var(--text2)}
.tab.active{background:var(--blue);color:white}
.tab-content{display:none}.tab-content.active{display:block}
.server-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:16px;margin-bottom:24px}
.server-card{background:linear-gradient(135deg,var(--card),var(--card2));border:1px solid var(--border);border-radius:16px;padding:22px;transition:all 0.3s;position:relative;overflow:hidden}
.server-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px}
.server-card.iran::before{background:linear-gradient(90deg,var(--green),var(--cyan))}
.server-card.kharej::before{background:linear-gradient(90deg,var(--blue),var(--purple))}
.server-card:hover{border-color:rgba(59,130,246,0.3);transform:translateY(-2px)}
.server-card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.server-card-title{display:flex;align-items:center;gap:10px}
.server-card-title h3{font-size:16px;font-weight:600}
.role-badge{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;text-transform:uppercase}
.role-badge.iran{background:rgba(16,185,129,0.15);color:var(--green);border:1px solid rgba(16,185,129,0.3)}
.role-badge.kharej{background:rgba(59,130,246,0.15);color:var(--blue);border:1px solid rgba(59,130,246,0.3)}
.ssh-status{font-size:11px;display:flex;align-items:center;gap:4px}
.ssh-status .dot{width:8px;height:8px;border-radius:50%}
.ssh-status .dot.ok{background:var(--green)}
.ssh-status .dot.err{background:var(--red)}
.server-stats{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.server-stat{background:var(--bg);border-radius:10px;padding:10px 12px}
.server-stat .label{font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px}
.server-stat .value{font-size:14px;font-weight:600;margin-top:2px}
.server-card-actions{display:flex;gap:6px;margin-top:14px}
.server-card-actions button{flex:1;padding:8px;border-radius:8px;border:1px solid var(--border);background:var(--bg);color:var(--text2);font-size:12px;cursor:pointer;transition:all 0.2s}
.server-card-actions button:hover{border-color:var(--blue);color:var(--blue)}
.server-card-actions button.del{color:var(--red);border-color:rgba(239,68,68,0.3)}
.section{background:linear-gradient(135deg,var(--card),var(--card2));border:1px solid var(--border);border-radius:16px;margin-bottom:24px;overflow:hidden}
.section-header{padding:18px 22px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.section-header h2{font-size:16px;font-weight:600}
.section-body{padding:20px 22px}
.tunnel-list{display:flex;flex-direction:column;gap:10px}
.tunnel-item{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:16px 18px;display:flex;align-items:center;justify-content:space-between;transition:all 0.2s}
.tunnel-item:hover{border-color:rgba(59,130,246,0.3)}
.tunnel-left{display:flex;align-items:center;gap:14px}
.tunnel-status{width:10px;height:10px;border-radius:50%}
.tunnel-status.running{background:var(--green);box-shadow:0 0 8px rgba(16,185,129,0.5)}
.tunnel-status.stopped{background:var(--red);box-shadow:0 0 8px rgba(239,68,68,0.5)}
.tunnel-name{font-weight:600;font-size:14px}
.tunnel-meta{font-size:12px;color:var(--text3);margin-top:3px;display:flex;gap:12px;flex-wrap:wrap}
.tunnel-server-tag{background:rgba(139,92,246,0.1);border:1px solid rgba(139,92,246,0.2);border-radius:6px;padding:1px 8px;font-size:10px;color:var(--purple)}
.cron-badge{background:rgba(139,92,246,0.15);border:1px solid rgba(139,92,246,0.3);border-radius:6px;padding:2px 8px;font-size:10px;color:var(--purple)}
.tunnel-actions{display:flex;gap:5px}
.tunnel-actions button{padding:7px 10px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text2);font-size:12px;cursor:pointer;transition:all 0.2s}
.tunnel-actions button:hover{border-color:var(--blue);color:var(--blue)}
.tunnel-actions button.start{border-color:rgba(16,185,129,0.3);color:var(--green)}.tunnel-actions button.start:hover{background:rgba(16,185,129,0.1)}
.tunnel-actions button.stop{border-color:rgba(245,158,11,0.3);color:var(--yellow)}.tunnel-actions button.stop:hover{background:rgba(245,158,11,0.1)}
.tunnel-actions button.restart{border-color:rgba(59,130,246,0.3);color:var(--blue)}.tunnel-actions button.restart:hover{background:rgba(59,130,246,0.1)}
.tunnel-actions button.delete{border-color:rgba(239,68,68,0.3);color:var(--red)}.tunnel-actions button.delete:hover{background:rgba(239,68,68,0.1)}
.empty{text-align:center;padding:40px;color:var(--text3)}.empty .icon{font-size:40px;margin-bottom:12px}
.modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);z-index:200;display:none;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal{background:linear-gradient(135deg,var(--card),var(--card2));border:1px solid var(--border);border-radius:16px;width:600px;max-height:85vh;overflow-y:auto;box-shadow:0 25px 60px rgba(0,0,0,0.5)}
.modal-header{padding:20px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.modal-header h3{font-size:17px;font-weight:600}
.modal-close{background:none;border:none;color:var(--text3);font-size:20px;cursor:pointer;padding:4px 8px;border-radius:6px}
.modal-close:hover{background:rgba(239,68,68,0.1);color:var(--red)}
.modal-body{padding:24px}
.modal-footer{padding:16px 24px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:10px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:12px;color:var(--text2);margin-bottom:6px;font-weight:500}
.form-group input,.form-group select,.form-group textarea{width:100%;padding:11px 14px;background:var(--bg);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:14px;outline:none;transition:all 0.2s;font-family:inherit}
.form-group input:focus,.form-group select:focus,.form-group textarea:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(59,130,246,0.1)}
.form-group textarea{min-height:180px;resize:vertical;font-family:'Cascadia Code','Fira Code',monospace;font-size:13px;line-height:1.5}
.btn{padding:10px 20px;border-radius:10px;font-size:13px;font-weight:500;cursor:pointer;transition:all 0.2s;border:none}
.btn-primary{background:linear-gradient(135deg,var(--blue),#2563eb);color:white}.btn-primary:hover{box-shadow:0 6px 20px rgba(59,130,246,0.3)}
.btn-secondary{background:var(--bg);border:1px solid var(--border);color:var(--text2)}.btn-secondary:hover{border-color:var(--text3)}
.btn-danger{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:var(--red)}
.btn-success{background:linear-gradient(135deg,var(--green),#059669);color:white}.btn-success:hover{box-shadow:0 6px 20px rgba(16,185,129,0.3)}
.logs-box{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:14px;font-family:'Cascadia Code','Fira Code',monospace;font-size:12px;line-height:1.6;max-height:400px;overflow-y:auto;color:var(--text2);white-space:pre-wrap;word-break:break-all}
.toast{position:fixed;bottom:24px;right:24px;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 20px;font-size:13px;z-index:300;transform:translateY(100px);opacity:0;transition:all 0.3s;box-shadow:0 10px 30px rgba(0,0,0,0.3)}
.toast.show{transform:translateY(0);opacity:1}
.toast.success{border-color:rgba(16,185,129,0.4);color:var(--green)}
.toast.error{border-color:rgba(239,68,68,0.4);color:var(--red)}
.toast.info{border-color:rgba(59,130,246,0.4);color:var(--blue)}
.cron-select{display:flex;gap:8px;flex-wrap:wrap}
.cron-option{padding:8px 16px;border:1px solid var(--border);border-radius:8px;cursor:pointer;font-size:13px;transition:all 0.2s;background:var(--bg);color:var(--text2)}
.cron-option:hover{border-color:var(--purple);color:var(--purple)}
.cron-option.active{background:rgba(139,92,246,0.15);border-color:var(--purple);color:var(--purple)}
.wizard-steps{display:flex;gap:8px;margin-bottom:20px}
.wizard-step{flex:1;padding:10px;text-align:center;border-radius:10px;font-size:12px;font-weight:500;color:var(--text3);background:var(--bg);border:1px solid var(--border);transition:all 0.2s}
.wizard-step.active{color:var(--blue);border-color:var(--blue);background:rgba(59,130,246,0.05)}
.wizard-step.done{color:var(--green);border-color:var(--green);background:rgba(16,185,129,0.05)}
.wizard-page{display:none}.wizard-page.active{display:block}
.connection-line{display:flex;align-items:center;justify-content:center;gap:8px;padding:12px;margin:10px 0}
.connection-line .line{flex:1;height:2px;background:linear-gradient(90deg,var(--green),var(--blue))}
.connection-line .arrow{color:var(--cyan);font-size:20px}
.server-select-card{background:var(--bg);border:2px solid var(--border);border-radius:12px;padding:16px;cursor:pointer;transition:all 0.2s;text-align:center}
.server-select-card:hover{border-color:var(--blue)}
.server-select-card.selected{border-color:var(--green);background:rgba(16,185,129,0.05)}
.server-select-card h4{margin-bottom:4px}.server-select-card p{font-size:12px;color:var(--text3)}
@media(max-width:768px){.server-grid{grid-template-columns:1fr}.form-row{grid-template-columns:1fr}.tunnel-item{flex-direction:column;align-items:flex-start;gap:12px}}
</style>
</head>
<body>
<div class="topbar">
<div class="topbar-left">
<div class="topbar-logo">BACKHAUL</div>
<div class="topbar-badge">Multi-Server Panel v2.3.0</div>
</div>
<div class="topbar-right">
<button class="btn-logout" onclick="doLogout()">Logout</button>
</div>
</div>

<div class="container">
<div class="tabs">
<button class="tab active" onclick="switchTab('dashboard')">Dashboard</button>
<button class="tab" onclick="switchTab('servers')">Servers</button>
<button class="tab" onclick="switchTab('tunnels')">Tunnels</button>
<button class="tab" onclick="switchTab('create')">Create Tunnel</button>
</div>

<div class="tab-content active" id="tab-dashboard">
<div class="server-grid" id="server-grid">
<div class="empty"><div class="icon"> </div><p>Loading servers...</p></div>
</div>
<div class="section">
<div class="section-header"><h2>All Tunnels</h2><button class="btn btn-secondary" onclick="refreshAll()" style="font-size:12px;padding:7px 14px"> Refresh</button></div>
<div class="section-body"><div class="tunnel-list" id="dashboard-tunnels"><div class="empty"><p>No tunnels found.</p></div></div></div>
</div>
</div>

<div class="tab-content" id="tab-servers">
<div class="section">
<div class="section-header"><h2>Server Management</h2><button class="btn btn-primary" onclick="showAddServer()" style="font-size:12px;padding:7px 14px">+ Add Server</button></div>
<div class="section-body"><div class="server-grid" id="server-manage-grid"></div></div>
</div>
</div>

<div class="tab-content" id="tab-tunnels">
<div class="section">
<div class="section-header"><h2>All Tunnels</h2><button class="btn btn-secondary" onclick="refreshAll()" style="font-size:12px;padding:7px 14px"> Refresh</button></div>
<div class="section-body"><div class="tunnel-list" id="all-tunnels"><div class="empty"><p>No tunnels found.</p></div></div></div>
</div>
</div>

<div class="tab-content" id="tab-create">
<div class="section">
<div class="section-header"><h2>  Create Tunnel (Iran + Kharej)</h2></div>
<div class="section-body">
<div class="wizard-steps">
<div class="wizard-step active" id="ws1">1. Select Servers</div>
<div class="wizard-step" id="ws2">2. Configure</div>
<div class="wizard-step" id="ws3">3. Deploy</div>
</div>
<div class="wizard-page active" id="wp1">
<p style="font-size:13px;color:var(--text2);margin-bottom:16px">Select the Iran and Kharej servers to create a tunnel between them.</p>
<div style="display:grid;grid-template-columns:1fr 40px 1fr;gap:10px;align-items:center">
<div>
<div style="font-size:12px;color:var(--green);font-weight:600;margin-bottom:8px;text-align:center">IRAN (Server)</div>
<div id="iran-server-select"></div>
</div>
<div class="connection-line"><div class="line"></div><div class="arrow">⚡</div><div class="line"></div></div>
<div>
<div style="font-size:12px;color:var(--blue);font-weight:600;margin-bottom:8px;text-align:center">KHAREJ (Client)</div>
<div id="kharej-server-select"></div>
</div>
</div>
<div style="text-align:right;margin-top:20px"><button class="btn btn-primary" onclick="wizardNext(2)">Next →</button></div>
</div>
<div class="wizard-page" id="wp2">
<div class="form-row">
<div class="form-group"><label>Transport</label><select id="wiz-transport"><option value="wssmux">WSSMUX (TLS - Recommended)</option><option value="wsmux">WSMUX</option><option value="tcpmux">TCPMUX</option><option value="tcp">TCP</option></select></div>
<div class="form-group"><label>Port</label><input id="wiz-port" value="9743"></div>
</div>
<div class="form-row">
<div class="form-group"><label>Token</label><input id="wiz-token" placeholder="Auto-generated"><small style="color:var(--text3);font-size:11px">Leave empty for auto-generate</small></div>
<div class="form-group"><label>Listen Ports (Iran)</label><input id="wiz-ports" placeholder="443=127.0.0.1:443,9191=127.0.0.1:9191"><small style="color:var(--text3);font-size:11px">Comma separated: port=ip:port</small></div>
</div>
<div style="display:flex;justify-content:space-between;margin-top:20px">
<button class="btn btn-secondary" onclick="wizardNext(1)">← Back</button>
<button class="btn btn-primary" onclick="wizardNext(3)">Deploy Tunnel →</button>
</div>
</div>
<div class="wizard-page" id="wp3">
<div id="deploy-status" style="text-align:center;padding:20px">
<div style="font-size:18px;margin-bottom:12px">⏳</div>
<div style="font-size:14px;color:var(--text2)">Deploying tunnel on both servers...</div>
<div style="font-size:12px;color:var(--text3);margin-top:6px">This may take a few seconds.</div>
</div>
<div id="deploy-result" style="display:none"></div>
</div>
</div>
</div>
</div>
</div>

<div class="modal-overlay" id="modal-add-server">
<div class="modal">
<div class="modal-header"><h3 id="server-modal-title">Add Server</h3><button class="modal-close" onclick="closeModal('modal-add-server')">&times;</button></div>
<div class="modal-body">
<div class="form-group"><label>Server Name</label><input id="srv-name" placeholder="e.g. Iran Main"></div>
<div class="form-row">
<div class="form-group"><label>IP Address</label><input id="srv-ip" placeholder="1.2.3.4"></div>
<div class="form-group"><label>Role</label><select id="srv-role"><option value="iran">IRAN</option><option value="kharej">KHAREJ</option></select></div>
</div>
<div class="form-row">
<div class="form-group"><label>SSH User</label><input id="srv-ssh-user" value="root"></div>
<div class="form-group"><label>SSH Port</label><input id="srv-ssh-port" value="22" type="number"></div>
</div>
<div class="form-row">
<div class="form-group"><label>SSH Password</label><input id="srv-ssh-password" type="password" placeholder="Enter SSH password"></div>
<div class="form-group"><label>SSH Key Path (optional)</label><input id="srv-ssh-key" placeholder="/root/.ssh/id_rsa"><small style="color:var(--text3);font-size:11px">Leave empty for password auth</small></div>
</div>
</div>
<div class="modal-footer">
<button class="btn btn-secondary" onclick="closeModal('modal-add-server')">Cancel</button>
<button class="btn btn-primary" onclick="saveServer()">Save</button>
</div>
</div>
</div>

<div class="modal-overlay" id="modal-logs">
<div class="modal" style="width:700px"><div class="modal-header"><h3>Logs</h3><button class="modal-close" onclick="closeModal('modal-logs')">&times;</button></div><div class="modal-body"><div class="logs-box" id="logs-content">Loading...</div></div><div class="modal-footer"><button class="btn btn-secondary" onclick="closeModal('modal-logs')">Close</button></div></div>
</div>

<div class="modal-overlay" id="modal-config">
<div class="modal" style="width:700px"><div class="modal-header"><h3>Edit Config</h3><button class="modal-close" onclick="closeModal('modal-config')">&times;</button></div><div class="modal-body"><div class="form-group"><textarea id="config-content" style="min-height:300px"></textarea></div></div><div class="modal-footer"><button class="btn btn-secondary" onclick="closeModal('modal-config')">Cancel</button><button class="btn btn-primary" onclick="doSaveConfig()">Save & Restart</button></div></div>
</div>

<div class="modal-overlay" id="modal-cron">
<div class="modal" style="width:440px"><div class="modal-header"><h3>Auto-Restart</h3><button class="modal-close" onclick="closeModal('modal-cron')">&times;</button></div>
<div class="modal-body">
<p style="font-size:13px;color:var(--text2);margin-bottom:16px">Interval for <strong id="cron-svc-name"></strong>:</p>
<div class="cron-select" id="cron-options">
<div class="cron-option" data-min="30">30 min</div>
<div class="cron-option" data-min="60">1 hour</div>
<div class="cron-option" data-min="120">2 hours</div>
<div class="cron-option" data-min="360">6 hours</div>
</div>
</div>
<div class="modal-footer">
<button class="btn btn-danger" onclick="doRemoveCron()" id="btn-remove-cron" style="margin-right:auto;display:none">Disable</button>
<button class="btn btn-secondary" onclick="closeModal('modal-cron')">Cancel</button>
<button class="btn btn-primary" onclick="doSetCron()">Apply</button>
</div>
</div>
</div>

<div class="toast" id="toast"></div>

<script>
let servers=[];
let selectedIran="";
let selectedKharej="";
let editingServerId="";
let currentCronSvc="";
let currentCronServerId="";
let currentConfigSvc="";
let currentConfigServerId="";

function showToast(m,t="info"){const e=document.getElementById("toast");e.textContent=m;e.className="toast "+t+" show";setTimeout(()=>e.classList.remove("show"),3500)}
function closeModal(id){document.getElementById(id).classList.remove("show")}
function switchTab(name){document.querySelectorAll(".tab").forEach((t,i)=>t.classList.remove("active"));document.querySelectorAll(".tab-content").forEach(t=>t.classList.remove("active"));document.querySelectorAll(".tab").forEach(t=>{if(t.textContent.toLowerCase().includes(name)){t.classList.add("active")}});document.getElementById("tab-"+name).classList.add("active")}

async function api(url,body){const opts=body?{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}:{};const r=await fetch(url,opts);if(r.status===401){window.location.href="/login.html";return null}return r.json()}
async function doLogout(){await api("/api/auth/logout");window.location.href="/login.html"}

async function loadServers(){
const d=await api("/api/servers");
if(d&&d.servers){servers=d.servers;renderServerCards();renderServerManage();renderCreateWizard();renderDashboardTunnels()}
}

function renderServerCards(){
const g=document.getElementById("server-grid");
if(servers.length===0){g.innerHTML='<div class="empty"><div class="icon"> </div><p>No servers added yet. Go to Servers tab to add one.</p></div>';return}
g.innerHTML=servers.map(s=>{
const roleClass=s.role==="iran"?"iran":"kharej";
const sshDot=s.ssh_ok?"ok":"err";
const sshText=s.ssh_ok?"Connected":"Disconnected";
return `<div class="server-card ${roleClass}">
<div class="server-card-header">
<div class="server-card-title"><h3>${s.name}</h3><span class="role-badge ${roleClass}">${s.role}</span></div>
<div class="ssh-status"><span class="dot ${sshDot}"></span>${sshText}</div>
</div>
<div class="server-stats">
<div class="server-stat"><div class="label">IP</div><div class="value" style="color:var(--cyan)">${s.ip}</div></div>
<div class="server-stat"><div class="label">Binary</div><div class="value" style="font-size:12px">${s.version||"N/A"}</div></div>
<div class="server-stat"><div class="label">Memory</div><div class="value">${s.memory||"—"}</div></div>
<div class="server-stat"><div class="label">Disk</div><div class="value">${s.disk||"—"}</div></div>
</div>
</div>`}).join("");
}

function renderServerManage(){
const g=document.getElementById("server-manage-grid");
if(servers.length===0){g.innerHTML='<div class="empty"><p>No servers configured.</p></div>';return}
g.innerHTML=servers.map(s=>{
const roleClass=s.role==="iran"?"iran":"kharej";
return `<div class="server-card ${roleClass}">
<div class="server-card-header">
<div class="server-card-title"><h3>${s.name}</h3><span class="role-badge ${roleClass}">${s.role}</span></div>
</div>
<div class="server-stats">
<div class="server-stat"><div class="label">IP</div><div class="value" style="color:var(--cyan)">${s.ip}</div></div>
<div class="server-stat"><div class="label">SSH User</div><div class="value">${s.ssh_user}</div></div>
<div class="server-stat"><div class="label">SSH Port</div><div class="value">${s.ssh_port||22}</div></div>
<div class="server-stat"><div class="label">Auth</div><div class="value">${s.ssh_password?"Password":"Key"}</div></div>
</div>
<div class="server-card-actions">
<button onclick="installBinary('${s.id}')">Install Binary</button>
<button onclick="editServer('${s.id}')">Edit</button>
<button class="del" onclick="deleteServer('${s.id}','${s.name}')">Delete</button>
</div>
</div>`}).join("");
}

function renderCreateWizard(){
const iran=servers.filter(s=>s.role==="iran");
const kharej=servers.filter(s=>s.role==="kharej");
document.getElementById("iran-server-select").innerHTML=iran.length?iran.map(s=>`<div class="server-select-card ${selectedIran===s.id?"selected":""}" onclick="selectIran('${s.id}')"><h4>${s.name}</h4><p>${s.ip}</p></div>`).join(""):'<div style="text-align:center;color:var(--text3);font-size:12px;padding:20px">No Iran server added</div>';
document.getElementById("kharej-server-select").innerHTML=kharej.length?kharej.map(s=>`<div class="server-select-card ${selectedKharej===s.id?"selected":""}" onclick="selectKharej('${s.id}')"><h4>${s.name}</h4><p>${s.ip}</p></div>`).join(""):'<div style="text-align:center;color:var(--text3);font-size:12px;padding:20px">No Kharej server added</div>';
}

function renderDashboardTunnels(){
api("/api/tunnels").then(d=>{
if(!d)return;
const list=document.getElementById("dashboard-tunnels");
const tl=document.getElementById("all-tunnels");
const tunnels=d.tunnels||[];
if(tunnels.length===0){const h='<div class="empty"><div class="icon"> </div><p>No tunnels found.</p></div>';list.innerHTML=h;tl.innerHTML=h;return}
const html=tunnels.map(t=>{
const sc=t.status==="running"?"running":"stopped";
const cb=t.cron_active?`<span class="cron-badge">  ${t.cron_interval}m</span>`:"";
return `<div class="tunnel-item">
<div class="tunnel-left">
<div class="tunnel-status ${sc}"></div>
<div>
<div class="tunnel-name">${t.service} <span class="tunnel-server-tag">${t.server_name}</span>${cb}</div>
<div class="tunnel-meta">
<span> ${t.transport.toUpperCase()}</span><span> ${t.bind_addr}</span><span>  ${t.cpu}%</span><span>  ${t.memory}</span>
</div>
</div>
</div>
<div class="tunnel-actions">
<button class="start" onclick="tunnelAction('start','${t.service}','${t.server_id}')">▶</button>
<button class="stop" onclick="tunnelAction('stop','${t.service}','${t.server_id}')">⏹</button>
<button class="restart" onclick="tunnelAction('restart','${t.service}','${t.server_id}')">🔄</button>
<button onclick="showLogs('${t.service}','${t.server_id}')"> </button>
<button onclick="showConfig('${t.service}','${t.server_id}')">✏️</button>
<button onclick="showCron('${t.service}','${t.server_id}',${t.cron_active},'${t.cron_interval}')"></button>
<button class="delete" onclick="doDelete('${t.service}','${t.server_id}')">🗑</button>
</div>
</div>`}).join("");
list.innerHTML=html;tl.innerHTML=html;
});
}

function selectIran(id){selectedIran=id;renderCreateWizard()}
function selectKharej(id){selectedKharej=id;renderCreateWizard()}

function wizardNext(page){
document.querySelectorAll(".wizard-step").forEach((s,i)=>{s.classList.remove("active","done");if(i+1<page)s.classList.add("done");if(i+1===page)s.classList.add("active")});
document.querySelectorAll(".wizard-page").forEach((p,i)=>{p.classList.remove("active");if(i+1===page)p.classList.add("active")});
if(page===3)doCreateBoth();
}

async function doCreateBoth(){
const iranSrv=servers.find(s=>s.id===selectedIran);
const kharejSrv=servers.find(s=>s.id===selectedKharej);
if(!iranSrv||!kharejSrv){showToast("Select both servers first","error");wizardNext(1);return}
const portsRaw=document.getElementById("wiz-ports").value.trim();
let portsArr=[];
if(portsRaw){portsArr=portsRaw.split(",").map(p=>p.trim()).filter(Boolean).map(p=>{if(/^\\d+$/.test(p))return p+"=127.0.0.1:"+p;return p});}
const params={
iran_server:iranSrv,kharej_server:kharejSrv,
transport:document.getElementById("wiz-transport").value,
port:document.getElementById("wiz-port").value,
token:document.getElementById("wiz-token").value,
ports:portsArr.map(p=>'"'+p+'"').join(",")
};
const r=await api("/api/tunnel/create-both",params);
const ds=document.getElementById("deploy-status");
const dr=document.getElementById("deploy-result");
ds.style.display="none";dr.style.display="block";
if(r&&r.success){
dr.innerHTML=`<div style="text-align:center"><div style="font-size:40px;margin-bottom:12px"> </div><div style="font-size:16px;font-weight:600;color:var(--green)">Tunnel Created Successfully!</div>
<div style="margin-top:16px;text-align:left;background:var(--bg);border-radius:10px;padding:16px;font-size:13px">
<div style="margin-bottom:8px"><strong>Token:</strong> <span style="color:var(--cyan)">${r.token}</span></div>
<div style="margin-bottom:8px"><strong>Port:</strong> ${r.port}</div>
<div style="margin-bottom:8px"><strong>Transport:</strong> ${r.transport.toUpperCase()}</div>
<div><strong>Iran:</strong> ${r.iran?"✅ "+r.iran.service:"❌ Failed"}</div>
<div><strong>Kharej:</strong> ${r.kharej?"✅ "+r.kharej.service:"❌ Failed"}</div>
</div>
<div style="margin-top:16px"><button class="btn btn-primary" onclick="wizardNext(1)">Create Another</button></div></div>`;
showToast("Tunnel created!","success");refreshAll();
}else{
dr.innerHTML=`<div style="text-align:center"><div style="font-size:40px;margin-bottom:12px">❌</div><div style="font-size:16px;font-weight:600;color:var(--red)">Creation Failed</div>
<div style="margin-top:8px;font-size:13px;color:var(--text3)">Check server connectivity and try again.</div>
<div style="margin-top:16px"><button class="btn btn-secondary" onclick="wizardNext(1)">Try Again</button></div></div>`;
showToast("Tunnel creation failed","error");
}
}

async function tunnelAction(action,svc,server_id){
showToast(action+"ing "+svc+"...","info");
await api("/api/tunnel/action",{service:svc,action:action,server_id:server_id});
setTimeout(()=>{refreshAll();showToast(svc+" "+action+"ed","success")},2000);
}

async function doDelete(svc,server_id){
if(!confirm("Delete "+svc+"?"))return;
await api("/api/tunnel/delete",{service:svc,server_id:server_id});
showToast(svc+" deleted","success");refreshAll();
}

async function showLogs(svc,server_id){
document.getElementById("modal-logs").classList.add("show");
document.getElementById("logs-content").textContent="Loading...";
const d=await api("/api/tunnel/logs?svc="+encodeURIComponent(svc)+"&server_id="+server_id+"&lines=200");
if(d)document.getElementById("logs-content").textContent=d.logs||"No logs.";
}

async function showConfig(svc,server_id){
document.getElementById("modal-config").classList.add("show");
currentConfigSvc=svc;currentConfigServerId=server_id;
const d=await api("/api/tunnel/config?svc="+encodeURIComponent(svc)+"&server_id="+server_id);
if(d)document.getElementById("config-content").value=d.config||"";
}

async function doSaveConfig(){
showToast("Saving...","info");
await api("/api/tunnel/save_config",{service:currentConfigSvc,config:document.getElementById("config-content").value,server_id:currentConfigServerId});
closeModal("modal-config");showToast("Config saved","success");refreshAll();
}

function showCron(svc,server_id,active,interval){
currentCronSvc=svc;currentCronServerId=server_id;
document.getElementById("modal-cron").classList.add("show");
document.getElementById("cron-svc-name").textContent=svc;
document.getElementById("btn-remove-cron").style.display=active?"inline-block":"none";
document.querySelectorAll(".cron-option").forEach(o=>{o.classList.toggle("active",active&&o.dataset.min===String(interval))});
}

document.querySelectorAll(".cron-option").forEach(o=>{o.onclick=function(){document.querySelectorAll(".cron-option").forEach(x=>x.classList.remove("active"));this.classList.add("active")}});

async function doSetCron(){
const a=document.querySelector(".cron-option.active");
if(!a){showToast("Select interval","error");return}
showToast("Setting auto-restart...","info");
await api("/api/tunnel/cron",{service:currentCronSvc,interval:parseInt(a.dataset.min),action:"set",server_id:currentCronServerId});
closeModal("modal-cron");showToast("Auto-restart enabled","success");refreshAll();
}

async function doRemoveCron(){
await api("/api/tunnel/cron",{service:currentCronSvc,action:"remove",server_id:currentCronServerId});
closeModal("modal-cron");showToast("Auto-restart disabled","success");refreshAll();
}

function showAddServer(editId){
editingServerId=editId||"";
document.getElementById("server-modal-title").textContent=editId?"Edit Server":"Add Server";
if(editId){
const s=servers.find(x=>x.id===editId);
if(s){document.getElementById("srv-name").value=s.name;document.getElementById("srv-ip").value=s.ip;document.getElementById("srv-role").value=s.role;document.getElementById("srv-ssh-user").value=s.ssh_user;document.getElementById("srv-ssh-port").value=s.ssh_port||22;document.getElementById("srv-ssh-password").value=s.ssh_password||"";document.getElementById("srv-ssh-key").value=s.ssh_key||""}
}else{
document.getElementById("srv-name").value="";document.getElementById("srv-ip").value="";document.getElementById("srv-role").value="iran";document.getElementById("srv-ssh-user").value="root";document.getElementById("srv-ssh-port").value="22";document.getElementById("srv-ssh-password").value="";document.getElementById("srv-ssh-key").value=""
}
document.getElementById("modal-add-server").classList.add("show");
}

function editServer(id){showAddServer(id)}

async function saveServer(){
const params={name:document.getElementById("srv-name").value,ip:document.getElementById("srv-ip").value,role:document.getElementById("srv-role").value,ssh_user:document.getElementById("srv-ssh-user").value,ssh_password:document.getElementById("srv-ssh-password").value,ssh_port:parseInt(document.getElementById("srv-ssh-port").value)||22,ssh_key:document.getElementById("srv-ssh-key").value};
if(!params.name||!params.ip){showToast("Name and IP required","error");return}
showToast("Testing connection...","info");
const test=await api("/api/server/test",{ip:params.ip,ssh_user:params.ssh_user,ssh_password:params.ssh_password,ssh_port:params.ssh_port,ssh_key:params.ssh_key});
if(!test||!test.success){showToast("Cannot connect to server. Check IP and SSH.","error");return}
if(editingServerId){params.id=editingServerId;await api("/api/server/update",params)}
else{await api("/api/server/add",params)}
closeModal("modal-add-server");showToast("Server saved","success");loadServers();
}

async function deleteServer(id,name){
if(!confirm("Delete server "+name+"?"))return;
await api("/api/server/delete",{id:id});
showToast("Server deleted","success");loadServers();
}

async function installBinary(server_id){
if(!confirm("Install/update Backhaul binary on this server?"))return;
showToast("Installing binary...","info");
const r=await api("/api/install/binary",{server_id:server_id});
if(r&&r.success){showToast("Installed: "+r.version,"success");loadServers()}
else{showToast("Install failed","error")}
}

function refreshAll(){loadServers();renderDashboardTunnels()}

loadServers();
setInterval(()=>{loadServers();renderDashboardTunnels()},15000);

document.querySelectorAll(".modal-overlay").forEach(m=>{m.addEventListener("click",function(e){if(e.target===this)this.classList.remove("show")})});
</script>
</body>
</html>'''


if __name__ == "__main__":
    os.makedirs(INSTALL_DIR, exist_ok=True)
    os.makedirs(CRON_CONFIG_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    os.makedirs(PANEL_DIR, exist_ok=True)

    server = ReuseAddrHTTPServer(("0.0.0.0", PORT), PanelHandler)
    local_ip = get_local_ip()
    print("")
    print("  BackhaulManager Web Panel v2.3.0")
    print("  Multi-Server Edition by emad1381")
    print("")
    print(f"  URL:      http://{local_ip}:{PORT}")
    print(f"  Login:    {ADMIN_USER} / {ADMIN_PASS}")
    print("")
    print("  Manage Iran + Kharej servers from one panel!")
    print("  Press Ctrl+C to stop")
    print("")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.server_close()
