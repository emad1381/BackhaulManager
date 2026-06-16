#!/usr/bin/env python3
"""
BackhaulManager Web Panel - Multi-Server Edition
Version: 2.4.5
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
SETTINGS_FILE = f"{PANEL_DIR}/settings.json"

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
    if user != "root" and cmd.startswith("sudo "):
        if password:
            cmd = f"echo '{password}' | sudo -S {cmd[5:]}"
        else:
            cmd = f"sudo -n {cmd[5:]}"

    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5", "-p", str(port)]
    if password:
        sshpass_check, _ = run_cmd("which sshpass")
        if not sshpass_check:
            return "sshpass not installed. Run: apt install sshpass", 1
        ssh_opts.extend(["-o", "PubkeyAuthentication=no"])
        full_cmd = ["sshpass", "-p", password, "ssh"] + ssh_opts + [f"{user}@{host}", cmd]
    else:
        ssh_opts.extend(["-o", "BatchMode=yes"])
        if key_file:
            full_cmd = ["ssh", "-i", key_file] + ssh_opts + [f"{user}@{host}", cmd]
        else:
            full_cmd = ["ssh"] + ssh_opts + [f"{user}@{host}", cmd]
    try:
        r = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
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
    return all(c.isalnum() or c in ".-" for c in target)

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
        out, _ = run_ssh(host, user, key, sudo_cmd(user, "systemctl list-unit-files --type=service 2>/dev/null | grep -o 'backhaul[^ ]*\\.service' | sort -u"), password=password, port=port)

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
            status_out, _ = run_ssh(host, user, key, sudo_cmd(user, f"systemctl is-active {svc} 2>/dev/null"), password=password, port=port)
            pid_out, _ = run_ssh(host, user, key, sudo_cmd(user, f"systemctl show -p MainPID --value {svc} 2>/dev/null"), password=password, port=port)
            cpu_out, _ = run_ssh(host, user, key, sudo_cmd(user, f"ps -p $(systemctl show -p MainPID --value {svc} 2>/dev/null) -o %cpu= 2>/dev/null"), password=password, port=port) if pid_out.strip() not in ["0", ""] else ("", 1)
            mem_out, _ = run_ssh(host, user, key, sudo_cmd(user, f"ps -p $(systemctl show -p MainPID --value {svc} 2>/dev/null) -o rss= 2>/dev/null"), password=password, port=port) if pid_out.strip() not in ["0", ""] else ("", 1)
            up_out, _ = run_ssh(host, user, key, sudo_cmd(user, f"ps -p $(systemctl show -p MainPID --value {svc} 2>/dev/null) -o etime= 2>/dev/null"), password=password, port=port) if pid_out.strip() not in ["0", ""] else ("", 1)

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
            cfg_out, _ = run_ssh(host, user, key, sudo_cmd(user, f"cat {config_path} 2>/dev/null"), password=password, port=port)
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
            cron_out, _ = run_ssh(host, user, key, sudo_cmd(user, f"cat {cron_conf} 2>/dev/null | grep INTERVAL"), password=password, port=port)
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
    return run_ssh(host, user, key, sudo_cmd(user, cmd), timeout, password=password, port=port)

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

    # Auto-install binary if it doesn't exist or is not executable on target
    binary_check, _ = remote_exec(srv, f"test -x {BINARY} && echo ok")
    if binary_check.strip() != "ok":
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
        c1 = 1
        out1 = "No download attempt made"
        for idx, url in enumerate(urls):
            if idx > 0:
                print(f"[{srv.get('ip') or srv.get('name')}] Direct download failed. Trying mirror proxy: {url}")
            out1, c1 = remote_exec(srv, f"wget -q -O /tmp/{asset} '{url}' 2>/dev/null || curl -sL -o /tmp/{asset} '{url}' 2>/dev/null", timeout=120)
            if c1 == 0:
                break
        if c1 != 0:
            return {
                "success": False,
                "error": f"Failed to download Backhaul binary on {srv.get('name') or srv.get('ip')}: {out1}"
            }
        out2, c2 = remote_exec(srv, f"tar -xzf /tmp/{asset} -C /tmp/ 2>/dev/null", timeout=60)
        if c2 != 0:
            return {
                "success": False,
                "error": f"Failed to extract Backhaul archive on {srv.get('name') or srv.get('ip')}: {out2}"
            }
        remote_exec(srv, f"cp /tmp/backhaul {BINARY}")
        remote_exec(srv, f"chmod +x {BINARY}")
        remote_exec(srv, f"rm -rf /tmp/backhaul /tmp/{asset}")

    if transport == "wssmux":
        remote_exec(srv, f"mkdir -p {CERT_DIR}")
        cert_check, _ = remote_exec(srv, f"test -f {CERT_DIR}/wssmux.crt && echo ok")
        if cert_check != "ok":
            remote_exec(srv, f'openssl req -x509 -newkey rsa:2048 -keyout {CERT_DIR}/wssmux.key -out {CERT_DIR}/wssmux.crt -days 3650 -nodes -subj "/CN=backhaul-wssmux" 2>/dev/null')

    check_cfg, _ = remote_exec(srv, f"test -f {config_file} && echo yes")
    if check_cfg.strip() == "yes":
        remote_exec(srv, f"cp {config_file} {BACKUP_DIR}/$(basename {config_file}).bak.$(date +%Y%m%d-%H%M%S)")

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
        delim = f"DELIM_{secrets.token_hex(8)}"
        run_ssh(host, user, key, sudo_cmd(user, f"mkdir -p {INSTALL_DIR} && cat > {config_file} << '{delim}'\n{config_content}{delim}"), password=password, port=ssh_port)

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
        delim = f"DELIM_{secrets.token_hex(8)}"
        run_ssh(host, user, key, sudo_cmd(user, f"cat > {service_file} << '{delim}'\n{service_content}{delim}"), password=password, port=ssh_port)

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

        if path == "/api/debug_ssh":
            query = urllib.parse.parse_qs(parsed.query)
            srv_id = query.get("server_id", [""])[0]
            cmd = query.get("cmd", [""])[0]
            data_servers = load_servers()
            srv = next((s for s in data_servers.get("servers", []) if s.get("id") == srv_id), None)
            if not srv:
                self.send_json({"error": "server not found"}, 404)
                return
            out, code = remote_exec(srv, cmd)
            self.send_json({"stdout": out, "exit_code": code})
            return

        if path == "/api/settings/get":
            settings = load_settings()
            self.send_json({"username": settings.get("admin_user", ADMIN_USER)})
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
            settings = load_settings()
            if username == settings.get("admin_user", ADMIN_USER) and password == settings.get("admin_pass", ADMIN_PASS):
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

        if path == "/api/settings/update":
            new_user = data.get("username", "")
            new_pass = data.get("password", "")
            if new_user and new_pass:
                settings = load_settings()
                settings["admin_user"] = new_user
                settings["admin_pass"] = new_pass
                save_settings(settings)
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
            remote_exec(kharej_srv, f"python3 -m http.server {test_port} > /dev/null 2>&1 & echo $! > /tmp/test_pid", timeout=5)
            time.sleep(1)
            curl_out, curl_code = remote_exec(iran_srv, f"curl -m 5 -s http://{kharej_ip}:{test_port} | head -n 1", timeout=10)
            tcp_open = "Directory listing" in curl_out or curl_code == 0
            remote_exec(kharej_srv, "kill -9 $(cat /tmp/test_pid) 2>/dev/null || true", timeout=5)
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
                    remote_exec(srv, f"crontab -l 2>/dev/null | grep -v '{CRON_MARKER}.*{svc}' | crontab -")
                    remote_exec(srv, "systemctl daemon-reload")
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
                        run_ssh(host, srv.get("ssh_user", "root"), srv.get("ssh_key", ""), sudo_cmd(srv.get("ssh_user", "root"), f"cat > {config_path} << '{delim}'\n{config}{delim}"), password=srv.get("ssh_password", ""), port=srv.get("ssh_port", 22))
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
            self.send_json({"success": True, "version": ver, "used_mirror": used_mirror})
            return

        self.send_json({"error": "not found"}, 404)


def get_login_page():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BackhaulManager - Premium Login</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
<style>
* { margin:0; padding:0; box-sizing:border-box; font-family:'Outfit', sans-serif; }
body { background: #050505; min-height: 100vh; display: flex; align-items: center; justify-content: center; color: #fff; overflow: hidden; }
.bg-glow { position: absolute; width: 600px; height: 600px; background: radial-gradient(circle, rgba(6,182,212,0.15) 0%, rgba(139,92,246,0.15) 50%, transparent 70%); top: 50%; left: 50%; transform: translate(-50%, -50%); z-index: 0; animation: pulse 8s infinite alternate; }
@keyframes pulse { 0% { transform: translate(-50%, -50%) scale(1); opacity: 0.8; } 100% { transform: translate(-50%, -50%) scale(1.1); opacity: 1; } }
.login-container { position: relative; z-index: 1; background: rgba(20, 20, 20, 0.6); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 24px; padding: 50px 40px; width: 420px; box-shadow: 0 30px 60px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.1); }
.logo { text-align: center; margin-bottom: 35px; }
.logo h1 { font-size: 34px; font-weight: 800; background: linear-gradient(135deg, #fff, #a1a1aa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: -1px; }
.logo p { color: #06b6d4; font-size: 13px; font-weight: 600; margin-top: 5px; text-transform: uppercase; letter-spacing: 2px; }
.form-group { margin-bottom: 22px; }
.form-group label { display: block; font-size: 13px; color: #a1a1aa; margin-bottom: 8px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
.form-group input { width: 100%; padding: 15px 18px; background: rgba(0, 0, 0, 0.5); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; color: #fff; font-size: 15px; transition: all 0.3s; outline: none; }
.form-group input:focus { border-color: #06b6d4; box-shadow: 0 0 0 4px rgba(6, 182, 212, 0.15); background: rgba(0, 0, 0, 0.8); }
.form-group input::placeholder { color: #52525b; }
.btn-login { width: 100%; padding: 15px; background: linear-gradient(135deg, #06b6d4, #3b82f6); border: none; border-radius: 12px; color: white; font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.3s; margin-top: 10px; position: relative; overflow: hidden; }
.btn-login::before { content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent); transition: all 0.5s; }
.btn-login:hover::before { left: 100%; }
.btn-login:hover { transform: translateY(-2px); box-shadow: 0 10px 25px rgba(6, 182, 212, 0.4); }
.error-msg { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 12px; padding: 14px; color: #f87171; font-size: 13px; text-align: center; display: none; margin-bottom: 20px; font-weight: 600; }
.footer { text-align: center; margin-top: 25px; color: #52525b; font-size: 12px; font-weight: 600; letter-spacing: 1px; }
</style>
</head>
<body>
<div class="bg-glow"></div>
<div class="login-container">
<div class="logo"><h1>BACKHAUL</h1><p>Premium Panel</p></div>
<div class="error-msg" id="error"></div>
<form onsubmit="doLogin(event)">
<div class="form-group"><label>Username</label><input type="text" id="username" placeholder="Enter username" autocomplete="username" required></div>
<div class="form-group"><label>Password</label><input type="password" id="password" placeholder="Enter password" autocomplete="current-password" required></div>
<button type="submit" class="btn-login">Sign In to Dashboard</button>
</form>
<div class="footer">EMAD1381</div>
</div>
<script>
async function doLogin(e){e.preventDefault();const u=document.getElementById("username").value;const p=document.getElementById("password").value;const btn=document.querySelector(".btn-login");btn.textContent="Authenticating...";btn.style.opacity="0.8";const r=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});const d=await r.json();if(d.success){window.location.href="/"}else{const er=document.getElementById("error");er.textContent=d.error||"Invalid credentials";er.style.display="block";btn.textContent="Sign In to Dashboard";btn.style.opacity="1";}}
</script>
</body>
</html>"""


def get_main_page():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BackhaulManager - Premium Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;800&display=swap" rel="stylesheet">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Outfit', sans-serif; }
:root {
  --bg: #050505;
  --bg-card: rgba(20, 20, 20, 0.6);
  --border: rgba(255, 255, 255, 0.08);
  --text: #f4f4f5; --text-muted: #a1a1aa; --text-dark: #52525b;
  --primary: #06b6d4; --primary-hover: #0891b2;
  --secondary: #8b5cf6;
  --success: #10b981; --warning: #f59e0b; --danger: #ef4444;
}
body { background: var(--bg); color: var(--text); min-height: 100vh; overflow-x: hidden; }
/* Glassmorphism Background Glows */
.bg-glow-1 { position: fixed; top: -10%; left: -10%; width: 500px; height: 500px; background: radial-gradient(circle, rgba(6,182,212,0.1) 0%, transparent 70%); z-index: -1; }
.bg-glow-2 { position: fixed; bottom: -10%; right: -10%; width: 600px; height: 600px; background: radial-gradient(circle, rgba(139,92,246,0.1) 0%, transparent 70%); z-index: -1; }

.topbar { background: rgba(10, 10, 10, 0.8); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border-bottom: 1px solid var(--border); padding: 16px 32px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; box-shadow: 0 4px 30px rgba(0,0,0,0.5); }
.topbar-left { display: flex; align-items: center; gap: 16px; }
.topbar-logo { font-size: 24px; font-weight: 800; background: linear-gradient(135deg, #fff, #a1a1aa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: -0.5px; }
.topbar-badge { background: rgba(6,182,212,0.1); border: 1px solid rgba(6,182,212,0.2); border-radius: 20px; padding: 4px 12px; font-size: 11px; color: var(--primary); font-weight: 600; letter-spacing: 1px; text-transform: uppercase; }
.topbar-right { display: flex; align-items: center; gap: 20px; }
.btn-logout { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.2); border-radius: 10px; padding: 8px 16px; color: var(--danger); font-size: 13px; font-weight: 600; cursor: pointer; transition: all 0.3s; }
.btn-logout:hover { background: rgba(239,68,68,0.2); box-shadow: 0 0 15px rgba(239,68,68,0.2); }

.container { max-width: 1400px; margin: 0 auto; padding: 32px; }

/* Tabs */
.tabs { display: flex; gap: 8px; padding: 6px; background: rgba(15,15,15,0.6); backdrop-filter: blur(10px); border-radius: 16px; margin-bottom: 32px; border: 1px solid var(--border); width: fit-content; margin-left: auto; margin-right: auto; }
.tab { padding: 12px 24px; border-radius: 12px; cursor: pointer; font-size: 14px; font-weight: 600; color: var(--text-muted); transition: all 0.3s; border: none; background: transparent; display: flex; align-items: center; gap: 8px; }
.tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
.tab.active { background: linear-gradient(135deg, var(--primary), #3b82f6); color: white; box-shadow: 0 8px 20px rgba(6,182,212,0.3); }
.tab-content { display: none; animation: fadeIn 0.4s ease forwards; }
.tab-content.active { display: block; }

@keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

/* Cards & Grid */
.server-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 24px; margin-bottom: 32px; }
.card { background: var(--bg-card); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border: 1px solid var(--border); border-radius: 20px; padding: 24px; transition: all 0.3s; position: relative; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
.card:hover { transform: translateY(-4px); border-color: rgba(255,255,255,0.15); box-shadow: 0 20px 40px rgba(0,0,0,0.6); }

/* Accent lines for Server Cards */
.server-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; }
.server-card.iran::before { background: linear-gradient(90deg, var(--success), var(--primary)); }
.server-card.kharej::before { background: linear-gradient(90deg, var(--primary), var(--secondary)); }

.server-card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; }
.server-card-title { display: flex; align-items: center; gap: 12px; }
.server-card-title h3 { font-size: 18px; font-weight: 600; letter-spacing: 0.5px; }
.role-badge { padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; }
.role-badge.iran { background: rgba(16,185,129,0.1); color: var(--success); border: 1px solid rgba(16,185,129,0.2); }
.role-badge.kharej { background: rgba(139,92,246,0.1); color: var(--secondary); border: 1px solid rgba(139,92,246,0.2); }
.ssh-status { font-size: 12px; font-weight: 600; display: flex; align-items: center; gap: 6px; }
.ssh-status .dot { width: 8px; height: 8px; border-radius: 50%; box-shadow: 0 0 8px currentColor; }
.ssh-status .dot.ok { background: var(--success); color: var(--success); }
.ssh-status .dot.err { background: var(--danger); color: var(--danger); }

.server-stats { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.server-stat { background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.03); border-radius: 12px; padding: 12px 16px; transition: all 0.2s; }
.server-stat:hover { background: rgba(255,255,255,0.03); }
.server-stat .label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }
.server-stat .value { font-size: 15px; font-weight: 600; margin-top: 4px; color: #fff; }

.server-card-actions { display: flex; gap: 8px; margin-top: 20px; }
.btn { padding: 10px 16px; border-radius: 12px; font-size: 13px; font-weight: 600; cursor: pointer; transition: all 0.3s; border: none; display: inline-flex; align-items: center; justify-content: center; gap: 6px; }
.btn-outline { background: rgba(255,255,255,0.03); border: 1px solid var(--border); color: var(--text); }
.btn-outline:hover { background: rgba(255,255,255,0.08); border-color: rgba(255,255,255,0.2); }
.btn-primary { background: linear-gradient(135deg, var(--primary), #3b82f6); color: white; box-shadow: 0 4px 15px rgba(6,182,212,0.3); }
.btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(6,182,212,0.4); }
.btn-danger { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.2); color: var(--danger); }
.btn-danger:hover { background: rgba(239,68,68,0.2); box-shadow: 0 4px 15px rgba(239,68,68,0.2); }
.server-card-actions .btn { flex: 1; }

/* Sections & Tunnels */
.section { background: var(--bg-card); backdrop-filter: blur(20px); border: 1px solid var(--border); border-radius: 24px; margin-bottom: 32px; overflow: hidden; box-shadow: 0 10px 40px rgba(0,0,0,0.5); }
.section-header { padding: 24px 32px; border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; align-items: center; justify-content: space-between; background: rgba(255,255,255,0.01); }
.section-header h2 { font-size: 18px; font-weight: 600; letter-spacing: 0.5px; }
.section-body { padding: 24px 32px; }

.tunnel-list { display: flex; flex-direction: column; gap: 12px; }
.tunnel-item { background: rgba(0,0,0,0.4); border: 1px solid var(--border); border-radius: 16px; padding: 20px 24px; display: flex; align-items: center; justify-content: space-between; transition: all 0.3s; }
.tunnel-item:hover { border-color: rgba(6,182,212,0.3); background: rgba(6,182,212,0.02); transform: translateX(4px); }
.tunnel-left { display: flex; align-items: center; gap: 20px; }
.tunnel-status { width: 12px; height: 12px; border-radius: 50%; box-shadow: 0 0 10px currentColor; }
.tunnel-status.running { background: var(--success); color: var(--success); }
.tunnel-status.stopped { background: var(--danger); color: var(--danger); }
.tunnel-name { font-weight: 600; font-size: 16px; display: flex; align-items: center; gap: 10px; }
.tunnel-server-tag { background: rgba(139,92,246,0.15); border: 1px solid rgba(139,92,246,0.2); border-radius: 8px; padding: 2px 10px; font-size: 11px; color: #c4b5fd; text-transform: uppercase; letter-spacing: 1px; }
.cron-badge { background: rgba(6,182,212,0.15); border: 1px solid rgba(6,182,212,0.2); border-radius: 8px; padding: 2px 10px; font-size: 11px; color: #a5f3fc; }
.tunnel-meta { font-size: 13px; color: var(--text-muted); margin-top: 6px; display: flex; gap: 16px; flex-wrap: wrap; font-weight: 500; }
.tunnel-meta span { display: flex; align-items: center; gap: 4px; }

.tunnel-actions { display: flex; gap: 8px; }
.icon-btn { width: 36px; height: 36px; border-radius: 10px; border: 1px solid var(--border); background: rgba(255,255,255,0.03); color: var(--text-muted); display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.2s; font-size: 14px; }
.icon-btn:hover { background: rgba(255,255,255,0.1); color: #fff; transform: translateY(-2px); }
.icon-btn.start { color: var(--success); border-color: rgba(16,185,129,0.2); } .icon-btn.start:hover { background: rgba(16,185,129,0.1); box-shadow: 0 4px 12px rgba(16,185,129,0.2); }
.icon-btn.stop { color: var(--warning); border-color: rgba(245,158,11,0.2); } .icon-btn.stop:hover { background: rgba(245,158,11,0.1); box-shadow: 0 4px 12px rgba(245,158,11,0.2); }
.icon-btn.restart { color: var(--primary); border-color: rgba(6,182,212,0.2); } .icon-btn.restart:hover { background: rgba(6,182,212,0.1); box-shadow: 0 4px 12px rgba(6,182,212,0.2); }
.icon-btn.delete { color: var(--danger); border-color: rgba(239,68,68,0.2); } .icon-btn.delete:hover { background: rgba(239,68,68,0.1); box-shadow: 0 4px 12px rgba(239,68,68,0.2); }

/* Empty States */
.empty { text-align: center; padding: 60px 20px; color: var(--text-dark); grid-column: 1 / -1; width: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center; }
.empty .icon { font-size: 48px; margin-bottom: 16px; opacity: 0.5; }

/* Modals */
.modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); z-index: 200; display: none; align-items: center; justify-content: center; opacity: 0; transition: opacity 0.3s ease; }
.modal-overlay.show { display: flex; opacity: 1; }
.modal { background: var(--bg-card); border: 1px solid var(--border); border-radius: 24px; width: 600px; max-height: 85vh; overflow-y: auto; box-shadow: 0 30px 60px rgba(0,0,0,0.8); transform: translateY(20px); transition: transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275); }
.modal-overlay.show .modal { transform: translateY(0); }
.modal-header { padding: 24px 32px; border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; align-items: center; justify-content: space-between; }
.modal-header h3 { font-size: 20px; font-weight: 600; }
.modal-close { background: rgba(255,255,255,0.05); border: none; color: var(--text-muted); width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.2s; font-size: 18px; }
.modal-close:hover { background: rgba(239,68,68,0.1); color: var(--danger); transform: rotate(90deg); }
.modal-body { padding: 32px; }
.modal-footer { padding: 24px 32px; border-top: 1px solid rgba(255,255,255,0.05); display: flex; justify-content: flex-end; gap: 12px; background: rgba(0,0,0,0.2); }

/* Forms */
.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
.form-group label { display: block; font-size: 12px; color: var(--text-muted); margin-bottom: 8px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
.form-group input, .form-group select, .form-group textarea { width: 100%; padding: 14px 16px; background: rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; color: #fff; font-size: 14px; outline: none; transition: all 0.3s; }
.form-group input:focus, .form-group select:focus, .form-group textarea:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(6,182,212,0.15); background: rgba(0,0,0,0.6); }
.form-group textarea { min-height: 200px; resize: vertical; font-family: monospace; font-size: 13px; line-height: 1.6; }

/* Logs */
.logs-box { background: rgba(0,0,0,0.8); border: 1px solid var(--border); border-radius: 12px; padding: 16px; font-family: monospace; font-size: 13px; line-height: 1.6; max-height: 450px; overflow-y: auto; color: #a1a1aa; white-space: pre-wrap; word-break: break-all; box-shadow: inset 0 4px 20px rgba(0,0,0,0.5); }

/* Toasts */
.toast { position: fixed; bottom: 32px; right: 32px; background: rgba(20,20,20,0.9); backdrop-filter: blur(10px); border: 1px solid var(--border); border-radius: 16px; padding: 16px 24px; font-size: 14px; font-weight: 500; z-index: 300; transform: translateY(100px); opacity: 0; transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); box-shadow: 0 15px 40px rgba(0,0,0,0.6); display: flex; align-items: center; gap: 12px; }
.toast.show { transform: translateY(0); opacity: 1; }
.toast::before { content: ''; display: block; width: 10px; height: 10px; border-radius: 50%; }
.toast.success::before { background: var(--success); box-shadow: 0 0 10px var(--success); }
.toast.error::before { background: var(--danger); box-shadow: 0 0 10px var(--danger); }
.toast.info::before { background: var(--primary); box-shadow: 0 0 10px var(--primary); }

/* Wizard */
.wizard-steps { display: flex; gap: 12px; margin-bottom: 32px; }
.wizard-step { flex: 1; padding: 16px; text-align: center; border-radius: 16px; font-size: 13px; font-weight: 600; color: var(--text-dark); background: rgba(0,0,0,0.3); border: 1px solid var(--border); transition: all 0.3s; position: relative; overflow: hidden; }
.wizard-step.active { color: #fff; border-color: var(--primary); background: rgba(6,182,212,0.1); box-shadow: 0 0 20px rgba(6,182,212,0.1); }
.wizard-step.done { color: var(--success); border-color: rgba(16,185,129,0.3); background: rgba(16,185,129,0.05); }
.wizard-page { display: none; animation: fadeIn 0.4s; }
.wizard-page.active { display: block; }
.connection-line { display: flex; align-items: center; justify-content: center; gap: 16px; padding: 20px; }
.connection-line .line { flex: 1; height: 2px; background: linear-gradient(90deg, rgba(16,185,129,0.5), rgba(6,182,212,0.5), rgba(139,92,246,0.5)); position: relative; overflow: hidden; }
.connection-line .line::after { content: ''; position: absolute; top: 0; left: -100%; width: 50%; height: 100%; background: linear-gradient(90deg, transparent, #fff, transparent); animation: flow 2s infinite; }
@keyframes flow { 100% { left: 200%; } }
.connection-line .arrow { color: var(--primary); font-size: 24px; filter: drop-shadow(0 0 8px var(--primary)); }

.server-select-card { background: rgba(0,0,0,0.4); border: 2px solid var(--border); border-radius: 16px; padding: 20px; cursor: pointer; transition: all 0.3s; text-align: center; }
.server-select-card:hover { border-color: rgba(255,255,255,0.2); background: rgba(255,255,255,0.02); transform: translateY(-2px); }
.server-select-card.selected { border-color: var(--primary); background: rgba(6,182,212,0.1); box-shadow: 0 8px 25px rgba(6,182,212,0.2); }
.server-select-card h4 { margin-bottom: 6px; font-size: 16px; }
.server-select-card p { font-size: 13px; color: var(--text-muted); font-family: monospace; }
</style>
</head>
<body>
<div class="bg-glow-1"></div><div class="bg-glow-2"></div>

<div class="topbar">
<div class="topbar-left">
<div class="topbar-logo">BACKHAUL</div>
<div class="topbar-badge">Premium v2.4.5</div>
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
<button class="tab" onclick="switchTab('diagnostics')">Diagnostics</button>
<button class="tab" onclick="switchTab('settings')">Settings</button>
</div>

<!-- Dashboard -->
<div class="tab-content active" id="tab-dashboard">
<div class="server-grid" id="server-grid">
<div class="empty"><div class="icon">⌛</div><p>Loading premium servers...</p></div>
</div>
<div class="section">
<div class="section-header"><h2>Active Tunnels</h2><button class="btn btn-outline" onclick="refreshAll()">Refresh</button></div>
<div class="section-body"><div class="tunnel-list" id="dashboard-tunnels"><div class="empty"><p>No tunnels found.</p></div></div></div>
</div>
</div>

<!-- Servers -->
<div class="tab-content" id="tab-servers">
<div class="section">
<div class="section-header"><h2>Server Management</h2><button class="btn btn-primary" onclick="showAddServer()">+ Add Server</button></div>
<div class="section-body"><div class="server-grid" id="server-manage-grid"></div></div>
</div>
</div>

<!-- Tunnels -->
<div class="tab-content" id="tab-tunnels">
<div class="section">
<div class="section-header"><h2>All Tunnels</h2><button class="btn btn-outline" onclick="refreshAll()">Refresh</button></div>
<div class="section-body"><div class="tunnel-list" id="all-tunnels"><div class="empty"><p>No tunnels found.</p></div></div></div>
</div>
</div>

<!-- Create Tunnel -->
<div class="tab-content" id="tab-create">
<div class="section">
<div class="section-header"><h2>Create New Tunnel</h2></div>
<div class="section-body">
<div class="wizard-steps">
<div class="wizard-step active" id="ws1">1. Select Servers</div>
<div class="wizard-step" id="ws2">2. Configuration</div>
<div class="wizard-step" id="ws3">3. Deploying</div>
</div>
<div class="wizard-page active" id="wp1">
<p style="font-size:14px;color:var(--text-muted);margin-bottom:24px;text-align:center">Select the origin and destination servers to establish a secure tunnel.</p>
<div style="display:grid;grid-template-columns:1fr 60px 1fr;gap:20px;align-items:center">
<div>
<div style="font-size:13px;color:var(--success);font-weight:800;margin-bottom:12px;text-align:center;letter-spacing:1px">IRAN (LISTENER)</div>
<div id="iran-server-select"></div>
</div>
<div class="connection-line"><div class="line"></div><div class="arrow">⚡</div><div class="line"></div></div>
<div>
<div style="font-size:13px;color:var(--secondary);font-weight:800;margin-bottom:12px;text-align:center;letter-spacing:1px">KHAREJ (CONNECTOR)</div>
<div id="kharej-server-select"></div>
</div>
</div>
<div style="text-align:right;margin-top:32px"><button class="btn btn-primary" onclick="wizardNext(2)">Next Step →</button></div>
</div>
<div class="wizard-page" id="wp2">
<div class="form-row">
<div class="form-group"><label>Transport Protocol</label><select id="wiz-transport"><option value="wssmux">WSSMUX (TLS Encrypted - Recommended)</option><option value="wsmux">WSMUX</option><option value="tcpmux">TCPMUX</option><option value="tcp">TCP</option></select></div>
<div class="form-group"><label>Tunnel Port</label><input id="wiz-port" value="9743"></div>
</div>
<div class="form-row">
<div class="form-group"><label>Authentication Token</label><input id="wiz-token" placeholder="Leave empty to auto-generate"><small style="color:var(--text-dark);font-size:11px;margin-top:4px;display:block">Secure 32-char token will be generated if empty</small></div>
<div class="form-group"><label>Port Forwarding Rules (Iran)</label><input id="wiz-ports" placeholder="e.g. 443=127.0.0.1:443"><small style="color:var(--text-dark);font-size:11px;margin-top:4px;display:block">Comma separated: listen_port=target_ip:target_port</small></div>
</div>
<div style="display:flex;justify-content:space-between;margin-top:32px">
<button class="btn btn-outline" onclick="wizardNext(1)">← Back</button>
<button class="btn btn-primary" onclick="wizardNext(3)">Launch Tunnel 🚀</button>
</div>
</div>
<div class="wizard-page" id="wp3">
<div id="deploy-status" style="text-align:center;padding:40px 20px">
<div style="font-size:40px;margin-bottom:20px;animation:spin 2s linear infinite">⚙️</div>
<div style="font-size:18px;font-weight:600;color:var(--text)">Deploying infrastructure...</div>
<div style="font-size:14px;color:var(--text-muted);margin-top:8px">Establishing secure connection between nodes.</div>
</div>
<div id="deploy-result" style="display:none"></div>
</div>
</div>
</div>
</div>

<!-- Diagnostics -->
<div class="tab-content" id="tab-diagnostics">
<div class="section">
<div class="section-header"><h2>Node-to-Node Diagnostics</h2></div>
<div class="section-body">
<p style="font-size:14px;color:var(--text-muted);margin-bottom:24px;text-align:center">Test reachability, TCP open ports, and ping latency between an Iran node and Kharej node before tunneling.</p>
<div style="display:grid;grid-template-columns:1fr 60px 1fr;gap:20px;align-items:center">
<div>
<div style="font-size:13px;color:var(--success);font-weight:800;margin-bottom:12px;text-align:center;letter-spacing:1px">IRAN (TESTER)</div>
<div class="form-group"><select id="diag-iran-select"><option value="">Select Iran Server</option></select></div>
</div>
<div class="connection-line" style="padding:0"><div class="line"></div><div class="arrow">🏓</div><div class="line"></div></div>
<div>
<div style="font-size:13px;color:var(--secondary);font-weight:800;margin-bottom:12px;text-align:center;letter-spacing:1px">KHAREJ (TARGET)</div>
<div class="form-group"><select id="diag-kharej-select"><option value="">Select Kharej Server</option></select></div>
</div>
</div>
<div class="form-row" style="margin-top:20px;justify-content:center;display:flex">
<div class="form-group" style="width:200px"><label>Test Port (Kharej Listener)</label><input type="number" id="diag-port" value="9999"></div>
</div>
<div style="text-align:center;margin-top:24px">
<button class="btn btn-primary" onclick="runDiagnostics()" id="btn-run-diag" style="width:200px">Run Diagnostics</button>
</div>
<div id="diag-results" style="display:none;margin-top:32px">
<div class="card" style="background:rgba(0,0,0,0.5)">
<h3 style="text-align:center;margin-bottom:20px" id="diag-verdict"></h3>
<div class="server-stats">
<div class="server-stat"><div class="label">TCP Reachability</div><div class="value" id="diag-tcp"></div></div>
<div class="server-stat"><div class="label">Packet Loss</div><div class="value" id="diag-loss"></div></div>
<div class="server-stat"><div class="label">Average Ping</div><div class="value" id="diag-ping"></div></div>
<div class="server-stat"><div class="label">Overall Score</div><div class="value" id="diag-score"></div></div>
</div>
<div style="margin-top:20px">
<label style="font-size:12px;color:var(--text-muted);font-weight:600">Raw Ping Output:</label>
<pre id="diag-raw" class="logs-box" style="margin-top:8px;max-height:150px"></pre>
</div>
</div>
</div>
</div>
</div>
</div>

<!-- Settings -->
<div class="tab-content" id="tab-settings">
<div class="section" style="max-width:600px;margin:0 auto">
<div class="section-header"><h2>Panel Settings</h2></div>
<div class="section-body">
<p style="font-size:14px;color:var(--text-muted);margin-bottom:24px">Update the credentials used to access this web panel.</p>
<div class="form-group">
<label>New Username</label>
<input type="text" id="set-username" placeholder="admin">
</div>
<div class="form-group">
<label>New Password</label>
<input type="password" id="set-password" placeholder="Enter new password">
</div>
<div style="text-align:right;margin-top:24px">
<button class="btn btn-primary" onclick="updateSettings()">Save Credentials</button>
</div>
</div>
</div>
</div>

</div>

<!-- Modals -->
<div class="modal-overlay" id="modal-add-server">
<div class="modal">
<div class="modal-header"><h3 id="server-modal-title">Add Server</h3><button class="modal-close" onclick="closeModal('modal-add-server')">✕</button></div>
<div class="modal-body">
<div id="add-srv-form-fields">
<div class="form-group"><label>Server Label</label><input id="srv-name" placeholder="e.g. Tehran Node 1"></div>
<div class="form-row">
<div class="form-group"><label>IP Address / Domain</label><input id="srv-ip" placeholder="1.2.3.4"></div>
<div class="form-group"><label>Server Role</label><select id="srv-role"><option value="iran">IRAN (Origin)</option><option value="kharej">KHAREJ (Destination)</option></select></div>
</div>
<div class="form-row">
<div class="form-group"><label>SSH Username</label><input id="srv-ssh-user" value="root"></div>
<div class="form-group"><label>SSH Port</label><input id="srv-ssh-port" value="22" type="number"></div>
</div>
<div class="form-row">
<div class="form-group"><label>SSH Password</label><input id="srv-ssh-password" type="password" placeholder="Password (Optional if key used)"></div>
<div class="form-group"><label>SSH Key Path</label><input id="srv-ssh-key" placeholder="/root/.ssh/id_rsa"></div>
</div>
</div>
<div id="add-srv-progress-container" style="display:none; margin-top:10px;">
  <div style="display:flex; justify-content:space-between; margin-bottom:8px; font-size:13px; font-weight:600;">
    <span id="add-srv-status-text" style="color:var(--text-muted)">Testing connection...</span>
    <span id="add-srv-pct-text" style="color:var(--primary)">0%</span>
  </div>
  <div style="width:100%; height:8px; background:rgba(255,255,255,0.05); border-radius:4px; overflow:hidden; border:1px solid rgba(255,255,255,0.05);">
    <div id="add-srv-progress-bar" style="width:0%; height:100%; background:linear-gradient(90deg, var(--primary), var(--secondary)); transition:width 0.4s ease, background 0.4s ease; border-radius:4px;"></div>
  </div>
  <div id="add-srv-error-details" style="display:none; color:var(--danger); font-size:12px; margin-top:15px; font-family:monospace; background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.2); border-radius:8px; padding:12px; text-align:left; line-height:1.5;"></div>
</div>
</div>
<div class="modal-footer">
<button class="btn btn-outline" onclick="closeModal('modal-add-server')">Cancel</button>
<button class="btn btn-primary" onclick="saveServer()">Save Server</button>
</div>
</div>
</div>

<div class="modal-overlay" id="modal-logs">
<div class="modal" style="width:800px"><div class="modal-header"><h3>Live Logs</h3><button class="modal-close" onclick="closeModal('modal-logs')">✕</button></div><div class="modal-body"><div class="logs-box" id="logs-content">Fetching logs...</div></div><div class="modal-footer"><button class="btn btn-outline" onclick="closeModal('modal-logs')">Close</button></div></div>
</div>

<div class="modal-overlay" id="modal-config">
<div class="modal" style="width:700px"><div class="modal-header"><h3>Edit Configuration</h3><button class="modal-close" onclick="closeModal('modal-config')">✕</button></div><div class="modal-body"><div class="form-group"><textarea id="config-content" spellcheck="false"></textarea></div></div><div class="modal-footer"><button class="btn btn-outline" onclick="closeModal('modal-config')">Cancel</button><button class="btn btn-primary" onclick="doSaveConfig()">Save & Restart</button></div></div>
</div>

<div class="modal-overlay" id="modal-cron">
<div class="modal" style="width:480px"><div class="modal-header"><h3>Auto-Restart Schedule</h3><button class="modal-close" onclick="closeModal('modal-cron')">✕</button></div>
<div class="modal-body">
<p style="font-size:14px;color:var(--text-muted);margin-bottom:20px">Configure auto-restart interval for <strong id="cron-svc-name" style="color:#fff"></strong> to maintain optimal speed and clear cache.</p>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;" id="cron-options">
<div class="btn btn-outline cron-option" data-min="30">30 Minutes</div>
<div class="btn btn-outline cron-option" data-min="60">1 Hour</div>
<div class="btn btn-outline cron-option" data-min="120">2 Hours</div>
<div class="btn btn-outline cron-option" data-min="360">6 Hours</div>
</div>
</div>
<div class="modal-footer">
<button class="btn btn-danger" onclick="doRemoveCron()" id="btn-remove-cron" style="margin-right:auto;display:none">Disable Cron</button>
<button class="btn btn-outline" onclick="closeModal('modal-cron')">Cancel</button>
<button class="btn btn-primary" onclick="doSetCron()">Apply Schedule</button>
</div>
</div>
</div>

<div class="toast" id="toast"></div>

<style>
@keyframes spin { 100% { transform: rotate(360deg); } }
</style>

<script>
let servers=[]; let selectedIran=""; let selectedKharej=""; let editingServerId=""; let currentCronSvc=""; let currentCronServerId=""; let currentConfigSvc=""; let currentConfigServerId="";
function showToast(m,t="info"){const e=document.getElementById("toast");e.textContent=m;e.className="toast "+t+" show";setTimeout(()=>e.classList.remove("show"),3500)}
function closeModal(id){document.getElementById(id).classList.remove("show")}
function switchTab(name){document.querySelectorAll(".tab").forEach((t,i)=>t.classList.remove("active"));document.querySelectorAll(".tab-content").forEach(t=>t.classList.remove("active"));document.querySelectorAll(".tab").forEach(t=>{if(t.textContent.toLowerCase().includes(name)){t.classList.add("active")}});document.getElementById("tab-"+name).classList.add("active"); if(name==='settings'){loadCurrentSettings();}}

async function api(url,body){const opts=body?{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}:{};const r=await fetch(url,opts);if(r.status===401){window.location.href="/login.html";return null}return r.json()}
async function doLogout(){await api("/api/auth/logout");window.location.href="/login.html"}

async function loadServers(){
const d=await api("/api/servers");
if(d&&d.servers){servers=d.servers;renderServerCards();renderServerManage();renderCreateWizard();renderDashboardTunnels();renderDiagnostics();}
}

function renderServerCards(){
const g=document.getElementById("server-grid");
if(servers.length===0){g.innerHTML='<div class="empty"><div class="icon">🖥️</div><p>No servers added yet. Head to Servers tab.</p></div>';return}
g.innerHTML=servers.map(s=>{
const roleClass=s.role==="iran"?"iran":"kharej";
const sshDot=s.ssh_ok?"ok":"err"; const sshText=s.ssh_ok?"Online":"Offline";
return `<div class="card server-card ${roleClass}">
<div class="server-card-header">
<div class="server-card-title"><h3>${s.name}</h3><span class="role-badge ${roleClass}">${s.role}</span></div>
<div class="ssh-status"><span class="dot ${sshDot}"></span>${sshText}</div>
</div>
<div class="server-stats">
<div class="server-stat"><div class="label">IP Address</div><div class="value" style="color:var(--primary);font-family:monospace">${s.ip}</div></div>
<div class="server-stat"><div class="label">Backhaul</div><div class="value">${s.version||"N/A"}</div></div>
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
return `<div class="card server-card ${roleClass}">
<div class="server-card-header">
<div class="server-card-title"><h3>${s.name}</h3><span class="role-badge ${roleClass}">${s.role}</span></div>
</div>
<div class="server-stats">
<div class="server-stat"><div class="label">IP Address</div><div class="value" style="color:var(--primary);font-family:monospace">${s.ip}</div></div>
<div class="server-stat"><div class="label">SSH User</div><div class="value">${s.ssh_user}</div></div>
<div class="server-stat"><div class="label">SSH Port</div><div class="value">${s.ssh_port||22}</div></div>
<div class="server-stat"><div class="label">Auth Type</div><div class="value">${s.ssh_password?"Password":"Key"}</div></div>
</div>
<div class="server-card-actions">
<button class="btn btn-outline" onclick="installBinary('${s.id}')">Install Binary</button>
<button class="btn btn-outline" onclick="editServer('${s.id}')">Edit</button>
<button class="btn btn-danger" onclick="deleteServer('${s.id}','${s.name}')">Delete</button>
</div>
</div>`}).join("");
}

function renderCreateWizard(){
const iran=servers.filter(s=>s.role==="iran"); const kharej=servers.filter(s=>s.role==="kharej");
document.getElementById("iran-server-select").innerHTML=iran.length?iran.map(s=>`<div class="server-select-card ${selectedIran===s.id?"selected":""}" onclick="selectIran('${s.id}')"><h4>${s.name}</h4><p>${s.ip}</p></div>`).join(""):'<div class="empty" style="padding:20px"><p style="font-size:12px">No Iran server added</p></div>';
document.getElementById("kharej-server-select").innerHTML=kharej.length?kharej.map(s=>`<div class="server-select-card ${selectedKharej===s.id?"selected":""}" onclick="selectKharej('${s.id}')"><h4>${s.name}</h4><p>${s.ip}</p></div>`).join(""):'<div class="empty" style="padding:20px"><p style="font-size:12px">No Kharej server added</p></div>';
}

function renderDiagnostics(){
const iran=servers.filter(s=>s.role==="iran"); const kharej=servers.filter(s=>s.role==="kharej");
document.getElementById("diag-iran-select").innerHTML='<option value="">Select Iran Server</option>'+iran.map(s=>`<option value="${s.id}">${s.name} (${s.ip})</option>`).join("");
document.getElementById("diag-kharej-select").innerHTML='<option value="">Select Kharej Server</option>'+kharej.map(s=>`<option value="${s.id}">${s.name} (${s.ip})</option>`).join("");
}

async function runDiagnostics(){
const iran_id = document.getElementById("diag-iran-select").value;
const kharej_id = document.getElementById("diag-kharej-select").value;
const port = document.getElementById("diag-port").value;
if(!iran_id || !kharej_id){showToast("Please select both servers","error");return;}
const btn = document.getElementById("btn-run-diag");
btn.disabled = true; btn.textContent = "Testing... Please wait (up to 20s)";
document.getElementById("diag-results").style.display = "none";
const r = await api("/api/tunnel/diagnostics", {iran_id: iran_id, kharej_id: kharej_id, test_port: port});
btn.disabled = false; btn.textContent = "Run Diagnostics";
if(r && r.success){
document.getElementById("diag-results").style.display = "block";
document.getElementById("diag-verdict").textContent = r.verdict;
document.getElementById("diag-verdict").style.color = r.score > 80 ? "var(--success)" : r.score > 40 ? "var(--warning)" : "var(--danger)";
document.getElementById("diag-tcp").innerHTML = r.tcp_open ? '<span style="color:var(--success)">OPEN</span>' : '<span style="color:var(--danger)">BLOCKED/CLOSED</span>';
document.getElementById("diag-loss").textContent = r.ping_loss;
document.getElementById("diag-ping").textContent = r.ping_avg;
document.getElementById("diag-score").textContent = r.score + "/100";
document.getElementById("diag-score").style.color = r.score > 80 ? "var(--success)" : r.score > 40 ? "var(--warning)" : "var(--danger)";
document.getElementById("diag-raw").textContent = r.ping_raw;
showToast("Diagnostics completed","success");
}else{
showToast("Diagnostics failed","error");
}
}

function renderDashboardTunnels(){
api("/api/tunnels").then(d=>{
if(!d)return;
const list=document.getElementById("dashboard-tunnels"); const tl=document.getElementById("all-tunnels");
const tunnels=d.tunnels||[];
if(tunnels.length===0){const h='<div class="empty"><div class="icon">🔍</div><p>No active tunnels discovered.</p></div>';list.innerHTML=h;tl.innerHTML=h;return}
const html=tunnels.map(t=>{
const sc=t.status==="running"?"running":"stopped";
const cb=t.cron_active?`<span class="cron-badge">↻ ${t.cron_interval}m</span>`:"";
return `<div class="tunnel-item">
<div class="tunnel-left">
<div class="tunnel-status ${sc}"></div>
<div>
<div class="tunnel-name">${t.service} <span class="tunnel-server-tag">${t.server_name}</span>${cb}</div>
<div class="tunnel-meta">
<span><b style="color:var(--primary)">Protocol:</b> ${t.transport.toUpperCase()}</span><span><b style="color:var(--secondary)">Bind:</b> ${t.bind_addr}</span><span><b>CPU:</b> ${t.cpu}%</span><span><b>Mem:</b> ${t.memory}</span>
</div>
</div>
</div>
<div class="tunnel-actions">
<button class="icon-btn start" title="Start" onclick="tunnelAction('start','${t.service}','${t.server_id}')">▶</button>
<button class="icon-btn stop" title="Stop" onclick="tunnelAction('stop','${t.service}','${t.server_id}')">⏹</button>
<button class="icon-btn restart" title="Restart" onclick="tunnelAction('restart','${t.service}','${t.server_id}')">🔄</button>
<button class="icon-btn ping" title="Live Ping" onclick="doPing('${t.service}','${t.server_id}','${t.bind_addr}')">🏓</button>
<button class="icon-btn" title="Logs" onclick="showLogs('${t.service}','${t.server_id}')">📄</button>
<button class="icon-btn" title="Edit Config" onclick="showConfig('${t.service}','${t.server_id}')">✏️</button>
<button class="icon-btn" title="Auto Restart" onclick="showCron('${t.service}','${t.server_id}',${t.cron_active},'${t.cron_interval}')">⏱</button>
<button class="icon-btn delete" title="Delete" onclick="doDelete('${t.service}','${t.server_id}')">🗑</button>
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
const iranSrv=servers.find(s=>s.id===selectedIran); const kharejSrv=servers.find(s=>s.id===selectedKharej);
if(!iranSrv||!kharejSrv){showToast("Select both servers first","error");wizardNext(1);return}
const portsRaw=document.getElementById("wiz-ports").value.trim();
let portsArr=[];
if(portsRaw){portsArr=portsRaw.split(",").map(p=>p.trim()).filter(Boolean).map(p=>{if(/^\\\\d+$/.test(p))return p+"=127.0.0.1:"+p;return p});}
const params={
iran_server:iranSrv,kharej_server:kharejSrv,
transport:document.getElementById("wiz-transport").value,
port:document.getElementById("wiz-port").value,
token:document.getElementById("wiz-token").value,
ports:portsArr.map(p=>'"'+p+'"').join(",")
};
const r=await api("/api/tunnel/create-both",params);
const ds=document.getElementById("deploy-status"); const dr=document.getElementById("deploy-result");
ds.style.display="none";dr.style.display="block";
if(r&&r.success){
dr.innerHTML=`<div style="text-align:center"><div style="font-size:50px;margin-bottom:16px;text-shadow:0 0 20px rgba(16,185,129,0.5)">✅</div><div style="font-size:20px;font-weight:600;color:var(--success)">Tunnel Established Successfully!</div>
<div style="margin-top:24px;text-align:left;background:rgba(0,0,0,0.4);border:1px solid var(--border);border-radius:16px;padding:20px;font-size:14px">
<div style="margin-bottom:10px"><strong>Secret Token:</strong> <span style="color:var(--primary);font-family:monospace">${r.token}</span></div>
<div style="margin-bottom:10px"><strong>Listen Port:</strong> ${r.port}</div>
<div style="margin-bottom:16px"><strong>Transport:</strong> ${r.transport.toUpperCase()}</div>
<div style="display:flex;justify-content:space-between;border-top:1px solid var(--border);padding-top:12px">
<div><span class="role-badge iran">IRAN</span> ${r.iran?"🟢 "+r.iran.service:"🔴 Failed"}</div>
<div><span class="role-badge kharej">KHAREJ</span> ${r.kharej?"🟢 "+r.kharej.service:"🔴 Failed"}</div>
</div>
</div>
<div style="margin-top:24px"><button class="btn btn-primary" onclick="wizardNext(1)" style="width:100%">Create Another Tunnel</button></div></div>`;
showToast("Tunnel deployed successfully!","success");refreshAll();
}else{
let errDetails = "";
if(r && r.iran && r.iran.error) errDetails += `<div style="color:var(--danger);font-family:monospace;margin-top:10px;font-size:12px;text-align:left;">Iran Node: ${r.iran.error}</div>`;
if(r && r.kharej && r.kharej.error) errDetails += `<div style="color:var(--danger);font-family:monospace;margin-top:10px;font-size:12px;text-align:left;">Kharej Node: ${r.kharej.error}</div>`;
dr.innerHTML=`<div style="text-align:center"><div style="font-size:50px;margin-bottom:16px;text-shadow:0 0 20px rgba(239,68,68,0.5)">❌</div><div style="font-size:20px;font-weight:600;color:var(--danger)">Deployment Failed</div>
<div style="margin-top:12px;font-size:14px;color:var(--text-muted)">Please check SSH connectivity and firewall settings.</div>
${errDetails}
<div style="margin-top:24px"><button class="btn btn-outline" onclick="wizardNext(1)" style="width:100%">Try Again</button></div></div>`;
showToast("Tunnel creation failed","error");
}
}

async function tunnelAction(action,svc,server_id){
showToast(action.toUpperCase()+" command sent...","info");
await api("/api/tunnel/action",{service:svc,action:action,server_id:server_id});
setTimeout(()=>{refreshAll();showToast("Action completed","success")},2000);
}

async function doDelete(svc,server_id){
if(!confirm("Are you sure you want to permanently delete "+svc+"?"))return;
await api("/api/tunnel/delete",{service:svc,server_id:server_id});
showToast(svc+" deleted","success");refreshAll();
}

async function doPing(svc, server_id, bind_addr) {
const targetIp = bind_addr.split(":")[0];
if (!targetIp || targetIp === "0.0.0.0") {
showToast("Target IP not valid for ping test.", "error"); return;
}
showToast("Testing connection to " + targetIp + "...", "info");
const d = await api("/api/tunnel/ping", {server_id: server_id, target_ip: targetIp});
if (d && d.success) {
showToast(`Ping: ${d.avg} | Loss: ${d.loss}`, "success");
} else {
showToast("Ping test failed.", "error");
}
}

async function showLogs(svc,server_id){
document.getElementById("modal-logs").classList.add("show");
document.getElementById("logs-content").textContent="Fetching secure logs...";
const d=await api("/api/tunnel/logs?svc="+encodeURIComponent(svc)+"&server_id="+server_id+"&lines=200");
if(d)document.getElementById("logs-content").textContent=d.logs||"No logs available.";
}

async function showConfig(svc,server_id){
document.getElementById("modal-config").classList.add("show");
currentConfigSvc=svc;currentConfigServerId=server_id;
const d=await api("/api/tunnel/config?svc="+encodeURIComponent(svc)+"&server_id="+server_id);
if(d)document.getElementById("config-content").value=d.config||"";
}

async function doSaveConfig(){
showToast("Applying configuration...","info");
await api("/api/tunnel/save_config",{service:currentConfigSvc,config:document.getElementById("config-content").value,server_id:currentConfigServerId});
closeModal("modal-config");showToast("Config saved & service restarted","success");refreshAll();
}

function showCron(svc,server_id,active,interval){
currentCronSvc=svc;currentCronServerId=server_id;
document.getElementById("modal-cron").classList.add("show");
document.getElementById("cron-svc-name").textContent=svc;
document.getElementById("btn-remove-cron").style.display=active?"inline-block":"none";
document.querySelectorAll(".cron-option").forEach(o=>{o.classList.toggle("active",active&&o.dataset.min===String(interval)); o.classList.toggle("btn-primary",active&&o.dataset.min===String(interval)); o.classList.toggle("btn-outline",!(active&&o.dataset.min===String(interval)))});
}

document.querySelectorAll(".cron-option").forEach(o=>{o.onclick=function(){document.querySelectorAll(".cron-option").forEach(x=>{x.classList.remove("active","btn-primary"); x.classList.add("btn-outline")});this.classList.add("active","btn-primary");this.classList.remove("btn-outline")}});

async function doSetCron(){
const a=document.querySelector(".cron-option.active");
if(!a){showToast("Select a schedule interval","error");return}
showToast("Applying schedule...","info");
await api("/api/tunnel/cron",{service:currentCronSvc,interval:parseInt(a.dataset.min),action:"set",server_id:currentCronServerId});
closeModal("modal-cron");showToast("Auto-restart schedule active","success");refreshAll();
}

async function doRemoveCron(){
await api("/api/tunnel/cron",{service:currentCronSvc,action:"remove",server_id:currentCronServerId});
closeModal("modal-cron");showToast("Auto-restart disabled","success");refreshAll();
}

function showAddServer(editId){
editingServerId=editId||"";
document.getElementById("server-modal-title").textContent=editId?"Edit Node Configuration":"Add New Server Node";

// Reset progress state & show form fields
document.getElementById("add-srv-form-fields").style.display = "block";
document.querySelector("#modal-add-server .modal-footer").style.display = "flex";
document.getElementById("add-srv-progress-container").style.display = "none";
const saveBtn = document.querySelector("#modal-add-server .modal-footer .btn-primary");
saveBtn.textContent = "Save Server";

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
if(!params.name||!params.ip){showToast("Label and IP address are required","error");return}

const fields = document.getElementById("add-srv-form-fields");
const footer = document.querySelector("#modal-add-server .modal-footer");
const progressContainer = document.getElementById("add-srv-progress-container");
const statusBar = document.getElementById("add-srv-progress-bar");
const statusText = document.getElementById("add-srv-status-text");
const pctText = document.getElementById("add-srv-pct-text");
const errorDetails = document.getElementById("add-srv-error-details");

// Hide inputs, show progress
fields.style.display = "none";
footer.style.display = "none";
progressContainer.style.display = "block";
errorDetails.style.display = "none";
statusBar.style.background = "linear-gradient(90deg, var(--primary), var(--secondary))";
statusBar.style.width = "0%";

// Fake progressive steps
let progress = 0;
statusText.textContent = "Connecting to remote server...";
pctText.textContent = "0%";

const interval = setInterval(() => {
    if (progress < 85) {
        progress += Math.floor(Math.random() * 10) + 2;
        if (progress > 85) progress = 85;
        statusBar.style.width = progress + "%";
        pctText.textContent = progress + "%";
        
        if (progress > 20 && progress <= 45) {
            statusText.textContent = "Initiating SSH handshake...";
        } else if (progress > 45 && progress <= 70) {
            statusText.textContent = "Authenticating credentials...";
        } else if (progress > 70) {
            statusText.textContent = "Verifying environment and host tools...";
        }
    }
}, 300);

let test;
try {
    test = await api("/api/server/test", {ip:params.ip, ssh_user:params.ssh_user, ssh_password:params.ssh_password, ssh_port:params.ssh_port, ssh_key:params.ssh_key});
} catch(e) {
    test = { success: false, output: String(e) };
}

clearInterval(interval);

if (test && test.success) {
    statusBar.style.width = "100%";
    pctText.textContent = "100%";
    statusBar.style.background = "var(--success)";
    statusText.textContent = "Connection Verified! Saving configuration...";
    
    // Perform save
    if (editingServerId) {
        params.id = editingServerId;
        await api("/api/server/update", params);
    } else {
        await api("/api/server/add", params);
    }
    
    setTimeout(() => {
        // Reset modal layout
        progressContainer.style.display = "none";
        fields.style.display = "block";
        footer.style.display = "flex";
        closeModal("modal-add-server");
        showToast("Server configuration saved", "success");
        loadServers();
    }, 1000);
} else {
    statusBar.style.width = "100%";
    pctText.textContent = "Failed";
    statusBar.style.background = "var(--danger)";
    statusText.textContent = "Verification Failed!";
    
    let errMsg = "Connection failed. Please check IP, port, and credentials.";
    if (test && test.output) {
        errMsg += `<br><span style="font-size:11px; opacity:0.8;">Details: ${test.output}</span>`;
    }
    errorDetails.innerHTML = errMsg;
    errorDetails.style.display = "block";
    
    // Show footer and let them try again
    footer.style.display = "flex";
    const saveBtn = footer.querySelector(".btn-primary");
    saveBtn.textContent = "Retry & Save";
    fields.style.display = "block";
}
}

async function deleteServer(id,name){
if(!confirm("Are you sure you want to remove "+name+" from the panel?"))return;
await api("/api/server/delete",{id:id});
showToast("Server removed","success");loadServers();
}

async function installBinary(server_id){
if(!confirm("Deploy the latest Backhaul binary to this node?"))return;
showToast("Downloading and installing...","info");
const r=await api("/api/install/binary",{server_id:server_id});
if(r&&r.success){
    let msg = "Successfully deployed: "+r.version;
    if(r.used_mirror) {
        msg += " (via Mirror fallback)";
    }
    showToast(msg,"success");
    loadServers();
}
else{showToast("Installation failed: "+(r?r.error||"Unknown error":"Connection failed"),"error")}
}

async function loadCurrentSettings(){
const r=await api("/api/settings/get");
if(r&&r.username){document.getElementById("set-username").value=r.username;document.getElementById("set-password").value="";}
}

async function updateSettings(){
const u=document.getElementById("set-username").value; const p=document.getElementById("set-password").value;
if(!u||!p){showToast("Username and new password are required","error");return;}
showToast("Updating credentials...","info");
const r=await api("/api/settings/update",{username:u,password:p});
if(r&&r.success){showToast("Credentials updated successfully","success");document.getElementById("set-password").value="";}
else{showToast("Failed to update credentials","error")}
}

function refreshAll(){loadServers();renderDashboardTunnels()}

loadServers();
setInterval(()=>{loadServers();renderDashboardTunnels()},15000);

document.querySelectorAll(".modal-overlay").forEach(m=>{m.addEventListener("click",function(e){if(e.target===this)this.classList.remove("show")})});
</script>
</body>
</html>"""


if __name__ == "__main__":
    os.makedirs(INSTALL_DIR, exist_ok=True)
    os.makedirs(CRON_CONFIG_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    os.makedirs(PANEL_DIR, exist_ok=True)

    server = ReuseAddrHTTPServer(("0.0.0.0", PORT), PanelHandler)
    local_ip = get_local_ip()
    print("")
    print("  BackhaulManager Web Panel v2.4.5")
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
