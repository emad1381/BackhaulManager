#!/usr/bin/env bash
# =============================================================================
#  Backhaul Free - Tunnel Manager
#  Version : 1.2.0
#  Author  : emad1381
#  Supports: TCP | TCPMUX | WSMUX | WSSMUX
#  Roles   : Iran (Server) | Kharej (Client)
# =============================================================================

set -uo pipefail

# Global server role — set once at startup, used everywhere
SERVER_ROLE=""

# ─── Colors & Symbols ────────────────────────────────────────────────────────
RED='\033[0;31m';    LRED='\033[1;31m'
GREEN='\033[0;32m';  LGREEN='\033[1;32m'
YELLOW='\033[1;33m'; LYELLOW='\033[0;33m'
BLUE='\033[0;34m';   LBLUE='\033[1;34m'
CYAN='\033[0;36m';   LCYAN='\033[1;36m'
MAGENTA='\033[0;35m';LMAGENTA='\033[1;35m'
WHITE='\033[1;37m';  GRAY='\033[0;37m'
DIM='\033[2m';       BOLD='\033[1m'
NC='\033[0m'

OK="${LGREEN}✔${NC}"; FAIL="${LRED}✘${NC}"; WARN="${YELLOW}⚠${NC}"
INFO="${LBLUE}ℹ${NC}"; ARROW="${CYAN}›${NC}"; BULLET="${MAGENTA}•${NC}"

# ─── Paths & Defaults ────────────────────────────────────────────────────────
INSTALL_DIR="/etc/backhaul"
BINARY="/usr/local/bin/backhaul"
CERT_DIR="$INSTALL_DIR/certs"
SERVICE_DIR="/etc/systemd/system"
BACKUP_DIR="$INSTALL_DIR/backups"

# ─── Helpers ─────────────────────────────────────────────────────────────────
die()        { echo -e "${FAIL} ${LRED}$*${NC}" >&2; exit 1; }
info()       { echo -e "${INFO} ${CYAN}$*${NC}"; }
success()    { echo -e "${OK}  ${LGREEN}$*${NC}"; }
warn()       { echo -e "${WARN} ${YELLOW}$*${NC}"; }
prompt()     { echo -ne "${ARROW} ${WHITE}$* ${NC}"; }
section()    { echo -e "\n${BOLD}${LBLUE}══ $* ══${NC}"; }
separator()  { echo -e "${DIM}$(printf '─%.0s' {1..60})${NC}"; }
press_enter(){ echo -e "\n${DIM}Press [Enter] to continue...${NC}"; read -r; }

require_root() {
    [[ $EUID -eq 0 ]] || die "This script must be run as root."
    mkdir -p "$CRON_CONFIG_DIR" 2>/dev/null || true
}

check_binary() {
    if [[ ! -x "$BINARY" ]]; then
        warn "Backhaul binary not found. Please install it first (Main Menu → Option 7)."
        press_enter
        return 1
    fi
}

detect_role() {
    # Check running services to guess role
    if systemctl list-units --type=service --state=running 2>/dev/null | grep -q "backhaul-iran"; then
        echo "iran"
    elif systemctl list-units --type=service --state=running 2>/dev/null | grep -q "backhaul-kharej"; then
        echo "kharej"
    else
        # Fallback: look at config files
        if ls "$INSTALL_DIR"/iran-*.toml 2>/dev/null | head -1 | grep -q .; then
            echo "iran"
        elif ls "$INSTALL_DIR"/kharej-*.toml 2>/dev/null | head -1 | grep -q .; then
            echo "kharej"
        else
            echo "unknown"
        fi
    fi
}

get_local_ip() {
    hostname -I 2>/dev/null | awk '{print $1}' || ip route get 1 2>/dev/null | awk '{print $7}' || echo "unknown"
}

service_status_color() {
    local svc="$1"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo -e "${LGREEN}● RUNNING${NC}"
    elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        echo -e "${YELLOW}○ STOPPED${NC}"
    else
        echo -e "${RED}✗ UNKNOWN${NC}"
    fi
}

port_in_use() {
    ss -tlnp 2>/dev/null | grep -q ":${1} " || \
    ss -tlnp 2>/dev/null | grep -q ":${1}$"
}

is_valid_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 ))
}

toml_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\r'/\\r}
    s=${s//$'\n'/\\n}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

get_service_config_path() {
    local svc="$1"
    local unit="${svc%.service}"
    local cfg=""

    if [[ "$unit" =~ ^backhaul-(iran|kharej)-([a-z0-9]+)-([0-9]+)$ ]]; then
        cfg="$INSTALL_DIR/${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]}.toml"
        [[ -f "$cfg" ]] && { printf '%s\n' "$cfg"; return 0; }
    fi

    local exec_line
    exec_line=$(systemctl cat "$svc" 2>/dev/null \
        | awk -F'ExecStart=' '/^[[:space:]]*ExecStart=/{print $2; exit}')
    [[ "$exec_line" == *" -c "* ]] || return 1

    cfg="${exec_line##* -c }"
    cfg="${cfg%%[[:space:]]*}"
    if [[ "$cfg" == "$INSTALL_DIR"/*.toml ]] && [[ -f "$cfg" ]]; then
        printf '%s\n' "$cfg"
        return 0
    fi
    return 1
}

backup_config() {
    local file="$1"
    [[ -f "$file" ]] || return
    mkdir -p "$BACKUP_DIR"
    local ts; ts=$(date +%Y%m%d-%H%M%S)
    cp "$file" "$BACKUP_DIR/$(basename "$file").bak.$ts"
}

generate_ssl_cert() {
    mkdir -p "$CERT_DIR"
    if [[ ! -f "$CERT_DIR/wssmux.crt" ]] || [[ ! -f "$CERT_DIR/wssmux.key" ]]; then
        info "Generating self-signed TLS certificate for WSSMUX..."
        openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/wssmux.key" \
            -out "$CERT_DIR/wssmux.crt" -days 3650 -nodes \
            -subj "/CN=backhaul-wssmux" 2>/dev/null \
            && success "TLS certificate generated." \
            || die "Failed to generate TLS certificate. Is openssl installed?"
    fi
}


# ─── Ask & Set Server Role (once at startup) ─────────────────────────────────
_print_logo() {
    echo -e "${BOLD}${LCYAN}"
    cat << 'LOGO'
  ██████╗  █████╗  ██████╗██╗  ██╗██╗  ██╗ █████╗ ██╗   ██╗██╗
  ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██║  ██║██╔══██╗██║   ██║██║
  ██████╔╝███████║██║     █████╔╝ ███████║███████║██║   ██║██║
  ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══██║██╔══██║██║   ██║██║
  ██████╔╝██║  ██║╚██████╗██║  ██╗██║  ██║██║  ██║╚██████╔╝███████╗
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
LOGO
    echo -e "${NC}"
}

ask_server_role() {
    clear
    _print_logo
    echo -e "  ${DIM}Backhaul Free Tunnel Manager v1.2.0 by ${NC}${CYAN}emad1381${NC}"
    echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Try auto-detect first
    local auto_role; auto_role=$(detect_role)

    echo -e "\n  ${BOLD}${WHITE}Which server is this?${NC}"
    echo -e "  ${DIM}This setting applies to all tunnel operations in this session.${NC}\n"
    echo -e "  ${WHITE}[1]${NC} ${LGREEN}IRAN${NC}   — Server inside Iran   ${DIM}(acts as listener / server side)${NC}"
    echo -e "  ${WHITE}[2]${NC} ${LBLUE}KHAREJ${NC} — Server outside Iran  ${DIM}(acts as connector / client side)${NC}"

    if [[ "$auto_role" != "unknown" ]]; then
        echo -e "\n  ${DIM}  Auto-detected from existing services: ${LYELLOW}${auto_role}${NC}"
        echo -e "  ${DIM}  Press Enter to accept auto-detected role.${NC}"
    fi

    echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    prompt "Choice [1/2]:"; read -r _rc

    if [[ -z "$_rc" ]] && [[ "$auto_role" != "unknown" ]]; then
        SERVER_ROLE="$auto_role"
    else
        case "$_rc" in
            1) SERVER_ROLE="iran" ;;
            2) SERVER_ROLE="kharej" ;;
            *) warn "Invalid choice — defaulting to auto-detect or Iran."
               SERVER_ROLE="$auto_role" ;;
        esac
    fi

    if [[ "$SERVER_ROLE" != "iran" ]] && [[ "$SERVER_ROLE" != "kharej" ]]; then
        SERVER_ROLE="iran"
    fi

    success "Server role set to: ${BOLD}$(echo "$SERVER_ROLE" | tr '[:lower:]' '[:upper:]')${NC}"
    sleep 0.8
}

# ─── Header ──────────────────────────────────────────────────────────────────
print_header() {
    clear
    local ip; ip=$(get_local_ip)
    local role_label role_color
    case "$SERVER_ROLE" in
        iran)   role_label="IRAN  (Server)"; role_color="$LGREEN" ;;
        kharej) role_label="KHAREJ (Client)"; role_color="$LBLUE" ;;
        *)      role_label="NOT SET";         role_color="$YELLOW" ;;
    esac

    _print_logo
    echo -e "  ${DIM}Backhaul Free Tunnel Manager v1.2.0 by ${NC}${CYAN}emad1381${NC}"
    echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${GRAY}IP   : ${WHITE}$ip${NC}   ${GRAY}Role : ${role_color}${BOLD}$role_label${NC}"
    [[ -x "$BINARY" ]] && {
        local ver; ver=$("$BINARY" --version 2>/dev/null | head -1 || echo "v0.7.x")
        echo -e "  ${GRAY}Binary: ${WHITE}$ver${NC}   ${GRAY}Path : ${DIM}$BINARY${NC}"
    }
    echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# ─── INSTALL ─────────────────────────────────────────────────────────────────
menu_install() {
    section "Install / Update Backhaul Binary"
    mkdir -p "$INSTALL_DIR" "$BACKUP_DIR"

    # Detect arch for correct download URL
    local arch; arch=$(uname -m)
    local gh_asset
    case "$arch" in
        x86_64)  gh_asset="backhaul_linux_amd64.tar.gz" ;;
        aarch64|arm64) gh_asset="backhaul_linux_arm64.tar.gz" ;;
        *) gh_asset="backhaul_linux_amd64.tar.gz" ;;
    esac
    local gh_url="https://github.com/Musixal/Backhaul/releases/latest/download/${gh_asset}"

    local dest_archive="$INSTALL_DIR/$gh_asset"
    local source_archive=""
    local custom_url=""

    [[ -x "$BINARY" ]] && \
        echo -e "  ${DIM}Current version: $("$BINARY" --version 2>/dev/null | head -1 || echo 'unknown')${NC}\n"

    echo -e "  ${BOLD}${WHITE}Select installation source:${NC}\n"
    echo -e "  ${WHITE}[1]${NC} ${LGREEN}GitHub${NC}      — Download latest release automatically"
    echo -e "            ${DIM}(${gh_url})${NC}"
    echo -e "  ${WHITE}[2]${NC} ${LYELLOW}Mirror URL${NC}  — Enter a custom download URL manually"
    echo -e "  ${WHITE}[3]${NC} ${LCYAN}Local file${NC}  — Use a file already on this server"
    echo -e "            ${DIM}(e.g. /root/backhaul_linux_amd64.tar.gz)${NC}"
    echo -e "  ${WHITE}[0]${NC} Cancel"
    separator
    prompt "Choice:"; read -r dl_choice

    case "$dl_choice" in
        1)
            custom_url="$gh_url"
            ;;
        2)
            prompt "Enter mirror/custom URL:"; read -r custom_url
            [[ -z "$custom_url" ]] && { warn "No URL entered."; return; }
            ;;
        3)
            prompt "Full path to archive [/root/backhaul_linux_amd64.tar.gz]:"; read -r local_path
            local_path="${local_path:-/root/backhaul_linux_amd64.tar.gz}"
            if [[ ! -f "$local_path" ]]; then
                warn "File not found: $local_path"
                return
            fi
            source_archive="$local_path"
            ;;
        0) return ;;
        *) warn "Invalid choice"; return ;;
    esac

    # Download if URL was given
    if [[ -n "$custom_url" ]]; then
        info "Downloading: $custom_url"
        if command -v wget &>/dev/null; then
            wget -q --show-progress -O "$dest_archive" "$custom_url" \
                || { warn "Download failed."; return; }
        elif command -v curl &>/dev/null; then
            curl -L --progress-bar -o "$dest_archive" "$custom_url" \
                || { warn "Download failed."; return; }
        else
            warn "Neither wget nor curl found. Install one and retry."
            return
        fi
        source_archive="$dest_archive"
    fi

    # Backup existing binary
    if [[ -x "$BINARY" ]]; then
        local ts; ts=$(date +%Y%m%d-%H%M%S)
        mkdir -p "$BACKUP_DIR"
        cp "$BINARY" "$BACKUP_DIR/backhaul.bak.$ts"
        info "Previous binary backed up to $BACKUP_DIR"
    fi

    # Extract to temp dir then install to /usr/local/bin
    local tmp_dir; tmp_dir=$(mktemp -d)
    info "Extracting archive..."
    tar -xzf "$source_archive" -C "$tmp_dir" 2>/dev/null \
        || { warn "Extraction failed. Is the file a valid tar.gz?"; rm -rf "$tmp_dir"; return; }

    # Find the binary inside extracted contents
    local extracted_bin; extracted_bin=$(find "$tmp_dir" -type f -name "backhaul" | head -1)
    if [[ -z "$extracted_bin" ]]; then
        warn "Could not find 'backhaul' binary inside the archive."
        rm -rf "$tmp_dir"; return
    fi

    cp "$extracted_bin" "$BINARY"
    chmod +x "$BINARY"
    rm -rf "$tmp_dir"

    local new_ver; new_ver=$("$BINARY" --version 2>/dev/null | head -1 || echo 'OK')
    success "Backhaul installed successfully — $new_ver"
    echo -e "  ${BULLET} Binary : ${CYAN}$BINARY${NC}"
    echo -e "  ${BULLET} Configs: ${DIM}$INSTALL_DIR${NC}"
    press_enter
}

# ─── TUNNEL STATUS ───────────────────────────────────────────────────────────
show_status() {
    section "Tunnel Status Overview"
    local found=0

    # Get all backhaul services
    mapfile -t services < <(systemctl list-unit-files --type=service 2>/dev/null \
        | grep -o 'backhaul[^ ]*\.service' | sort -u)

    if [[ ${#services[@]} -eq 0 ]]; then
        warn "No Backhaul services found."
        press_enter; return
    fi

    printf "  %-38s %-14s %-10s %-10s\n" \
        "${BOLD}${WHITE}Service${NC}" "${BOLD}${WHITE}Status${NC}" \
        "${BOLD}${WHITE}CPU${NC}" "${BOLD}${WHITE}Memory${NC}"
    separator

    for svc in "${services[@]}"; do
        local status cpu mem pid
        status=$(service_status_color "$svc")
        pid=$(systemctl show -p MainPID --value "$svc" 2>/dev/null || echo "0")
        if [[ "$pid" != "0" ]] && [[ -d "/proc/$pid" ]]; then
            cpu=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ' || echo "—")
            mem=$(ps -p "$pid" -o rss= 2>/dev/null | awk '{printf "%.1fM", $1/1024}' || echo "—")
        else
            cpu="—"; mem="—"
        fi
        printf "  %-38s %-24s %-10s %-10s\n" \
            "${CYAN}$svc${NC}" "$status" "$cpu" "$mem"
        found=1
    done

    [[ $found -eq 0 ]] && warn "No services listed."
    separator

    # Show config file mapping
    echo -e "\n  ${BOLD}${WHITE}Config Mapping:${NC}"
    while IFS= read -r toml; do
        local transport bind_or_remote ports_count
        transport=$(grep -m1 'transport' "$toml" 2>/dev/null | awk -F'"' '{print $2}' || echo "?")
        bind_or_remote=$(grep -m1 'bind_addr\|remote_addr' "$toml" 2>/dev/null | awk -F'"' '{print $2}' || echo "?")
        ports_count=$(grep -c '"' <<< "$(grep 'ports\|="' "$toml" 2>/dev/null | grep -v '#')" 2>/dev/null || echo "0")
        echo -e "  ${BULLET} ${DIM}$(basename "$toml")${NC} → ${LYELLOW}$transport${NC} @ ${WHITE}$bind_or_remote${NC}"
    done < <(find "$INSTALL_DIR" -maxdepth 1 -name "*.toml" 2>/dev/null | sort)

    press_enter
}

# ─── PRESET DEFAULTS ─────────────────────────────────────────────────────────
# These are per-protocol. log_level for TCP uses "info" as a safe default;
# mux/wsmux/wssmux already use "info" in practice.
# Iran / Server side
PRESET_IRAN_KEEPALIVE=75
PRESET_IRAN_NODELAY=true
PRESET_IRAN_HEARTBEAT=40
PRESET_IRAN_CHANNEL_SIZE=4096
PRESET_IRAN_MUX_CON=8
PRESET_IRAN_MUX_VERSION=1
PRESET_IRAN_MUX_FRAMESIZE=32768
PRESET_IRAN_MUX_RECVBUF=4194304
PRESET_IRAN_MUX_STREAMBUF=65536
PRESET_IRAN_SNIFFER=false
PRESET_IRAN_WEB_PORT=0
PRESET_IRAN_LOG_LEVEL_TCP="info"
PRESET_IRAN_LOG_LEVEL_MUX="info"
PRESET_IRAN_MSS=1360
PRESET_IRAN_SO_RCVBUF=4194304
PRESET_IRAN_SO_SNDBUF=4194304

# Kharej / Client side
PRESET_KHAREJ_CONN_POOL=8
PRESET_KHAREJ_AGGRESSIVE_POOL=false
PRESET_KHAREJ_KEEPALIVE=75
PRESET_KHAREJ_DIAL_TIMEOUT=10
PRESET_KHAREJ_RETRY_INTERVAL=3
PRESET_KHAREJ_NODELAY=true
PRESET_KHAREJ_MUX_VERSION=1
PRESET_KHAREJ_MUX_FRAMESIZE=32768
PRESET_KHAREJ_MUX_RECVBUF=4194304
PRESET_KHAREJ_MUX_STREAMBUF=65536
PRESET_KHAREJ_SNIFFER=false
PRESET_KHAREJ_WEB_PORT=0
PRESET_KHAREJ_LOG_LEVEL_TCP="info"
PRESET_KHAREJ_LOG_LEVEL_MUX="info"
PRESET_KHAREJ_MSS=1360
PRESET_KHAREJ_SO_RCVBUF=4194304
PRESET_KHAREJ_SO_SNDBUF=4194304

# ─── SHOW PRESET SUMMARY ─────────────────────────────────────────────────────
_show_preset_summary() {
    local role="$1" transport="$2"
    echo -e "\n  ${BOLD}${WHITE}Preset values that will be applied:${NC}"
    separator
    if [[ "$role" == "iran" ]]; then
        echo -e "  ${BULLET} keepalive_period  = ${LYELLOW}${PRESET_IRAN_KEEPALIVE}${NC}s"
        echo -e "  ${BULLET} nodelay           = ${LYELLOW}${PRESET_IRAN_NODELAY}${NC}"
        echo -e "  ${BULLET} heartbeat         = ${LYELLOW}${PRESET_IRAN_HEARTBEAT}${NC}s"
        echo -e "  ${BULLET} channel_size      = ${LYELLOW}${PRESET_IRAN_CHANNEL_SIZE}${NC}"
        local _ll_iran; _ll_iran=$([[ "$transport" == "tcp" ]] && echo "$PRESET_IRAN_LOG_LEVEL_TCP" || echo "$PRESET_IRAN_LOG_LEVEL_MUX")
        if [[ "$transport" != "tcp" ]]; then
            echo -e "  ${BULLET} mux_con           = ${LYELLOW}${PRESET_IRAN_MUX_CON}${NC}"
            echo -e "  ${BULLET} mux_version       = ${LYELLOW}${PRESET_IRAN_MUX_VERSION}${NC}"
            echo -e "  ${BULLET} mux_framesize     = ${LYELLOW}${PRESET_IRAN_MUX_FRAMESIZE}${NC} (32KB)"
            echo -e "  ${BULLET} mux_recievebuffer = ${LYELLOW}${PRESET_IRAN_MUX_RECVBUF}${NC} (4MB)"
            echo -e "  ${BULLET} mux_streambuffer  = ${LYELLOW}${PRESET_IRAN_MUX_STREAMBUF}${NC} (64KB)"
        fi
        echo -e "  ${BULLET} log_level         = ${LYELLOW}${_ll_iran}${NC}"
        if [[ "$transport" == "tcp" ]] || [[ "$transport" == "tcpmux" ]]; then
            echo -e "  ${BULLET} mss               = ${LYELLOW}${PRESET_IRAN_MSS}${NC}"
            echo -e "  ${BULLET} so_rcvbuf         = ${LYELLOW}${PRESET_IRAN_SO_RCVBUF}${NC} (4MB)"
            echo -e "  ${BULLET} so_sndbuf         = ${LYELLOW}${PRESET_IRAN_SO_SNDBUF}${NC} (4MB)"
        fi
        echo -e "  ${BULLET} sniffer           = ${LYELLOW}${PRESET_IRAN_SNIFFER}${NC}"
        echo -e "  ${BULLET} web_port          = ${LYELLOW}${PRESET_IRAN_WEB_PORT}${NC} (disabled)"
    else
        local _ll_kharej; _ll_kharej=$([[ "$transport" == "tcp" ]] && echo "$PRESET_KHAREJ_LOG_LEVEL_TCP" || echo "$PRESET_KHAREJ_LOG_LEVEL_MUX")
        echo -e "  ${BULLET} connection_pool   = ${LYELLOW}${PRESET_KHAREJ_CONN_POOL}${NC}"
        echo -e "  ${BULLET} aggressive_pool   = ${LYELLOW}${PRESET_KHAREJ_AGGRESSIVE_POOL}${NC}"
        echo -e "  ${BULLET} keepalive_period  = ${LYELLOW}${PRESET_KHAREJ_KEEPALIVE}${NC}s"
        echo -e "  ${BULLET} dial_timeout      = ${LYELLOW}${PRESET_KHAREJ_DIAL_TIMEOUT}${NC}s"
        echo -e "  ${BULLET} retry_interval    = ${LYELLOW}${PRESET_KHAREJ_RETRY_INTERVAL}${NC}s"
        echo -e "  ${BULLET} nodelay           = ${LYELLOW}${PRESET_KHAREJ_NODELAY}${NC}"
        if [[ "$transport" != "tcp" ]]; then
            echo -e "  ${BULLET} mux_version       = ${LYELLOW}${PRESET_KHAREJ_MUX_VERSION}${NC}"
            echo -e "  ${BULLET} mux_framesize     = ${LYELLOW}${PRESET_KHAREJ_MUX_FRAMESIZE}${NC} (32KB)"
            echo -e "  ${BULLET} mux_recievebuffer = ${LYELLOW}${PRESET_KHAREJ_MUX_RECVBUF}${NC} (4MB)"
            echo -e "  ${BULLET} mux_streambuffer  = ${LYELLOW}${PRESET_KHAREJ_MUX_STREAMBUF}${NC} (64KB)"
        fi
        echo -e "  ${BULLET} log_level         = ${LYELLOW}${_ll_kharej}${NC}"
        if [[ "$transport" == "tcp" ]] || [[ "$transport" == "tcpmux" ]]; then
            echo -e "  ${BULLET} mss               = ${LYELLOW}${PRESET_KHAREJ_MSS}${NC}"
            echo -e "  ${BULLET} so_rcvbuf         = ${LYELLOW}${PRESET_KHAREJ_SO_RCVBUF}${NC} (4MB)"
            echo -e "  ${BULLET} so_sndbuf         = ${LYELLOW}${PRESET_KHAREJ_SO_SNDBUF}${NC} (4MB)"
        fi
        echo -e "  ${BULLET} sniffer           = ${LYELLOW}${PRESET_KHAREJ_SNIFFER}${NC}"
        echo -e "  ${BULLET} web_port          = ${LYELLOW}${PRESET_KHAREJ_WEB_PORT}${NC} (disabled)"
    fi
    separator
}

# ─── ADVANCED INPUT (ask every parameter) ────────────────────────────────────
_ask_advanced_iran() {
    local transport="$1"

    prompt "keepalive_period [${PRESET_IRAN_KEEPALIVE}]:"; read -r v
    ADV_KEEPALIVE="${v:-$PRESET_IRAN_KEEPALIVE}"

    prompt "nodelay [${PRESET_IRAN_NODELAY}]:"; read -r v
    ADV_NODELAY="${v:-$PRESET_IRAN_NODELAY}"

    prompt "heartbeat [${PRESET_IRAN_HEARTBEAT}]:"; read -r v
    ADV_HEARTBEAT="${v:-$PRESET_IRAN_HEARTBEAT}"

    prompt "channel_size [${PRESET_IRAN_CHANNEL_SIZE}]:"; read -r v
    ADV_CHANNEL_SIZE="${v:-$PRESET_IRAN_CHANNEL_SIZE}"

    if [[ "$transport" != "tcp" ]]; then
        prompt "mux_con [${PRESET_IRAN_MUX_CON}]:"; read -r v
        ADV_MUX_CON="${v:-$PRESET_IRAN_MUX_CON}"

        prompt "mux_version [${PRESET_IRAN_MUX_VERSION}]:"; read -r v
        ADV_MUX_VERSION="${v:-$PRESET_IRAN_MUX_VERSION}"

        prompt "mux_framesize [${PRESET_IRAN_MUX_FRAMESIZE}]:"; read -r v
        ADV_MUX_FRAMESIZE="${v:-$PRESET_IRAN_MUX_FRAMESIZE}"

        prompt "mux_recievebuffer [${PRESET_IRAN_MUX_RECVBUF}]:"; read -r v
        ADV_MUX_RECVBUF="${v:-$PRESET_IRAN_MUX_RECVBUF}"

        prompt "mux_streambuffer [${PRESET_IRAN_MUX_STREAMBUF}]:"; read -r v
        ADV_MUX_STREAMBUF="${v:-$PRESET_IRAN_MUX_STREAMBUF}"
    else
        ADV_MUX_CON="$PRESET_IRAN_MUX_CON"
        ADV_MUX_VERSION="$PRESET_IRAN_MUX_VERSION"
        ADV_MUX_FRAMESIZE="$PRESET_IRAN_MUX_FRAMESIZE"
        ADV_MUX_RECVBUF="$PRESET_IRAN_MUX_RECVBUF"
        ADV_MUX_STREAMBUF="$PRESET_IRAN_MUX_STREAMBUF"
    fi

    local _def_ll_iran; _def_ll_iran=$([[ "$transport" == "tcp" ]] && echo "$PRESET_IRAN_LOG_LEVEL_TCP" || echo "$PRESET_IRAN_LOG_LEVEL_MUX")
    echo -e "  ${DIM}log_level options: panic | fatal | error | warn | info | debug | trace${NC}"
    prompt "log_level [${_def_ll_iran}]:"; read -r v
    ADV_LOG_LEVEL="${v:-$_def_ll_iran}"

    prompt "mss [${PRESET_IRAN_MSS}]:"; read -r v
    ADV_MSS="${v:-$PRESET_IRAN_MSS}"

    prompt "so_rcvbuf [${PRESET_IRAN_SO_RCVBUF}]:"; read -r v
    ADV_SO_RCVBUF="${v:-$PRESET_IRAN_SO_RCVBUF}"

    prompt "so_sndbuf [${PRESET_IRAN_SO_SNDBUF}]:"; read -r v
    ADV_SO_SNDBUF="${v:-$PRESET_IRAN_SO_SNDBUF}"

    prompt "sniffer (true/false) [${PRESET_IRAN_SNIFFER}]:"; read -r v
    ADV_SNIFFER="${v:-$PRESET_IRAN_SNIFFER}"

    prompt "web_port (0=disable) [${PRESET_IRAN_WEB_PORT}]:"; read -r v
    ADV_WEB_PORT="${v:-$PRESET_IRAN_WEB_PORT}"
}

_ask_advanced_kharej() {
    local transport="$1"

    prompt "connection_pool [${PRESET_KHAREJ_CONN_POOL}]:"; read -r v
    ADV_CONN_POOL="${v:-$PRESET_KHAREJ_CONN_POOL}"

    prompt "aggressive_pool (true/false) [${PRESET_KHAREJ_AGGRESSIVE_POOL}]:"; read -r v
    ADV_AGGRESSIVE_POOL="${v:-$PRESET_KHAREJ_AGGRESSIVE_POOL}"

    prompt "keepalive_period [${PRESET_KHAREJ_KEEPALIVE}]:"; read -r v
    ADV_KEEPALIVE="${v:-$PRESET_KHAREJ_KEEPALIVE}"

    prompt "dial_timeout [${PRESET_KHAREJ_DIAL_TIMEOUT}]:"; read -r v
    ADV_DIAL_TIMEOUT="${v:-$PRESET_KHAREJ_DIAL_TIMEOUT}"

    prompt "retry_interval [${PRESET_KHAREJ_RETRY_INTERVAL}]:"; read -r v
    ADV_RETRY_INTERVAL="${v:-$PRESET_KHAREJ_RETRY_INTERVAL}"

    prompt "nodelay (true/false) [${PRESET_KHAREJ_NODELAY}]:"; read -r v
    ADV_NODELAY="${v:-$PRESET_KHAREJ_NODELAY}"

    if [[ "$transport" != "tcp" ]]; then
        prompt "mux_version [${PRESET_KHAREJ_MUX_VERSION}]:"; read -r v
        ADV_MUX_VERSION="${v:-$PRESET_KHAREJ_MUX_VERSION}"

        prompt "mux_framesize [${PRESET_KHAREJ_MUX_FRAMESIZE}]:"; read -r v
        ADV_MUX_FRAMESIZE="${v:-$PRESET_KHAREJ_MUX_FRAMESIZE}"

        prompt "mux_recievebuffer [${PRESET_KHAREJ_MUX_RECVBUF}]:"; read -r v
        ADV_MUX_RECVBUF="${v:-$PRESET_KHAREJ_MUX_RECVBUF}"

        prompt "mux_streambuffer [${PRESET_KHAREJ_MUX_STREAMBUF}]:"; read -r v
        ADV_MUX_STREAMBUF="${v:-$PRESET_KHAREJ_MUX_STREAMBUF}"
    else
        ADV_MUX_VERSION="$PRESET_KHAREJ_MUX_VERSION"
        ADV_MUX_FRAMESIZE="$PRESET_KHAREJ_MUX_FRAMESIZE"
        ADV_MUX_RECVBUF="$PRESET_KHAREJ_MUX_RECVBUF"
        ADV_MUX_STREAMBUF="$PRESET_KHAREJ_MUX_STREAMBUF"
    fi

    local _def_ll_kharej; _def_ll_kharej=$([[ "$transport" == "tcp" ]] && echo "$PRESET_KHAREJ_LOG_LEVEL_TCP" || echo "$PRESET_KHAREJ_LOG_LEVEL_MUX")
    echo -e "  ${DIM}log_level options: panic | fatal | error | warn | info | debug | trace${NC}"
    prompt "log_level [${_def_ll_kharej}]:"; read -r v
    ADV_LOG_LEVEL="${v:-$_def_ll_kharej}"

    prompt "mss [${PRESET_KHAREJ_MSS}]:"; read -r v
    ADV_MSS="${v:-$PRESET_KHAREJ_MSS}"

    prompt "so_rcvbuf [${PRESET_KHAREJ_SO_RCVBUF}]:"; read -r v
    ADV_SO_RCVBUF="${v:-$PRESET_KHAREJ_SO_RCVBUF}"

    prompt "so_sndbuf [${PRESET_KHAREJ_SO_SNDBUF}]:"; read -r v
    ADV_SO_SNDBUF="${v:-$PRESET_KHAREJ_SO_SNDBUF}"

    prompt "sniffer (true/false) [${PRESET_KHAREJ_SNIFFER}]:"; read -r v
    ADV_SNIFFER="${v:-$PRESET_KHAREJ_SNIFFER}"

    prompt "web_port (0=disable) [${PRESET_KHAREJ_WEB_PORT}]:"; read -r v
    ADV_WEB_PORT="${v:-$PRESET_KHAREJ_WEB_PORT}"
}

# ─── WRITE CONFIG FILES ───────────────────────────────────────────────────────
# Notes on parameter applicability (verified against real configs):
#   accept_udp  : TCP only (server/Iran)
#   mux_*       : TCPMUX, WSMUX, WSSMUX only
#   tls_cert/key: WSSMUX only
#   mss, so_*   : TCP and TCPMUX only (NOT wsmux/wssmux)
#   edge_ip     : WSMUX and WSSMUX only (client/Kharej)

_write_iran_config() {
    local config_file="$1" transport="$2" tunnel_port="$3" token="$4"
    shift 4
    local ports=("$@")
    local token_e; token_e=$(toml_escape "$token")

    {
        echo "[server]"
        echo "bind_addr = \"0.0.0.0:${tunnel_port}\""
        echo "transport = \"${transport}\""
        # accept_udp only for TCP transport
        [[ "$transport" == "tcp" ]] && echo "accept_udp = false"
        echo "token = \"${token_e}\""
        echo "keepalive_period = ${ADV_KEEPALIVE}"
        echo "nodelay = ${ADV_NODELAY}"
        echo "heartbeat = ${ADV_HEARTBEAT}"
        echo "channel_size = ${ADV_CHANNEL_SIZE}"
        # mux params: TCPMUX, WSMUX, WSSMUX
        if [[ "$transport" != "tcp" ]]; then
            echo "mux_con = ${ADV_MUX_CON}"
            echo "mux_version = ${ADV_MUX_VERSION}"
            echo "mux_framesize = ${ADV_MUX_FRAMESIZE}"
            echo "mux_recievebuffer = ${ADV_MUX_RECVBUF}"
            echo "mux_streambuffer = ${ADV_MUX_STREAMBUF}"
        fi
        # TLS certs: WSSMUX only
        if [[ "$transport" == "wssmux" ]]; then
            echo "tls_cert = \"${CERT_DIR}/wssmux.crt\""
            echo "tls_key = \"${CERT_DIR}/wssmux.key\""
        fi
        echo "sniffer = ${ADV_SNIFFER}"
        echo "web_port = ${ADV_WEB_PORT}"
        echo "log_level = \"${ADV_LOG_LEVEL}\""
        # mss / so_rcvbuf / so_sndbuf: TCP and TCPMUX only
        if [[ "$transport" == "tcp" ]] || [[ "$transport" == "tcpmux" ]]; then
            echo "mss = ${ADV_MSS}"
            echo "so_rcvbuf = ${ADV_SO_RCVBUF}"
            echo "so_sndbuf = ${ADV_SO_SNDBUF}"
        fi
        echo "ports = ["
        local last_idx=$(( ${#ports[@]} - 1 ))
        local idx=0
        for p in "${ports[@]}"; do
            local p_e; p_e=$(toml_escape "$p")
            if [[ $idx -lt $last_idx ]]; then
                echo "  \"$p_e\","
            else
                echo "  \"$p_e\""
            fi
            idx=$(( idx + 1 ))
        done
        echo "]"
    } > "$config_file"
}

_write_kharej_config() {
    local config_file="$1" transport="$2" tunnel_port="$3" iran_ip="$4" token="$5"
    local iran_ip_e token_e
    iran_ip_e=$(toml_escape "$iran_ip")
    token_e=$(toml_escape "$token")

    {
        echo "[client]"
        echo "remote_addr = \"${iran_ip_e}:${tunnel_port}\""
        # edge_ip: WSMUX and WSSMUX only
        if [[ "$transport" == "wsmux" ]] || [[ "$transport" == "wssmux" ]]; then
            echo "edge_ip = \"\""
        fi
        echo "transport = \"${transport}\""
        echo "token = \"${token_e}\""
        echo "connection_pool = ${ADV_CONN_POOL}"
        echo "aggressive_pool = ${ADV_AGGRESSIVE_POOL}"
        echo "keepalive_period = ${ADV_KEEPALIVE}"
        echo "nodelay = ${ADV_NODELAY}"
        echo "retry_interval = ${ADV_RETRY_INTERVAL}"
        echo "dial_timeout = ${ADV_DIAL_TIMEOUT}"
        # mux params: TCPMUX, WSMUX, WSSMUX
        if [[ "$transport" != "tcp" ]]; then
            echo "mux_version = ${ADV_MUX_VERSION}"
            echo "mux_framesize = ${ADV_MUX_FRAMESIZE}"
            echo "mux_recievebuffer = ${ADV_MUX_RECVBUF}"
            echo "mux_streambuffer = ${ADV_MUX_STREAMBUF}"
        fi
        echo "sniffer = ${ADV_SNIFFER}"
        echo "web_port = ${ADV_WEB_PORT}"
        echo "log_level = \"${ADV_LOG_LEVEL}\""
        # mss / so_rcvbuf / so_sndbuf: TCP and TCPMUX only
        if [[ "$transport" == "tcp" ]] || [[ "$transport" == "tcpmux" ]]; then
            echo "mss = ${ADV_MSS}"
            echo "so_rcvbuf = ${ADV_SO_RCVBUF}"
            echo "so_sndbuf = ${ADV_SO_SNDBUF}"
        fi
    } > "$config_file"
}

# ─── CREATE TUNNEL ───────────────────────────────────────────────────────────
menu_create_tunnel() {
    section "Create New Tunnel"
    check_binary || return

    # Use globally-set SERVER_ROLE (set at startup)
    local ROLE="$SERVER_ROLE"
    local role_label role_color
    case "$ROLE" in
        iran)   role_label="IRAN (Server)";   role_color="$LGREEN" ;;
        kharej) role_label="KHAREJ (Client)"; role_color="$LBLUE" ;;
        *)      warn "Invalid server role. Please restart the script and select Iran or Kharej."; return ;;
    esac
    echo -e "  ${DIM}Server role: ${role_color}${BOLD}${role_label}${NC}"
    separator

    # ── Step 1: Transport ─────────────────────────────────────────────────────
    echo -e "\n  ${BOLD}${WHITE}Step 1 of 3 — Transport Protocol${NC}"
    echo -e "  ${WHITE}[1]${NC} ${LYELLOW}TCP${NC}    — Simple & lightweight, no multiplexing"
    echo -e "  ${WHITE}[2]${NC} ${LYELLOW}TCPMUX${NC} — TCP + SMUX multiplexing"
    echo -e "  ${WHITE}[3]${NC} ${LYELLOW}WSMUX${NC}  — WebSocket + mux, works through CDN/proxies"
    echo -e "  ${WHITE}[4]${NC} ${LYELLOW}WSSMUX${NC} — WebSocket Secure (TLS) + mux, encrypted ${LGREEN}(recommended)${NC}"
    separator
    prompt "Choice [1-4]:"; read -r proto_choice

    local TRANSPORT
    case "$proto_choice" in
        1) TRANSPORT="tcp" ;;
        2) TRANSPORT="tcpmux" ;;
        3) TRANSPORT="wsmux" ;;
        4) TRANSPORT="wssmux" ;;
        *) warn "Invalid choice"; return ;;
    esac

    # ── Step 2: Essential params (always asked) ───────────────────────────────
    echo -e "\n  ${BOLD}${WHITE}Step 2 of 3 — Essential Settings${NC}"
    separator

    local default_tunnel_port
    case "$TRANSPORT" in
        tcp)    default_tunnel_port=8443 ;;
        tcpmux) default_tunnel_port=9443 ;;
        wsmux)  default_tunnel_port=9643 ;;
        wssmux) default_tunnel_port=9743 ;;
    esac

    prompt "Tunnel listen/connect port [${default_tunnel_port}]:"; read -r TUNNEL_PORT
    TUNNEL_PORT="${TUNNEL_PORT:-$default_tunnel_port}"
    if ! is_valid_port "$TUNNEL_PORT"; then
        warn "Invalid tunnel port: $TUNNEL_PORT"
        return
    fi

    local IRAN_IP=""
    if [[ "$ROLE" == "iran" ]]; then
        echo -e "  ${DIM}(Iran server listens — no peer IP needed on server side)${NC}"
    else
        prompt "Iran server IP address:"; read -r IRAN_IP
        [[ -z "$IRAN_IP" ]] && { warn "Iran server IP is required."; return; }
        if [[ ! "$IRAN_IP" =~ ^[A-Za-z0-9._:-]+$ ]]; then
            warn "Invalid Iran server address. Use an IP address or domain name."
            return
        fi
    fi

    local generated_token; generated_token=$(cat /proc/sys/kernel/random/uuid 2>/dev/null \
        || tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 32)
    echo -e "  ${DIM}Generated token: ${LYELLOW}${generated_token}${NC}"
    echo -e "  ${DIM}Press Enter to use it, or type your own token.${NC}"
    prompt "Authentication token:"; read -r TOKEN
    TOKEN="${TOKEN:-$generated_token}"
    if [[ "$TOKEN" == *$'\n'* ]] || [[ "$TOKEN" == *$'\r'* ]]; then
        warn "Token must be a single line."
        return
    fi

    # Port mappings (Iran/Server side only)
    local PORTS=()
    if [[ "$ROLE" == "iran" ]]; then
        echo -e "\n  ${BOLD}${WHITE}Port Forwarding Rules${NC}"
        echo -e "  ${DIM}Format : ${WHITE}listen_port=target_ip:target_port${NC}"
        echo -e "  ${DIM}Example: ${WHITE}443=127.0.0.1:443${NC}   ${DIM}or${NC}   ${WHITE}9191=127.0.0.1:9191${NC}"
        echo -e "  ${DIM}Shortcut: just a port number like ${WHITE}443${NC}${DIM} → auto-expands to ${WHITE}443=127.0.0.1:443${NC}"
        echo -e "  ${DIM}Empty line to finish.${NC}"
        separator
        local pm_idx=1
        while true; do
            prompt "  Mapping #${pm_idx} (Enter to finish):"; read -r pm
            [[ -z "$pm" ]] && break
            # Shortcut: if user typed only a port number, expand it
            if [[ "$pm" =~ ^[0-9]+$ ]]; then
                pm="${pm}=127.0.0.1:${pm}"
                echo -e "  ${DIM}  → expanded to: ${WHITE}${pm}${NC}"
            fi
            # Validate format: must contain '=' and ':'
            if [[ ! "$pm" =~ ^[0-9]+=.+:[0-9]+$ ]]; then
                warn "Invalid format: '${pm}' — use port=ip:port (e.g. 443=127.0.0.1:443)"
                continue
            fi
            local listen_port="${pm%%=*}"
            local target="${pm#*=}"
            local target_host="${target%:*}"
            local target_port="${target##*:}"
            if ! is_valid_port "$listen_port" || ! is_valid_port "$target_port" || [[ -z "$target_host" ]]; then
                warn "Invalid port mapping: '${pm}'"
                continue
            fi
            if [[ ! "$target_host" =~ ^[A-Za-z0-9._:-]+$ ]]; then
                warn "Invalid target host in mapping: '${target_host}'"
                continue
            fi
            PORTS+=("$pm")
            pm_idx=$(( pm_idx + 1 ))
        done
        [[ ${#PORTS[@]} -eq 0 ]] && { warn "At least one port mapping is required on Iran side."; return; }
    fi

    # ── Step 3: Preset or Advanced ────────────────────────────────────────────
    echo -e "\n  ${BOLD}${WHITE}Step 3 of 3 — Tuning Parameters${NC}"
    separator
    echo -e "  ${WHITE}[1]${NC} ${LGREEN}Preset${NC}   — Apply recommended default values automatically"
    echo -e "  ${WHITE}[2]${NC} ${LYELLOW}Advanced${NC} — Configure every parameter manually ${DIM}(defaults shown in brackets)${NC}"
    separator
    prompt "Choice [1/2]:"; read -r mode_choice

    # Declare all ADV_ as local to this function — prevents bleed between tunnel creations
    local ADV_KEEPALIVE ADV_NODELAY ADV_HEARTBEAT ADV_CHANNEL_SIZE
    local ADV_MUX_CON ADV_MUX_VERSION ADV_MUX_FRAMESIZE ADV_MUX_RECVBUF ADV_MUX_STREAMBUF
    local ADV_LOG_LEVEL ADV_MSS ADV_SO_RCVBUF ADV_SO_SNDBUF ADV_SNIFFER ADV_WEB_PORT
    local ADV_CONN_POOL ADV_AGGRESSIVE_POOL ADV_DIAL_TIMEOUT ADV_RETRY_INTERVAL

    # Initialize with preset values (used by both preset & advanced modes)
    local _log_level_default
    if [[ "$ROLE" == "iran" ]]; then
        _log_level_default=$([[ "$TRANSPORT" == "tcp" ]] && echo "$PRESET_IRAN_LOG_LEVEL_TCP" || echo "$PRESET_IRAN_LOG_LEVEL_MUX")
        ADV_KEEPALIVE="$PRESET_IRAN_KEEPALIVE"
        ADV_NODELAY="$PRESET_IRAN_NODELAY"
        ADV_HEARTBEAT="$PRESET_IRAN_HEARTBEAT"
        ADV_CHANNEL_SIZE="$PRESET_IRAN_CHANNEL_SIZE"
        ADV_MUX_CON="$PRESET_IRAN_MUX_CON"
        ADV_MUX_VERSION="$PRESET_IRAN_MUX_VERSION"
        ADV_MUX_FRAMESIZE="$PRESET_IRAN_MUX_FRAMESIZE"
        ADV_MUX_RECVBUF="$PRESET_IRAN_MUX_RECVBUF"
        ADV_MUX_STREAMBUF="$PRESET_IRAN_MUX_STREAMBUF"
        ADV_LOG_LEVEL="$_log_level_default"
        ADV_MSS="$PRESET_IRAN_MSS"
        ADV_SO_RCVBUF="$PRESET_IRAN_SO_RCVBUF"
        ADV_SO_SNDBUF="$PRESET_IRAN_SO_SNDBUF"
        ADV_SNIFFER="$PRESET_IRAN_SNIFFER"
        ADV_WEB_PORT="$PRESET_IRAN_WEB_PORT"
        # kharej-only defaults (unused for iran, but must be set for set -u)
        ADV_CONN_POOL="$PRESET_KHAREJ_CONN_POOL"
        ADV_AGGRESSIVE_POOL="$PRESET_KHAREJ_AGGRESSIVE_POOL"
        ADV_DIAL_TIMEOUT="$PRESET_KHAREJ_DIAL_TIMEOUT"
        ADV_RETRY_INTERVAL="$PRESET_KHAREJ_RETRY_INTERVAL"
    else
        _log_level_default=$([[ "$TRANSPORT" == "tcp" ]] && echo "$PRESET_KHAREJ_LOG_LEVEL_TCP" || echo "$PRESET_KHAREJ_LOG_LEVEL_MUX")
        ADV_CONN_POOL="$PRESET_KHAREJ_CONN_POOL"
        ADV_AGGRESSIVE_POOL="$PRESET_KHAREJ_AGGRESSIVE_POOL"
        ADV_KEEPALIVE="$PRESET_KHAREJ_KEEPALIVE"
        ADV_DIAL_TIMEOUT="$PRESET_KHAREJ_DIAL_TIMEOUT"
        ADV_RETRY_INTERVAL="$PRESET_KHAREJ_RETRY_INTERVAL"
        ADV_NODELAY="$PRESET_KHAREJ_NODELAY"
        ADV_MUX_VERSION="$PRESET_KHAREJ_MUX_VERSION"
        ADV_MUX_FRAMESIZE="$PRESET_KHAREJ_MUX_FRAMESIZE"
        ADV_MUX_RECVBUF="$PRESET_KHAREJ_MUX_RECVBUF"
        ADV_MUX_STREAMBUF="$PRESET_KHAREJ_MUX_STREAMBUF"
        ADV_LOG_LEVEL="$_log_level_default"
        ADV_MSS="$PRESET_KHAREJ_MSS"
        ADV_SO_RCVBUF="$PRESET_KHAREJ_SO_RCVBUF"
        ADV_SO_SNDBUF="$PRESET_KHAREJ_SO_SNDBUF"
        ADV_SNIFFER="$PRESET_KHAREJ_SNIFFER"
        ADV_WEB_PORT="$PRESET_KHAREJ_WEB_PORT"
        # iran-only defaults (unused for kharej, but must be set for set -u)
        ADV_HEARTBEAT="$PRESET_IRAN_HEARTBEAT"
        ADV_CHANNEL_SIZE="$PRESET_IRAN_CHANNEL_SIZE"
        ADV_MUX_CON="$PRESET_IRAN_MUX_CON"
    fi

    case "$mode_choice" in
        1)
            _show_preset_summary "$ROLE" "$TRANSPORT"
            echo -e "\n  ${OK} Preset values will be applied."
            ;;
        2)
            echo -e "\n  ${BOLD}${WHITE}Advanced Configuration${NC}"
            echo -e "  ${DIM}Press Enter on any field to keep the default value shown in [brackets].${NC}"
            separator
            if [[ "$ROLE" == "iran" ]]; then
                _ask_advanced_iran "$TRANSPORT"
            else
                _ask_advanced_kharej "$TRANSPORT"
            fi
            ;;
        *)
            warn "Invalid choice — preset values will be used."
            _show_preset_summary "$ROLE" "$TRANSPORT"
            ;;
    esac

    # ── Conflict check & write ────────────────────────────────────────────────
    local SVC_NAME="backhaul-${ROLE}-${TRANSPORT}-${TUNNEL_PORT}"
    local CONFIG_FILE="$INSTALL_DIR/${ROLE}-${TRANSPORT}-${TUNNEL_PORT}.toml"
    local SERVICE_FILE="$SERVICE_DIR/${SVC_NAME}.service"

    if [[ -f "$CONFIG_FILE" ]] || [[ -f "$SERVICE_FILE" ]]; then
        echo ""
        warn "A tunnel with this name already exists: ${CYAN}$SVC_NAME${NC}"
        prompt "Overwrite? [y/N]:"; read -r ow
        [[ "${ow,,}" == "y" ]] || return
        backup_config "$CONFIG_FILE"
    fi

    if [[ "$ROLE" == "iran" ]] && port_in_use "$TUNNEL_PORT"; then
        warn "Port $TUNNEL_PORT appears to be in use already!"
        prompt "Continue anyway? [y/N]:"; read -r cont
        [[ "${cont,,}" == "y" ]] || return
    fi

    # ── Generate SSL cert if needed ───────────────────────────────────────────
    [[ "$TRANSPORT" == "wssmux" ]] && generate_ssl_cert

    # ── Write config & service ────────────────────────────────────────────────
    if [[ "$ROLE" == "iran" ]]; then
        _write_iran_config "$CONFIG_FILE" "$TRANSPORT" "$TUNNEL_PORT" "$TOKEN" "${PORTS[@]+"${PORTS[@]}"}"
    else
        _write_kharej_config "$CONFIG_FILE" "$TRANSPORT" "$TUNNEL_PORT" "$IRAN_IP" "$TOKEN"
    fi

    local DESCRIPTION
    case "$TRANSPORT" in
        tcp)    DESCRIPTION="Backhaul TCP Tunnel" ;;
        tcpmux) DESCRIPTION="Backhaul TCPMUX Tunnel" ;;
        wsmux)  DESCRIPTION="Backhaul WSMUX Tunnel" ;;
        wssmux) DESCRIPTION="Backhaul WSSMUX Tunnel (TLS)" ;;
    esac

    cat > "$SERVICE_FILE" << SERVICE
[Unit]
Description=${DESCRIPTION} - ${ROLE^} port ${TUNNEL_PORT}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BINARY} -c ${CONFIG_FILE}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable "$SVC_NAME" 2>/dev/null || warn "Failed to enable $SVC_NAME"

    local start_ok=0
    if systemctl restart "$SVC_NAME" 2>/dev/null || systemctl start "$SVC_NAME" 2>/dev/null; then
        sleep 1
        if systemctl is-active --quiet "$SVC_NAME" 2>/dev/null; then
            start_ok=1
        else
            warn "Service was created but is not active."
        fi
    else
        warn "Service was created but systemctl could not start it."
    fi

    if [[ "$start_ok" -ne 1 ]]; then
        echo -e "  ${DIM}Last service logs:${NC}"
        journalctl -u "$SVC_NAME" -n 30 --no-pager 2>/dev/null || true
        press_enter
        return
    fi

    # ── Summary ───────────────────────────────────────────────────────────────
    local local_ip; local_ip=$(get_local_ip)
    local svc_status; svc_status=$(service_status_color "$SVC_NAME")

    echo ""
    echo -e "${BOLD}${LGREEN}  ╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${LGREEN}  ║            Tunnel Created Successfully!              ║${NC}"
    echo -e "${BOLD}${LGREEN}  ╚══════════════════════════════════════════════════════╝${NC}"
    echo ""

    # This server info
    if [[ "$ROLE" == "iran" ]]; then
        echo -e "  ${BOLD}${LGREEN}[ THIS SERVER — IRAN (Listener) ]${NC}"
    else
        echo -e "  ${BOLD}${LBLUE}[ THIS SERVER — KHAREJ (Connector) ]${NC}"
    fi
    echo -e "  ${BULLET} IP          : ${WHITE}${local_ip}${NC}"
    echo -e "  ${BULLET} Service     : ${CYAN}${SVC_NAME}${NC}"
    echo -e "  ${BULLET} Status      : ${svc_status}"
    echo -e "  ${BULLET} Config file : ${DIM}${CONFIG_FILE}${NC}"
    echo -e "  ${BULLET} Transport   : ${LYELLOW}${TRANSPORT^^}${NC}  |  Port: ${WHITE}${TUNNEL_PORT}${NC}"
    echo -e "  ${BULLET} Token       : ${WHITE}${TOKEN}${NC}"
    if [[ "$ROLE" == "iran" ]]; then
        echo -e "  ${BULLET} Forwarding  :"
        for p in "${PORTS[@]}"; do
            echo -e "               ${DIM}${p}${NC}"
        done
    fi
    [[ "$TRANSPORT" == "wssmux" ]] && \
        echo -e "  ${BULLET} TLS cert    : ${DIM}${CERT_DIR}/wssmux.crt${NC}"
    separator

    # What to run on the OTHER server
    echo ""
    if [[ "$ROLE" == "iran" ]]; then
        echo -e "  ${BOLD}${LBLUE}[ OTHER SERVER — KHAREJ (run this script there) ]${NC}"
        echo -e "  ${BULLET} Role        : ${LBLUE}KHAREJ${NC}"
        echo -e "  ${BULLET} Transport   : ${LYELLOW}${TRANSPORT^^}${NC}"
        echo -e "  ${BULLET} Iran IP     : ${WHITE}${local_ip}${NC}  port ${WHITE}${TUNNEL_PORT}${NC}"
        echo -e "  ${BULLET} Token       : ${WHITE}${TOKEN}${NC}"
        echo ""
        echo -e "  ${DIM}On the Kharej server, run this script → Create Tunnel${NC}"
        echo -e "  ${DIM}→ Role: KHAREJ | Transport: ${TRANSPORT^^} | Iran IP: ${local_ip}:${TUNNEL_PORT} | Token: ${TOKEN}${NC}"
    else
        echo -e "  ${BOLD}${LGREEN}[ OTHER SERVER — IRAN (run this script there) ]${NC}"
        echo -e "  ${BULLET} Role        : ${LGREEN}IRAN${NC}"
        echo -e "  ${BULLET} Transport   : ${LYELLOW}${TRANSPORT^^}${NC}"
        echo -e "  ${BULLET} Listen port : ${WHITE}${TUNNEL_PORT}${NC}"
        echo -e "  ${BULLET} Token       : ${WHITE}${TOKEN}${NC}"
        echo ""
        echo -e "  ${DIM}On the Iran server, run this script → Create Tunnel${NC}"
        echo -e "  ${DIM}→ Role: IRAN | Transport: ${TRANSPORT^^} | Port: ${TUNNEL_PORT} | Token: ${TOKEN}${NC}"
    fi
    separator
    echo ""
    press_enter
}

# ─── LIST TUNNELS ─────────────────────────────────────────────────────────────
list_tunnels() {
    local -n _result=$1
    _result=()
    while IFS= read -r svc; do
        _result+=("$svc")
    done < <(systemctl list-unit-files --type=service 2>/dev/null \
        | grep -o 'backhaul[^ ]*\.service' | sort -u)
}

pick_tunnel() {
    local -n _picked=$1
    local prompt_msg="${2:-Select a tunnel}"
    local svcs=()
    list_tunnels svcs

    if [[ ${#svcs[@]} -eq 0 ]]; then
        warn "No Backhaul tunnels found."
        _picked=""
        return
    fi

    echo -e "\n  ${BOLD}${WHITE}Available Tunnels:${NC}"
    local i=1
    for svc in "${svcs[@]}"; do
        local stat; stat=$(service_status_color "$svc")
        echo -e "  ${WHITE}[$i]${NC} ${CYAN}$svc${NC}  $stat"
        i=$(( i + 1 ))
    done
    echo -e "  ${WHITE}[0]${NC} Cancel"
    separator
    prompt "$prompt_msg [0-$((i-1))]:"; read -r sel

    [[ "$sel" == "0" ]] && { _picked=""; return; }
    if [[ "$sel" =~ ^[0-9]+$ ]] && [[ "$sel" -ge 1 ]] && [[ "$sel" -lt "$i" ]]; then
        _picked="${svcs[$((sel-1))]}"
    else
        warn "Invalid selection"
        _picked=""
    fi
}

# ─── DELETE TUNNEL ────────────────────────────────────────────────────────────
menu_delete_tunnel() {
    section "Delete Tunnel"
    local sel_svc=""
    pick_tunnel sel_svc "Select tunnel to DELETE"
    [[ -z "$sel_svc" ]] && return

    echo -e "\n  ${LRED}${BOLD}WARNING:${NC} This will stop and remove ${CYAN}$sel_svc${NC}"

    # Find config file
    local exec_start
    exec_start=$(get_service_config_path "$sel_svc" || true)

    prompt "Type 'yes' to confirm deletion:"; read -r confirm
    [[ "$confirm" != "yes" ]] && { info "Aborted."; return; }

    systemctl stop "$sel_svc" 2>/dev/null || true
    systemctl disable "$sel_svc" 2>/dev/null || true
    rm -f "$SERVICE_DIR/$sel_svc"
    # Remove cron job if exists
    if [[ -d "$CRON_CONFIG_DIR" ]]; then
        _cron_remove "$sel_svc" 2>/dev/null || true
    fi
    systemctl daemon-reload

    if [[ -n "$exec_start" ]] && [[ -f "$exec_start" ]]; then
        backup_config "$exec_start"
        prompt "Also delete config file ($exec_start)? [y/N]:"; read -r delcfg
        [[ "${delcfg,,}" == "y" ]] && rm -f "$exec_start" && success "Config deleted."
    fi

    success "Tunnel $sel_svc removed."
    press_enter
}

# ─── RESTART / STOP / START ───────────────────────────────────────────────────
menu_service_control() {
    section "Service Control"

    echo -e "  ${WHITE}[1]${NC} ${LGREEN}Start${NC}    a tunnel"
    echo -e "  ${WHITE}[2]${NC} ${YELLOW}Stop${NC}     a tunnel"
    echo -e "  ${WHITE}[3]${NC} ${LCYAN}Restart${NC}  a tunnel"
    echo -e "  ${WHITE}[4]${NC} ${LGREEN}Start ALL${NC}  backhaul tunnels"
    echo -e "  ${WHITE}[5]${NC} ${YELLOW}Stop ALL${NC}   backhaul tunnels"
    echo -e "  ${WHITE}[6]${NC} ${LCYAN}Restart ALL${NC} backhaul tunnels"
    echo -e "  ${WHITE}[0]${NC} Back"
    separator
    prompt "Choice:"; read -r ctrl_choice

    local sel_svc="" svcs=()

    case "$ctrl_choice" in
        1|2|3)
            pick_tunnel sel_svc "Select tunnel"
            [[ -z "$sel_svc" ]] && return
            case "$ctrl_choice" in
                1) systemctl start   "$sel_svc" && success "Started $sel_svc" ;;
                2) systemctl stop    "$sel_svc" && success "Stopped $sel_svc" ;;
                3) systemctl restart "$sel_svc" && success "Restarted $sel_svc" ;;
            esac
            ;;
        4|5|6)
            list_tunnels svcs
            [[ ${#svcs[@]} -eq 0 ]] && { warn "No tunnels found."; press_enter; return; }
            for svc in "${svcs[@]}"; do
                case "$ctrl_choice" in
                    4) systemctl start   "$svc" 2>/dev/null && echo -e "  ${OK} Started $svc" ;;
                    5) systemctl stop    "$svc" 2>/dev/null && echo -e "  ${OK} Stopped $svc" ;;
                    6) systemctl restart "$svc" 2>/dev/null && echo -e "  ${OK} Restarted $svc" ;;
                esac
            done
            success "Done."
            ;;
        0) return ;;
        *) warn "Invalid choice" ;;
    esac
    press_enter
}

# ─── EDIT CONFIG ─────────────────────────────────────────────────────────────
menu_edit_config() {
    section "Edit Tunnel Configuration"

    # Find all backhaul TOML configs
    local configs=()
    while IFS= read -r f; do configs+=("$f"); done \
        < <(find "$INSTALL_DIR" -maxdepth 1 -name "*.toml" 2>/dev/null | sort)

    if [[ ${#configs[@]} -eq 0 ]]; then
        warn "No config files found in $INSTALL_DIR"
        press_enter; return
    fi

    echo -e "  ${BOLD}${WHITE}Config Files:${NC}"
    local i=1
    for cfg in "${configs[@]}"; do
        local transport bind_or_remote
        transport=$(grep -m1 'transport' "$cfg" 2>/dev/null | awk -F'"' '{print $2}' || echo "?")
        bind_or_remote=$(grep -m1 'bind_addr\|remote_addr' "$cfg" 2>/dev/null | awk -F'"' '{print $2}' || echo "?")
        echo -e "  ${WHITE}[$i]${NC} ${CYAN}$(basename "$cfg")${NC}  ${DIM}$transport @ $bind_or_remote${NC}"
        i=$(( i + 1 ))
    done
    echo -e "  ${WHITE}[0]${NC} Back"
    separator
    prompt "Select config [0-$((i-1))]:"; read -r cfg_sel
    [[ "$cfg_sel" == "0" ]] && return

    if [[ "$cfg_sel" =~ ^[0-9]+$ ]] && [[ "$cfg_sel" -ge 1 ]] && [[ "$cfg_sel" -lt "$i" ]]; then
        local chosen="${configs[$((cfg_sel-1))]}"
        backup_config "$chosen"
        local editor="${EDITOR:-nano}"
        command -v "$editor" &>/dev/null || editor="vi"
        "$editor" "$chosen"

        # Reload the associated service
        local cfg_basename; cfg_basename=$(basename "$chosen" .toml)
        local svc="backhaul-$cfg_basename.service"
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            prompt "Restart $svc to apply changes? [Y/n]:"; read -r do_restart
            [[ "${do_restart,,}" != "n" ]] && \
                systemctl restart "$svc" && success "Service restarted."
        fi
    else
        warn "Invalid selection"
    fi
    press_enter
}

# ─── LIVE LOGS ───────────────────────────────────────────────────────────────
menu_live_logs() {
    section "Live Logs"
    local sel_svc=""
    pick_tunnel sel_svc "Select tunnel to view logs"
    [[ -z "$sel_svc" ]] && return

    echo -e "\n  ${BOLD}${WHITE}Log filter level:${NC}"
    echo -e "  ${WHITE}[1]${NC} ALL (no filter)"
    echo -e "  ${WHITE}[2]${NC} ERROR only"
    echo -e "  ${WHITE}[3]${NC} INFO + ERROR"
    echo -e "  ${WHITE}[4]${NC} Last 100 lines then follow"
    separator
    prompt "Filter [1-4]:"; read -r log_filter

    echo -e "\n${DIM}Showing logs for ${CYAN}$sel_svc${NC}${DIM} — Press Ctrl+C to return to menu${NC}\n"

    (
        trap 'exit 0' INT
        case "$log_filter" in
            2) journalctl -u "$sel_svc" -f --no-pager | grep --color=always --line-buffered -i 'error\|fail\|warn' ;;
            3) journalctl -u "$sel_svc" -f --no-pager | grep --color=always --line-buffered -i 'error\|fail\|warn\|info' ;;
            4) journalctl -u "$sel_svc" -n 100 -f --no-pager ;;
            *) journalctl -u "$sel_svc" -f --no-pager ;;
        esac
    )
    echo -e "\n${DIM}  Returned to menu.${NC}"
    sleep 0.5
}

# ─── MONITOR (Dashboard) ─────────────────────────────────────────────────────
menu_monitor() {
    echo -e "\n${DIM}Live dashboard — Press Ctrl+C to exit${NC}"
    while true; do
        clear
        print_header
        section "Live Monitor"

        local svcs=()
        list_tunnels svcs

        printf "  %-38s %-16s %-8s %-10s %-18s\n" \
            "${BOLD}${WHITE}Service${NC}" "${BOLD}${WHITE}Status${NC}" \
            "${BOLD}${WHITE}CPU%${NC}" "${BOLD}${WHITE}Mem${NC}" "${BOLD}${WHITE}Uptime${NC}"
        separator

        for svc in "${svcs[@]}"; do
            local status cpu mem uptime pid
            status=$(service_status_color "$svc")
            pid=$(systemctl show -p MainPID --value "$svc" 2>/dev/null || echo "0")
            if [[ "$pid" != "0" ]] && [[ "$pid" != "" ]] && [[ -d "/proc/$pid" ]]; then
                cpu=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ' || echo "—")
                mem=$(ps -p "$pid" -o rss= 2>/dev/null | awk '{printf "%.1fM", $1/1024}' || echo "—")
                uptime=$(ps -p "$pid" -o etime= 2>/dev/null | tr -d ' ' || echo "—")
            else
                cpu="—"; mem="—"; uptime="—"
            fi
            printf "  %-38s %-24s %-8s %-10s %-18s\n" \
                "${CYAN}$svc${NC}" "$status" "$cpu" "$mem" "$uptime"
        done

        separator
        echo -e "\n  ${DIM}Last updated: $(date '+%H:%M:%S') — refreshing every 5s${NC}"
        echo -e "  ${DIM}Press Ctrl+C to exit${NC}"
        sleep 5
    done
}

# ─── BACKUP / RESTORE ────────────────────────────────────────────────────────
menu_backup() {
    section "Backup & Restore"
    echo -e "  ${WHITE}[1]${NC} Backup all configs now"
    echo -e "  ${WHITE}[2]${NC} List backups"
    echo -e "  ${WHITE}[3]${NC} Restore a backup"
    echo -e "  ${WHITE}[0]${NC} Back"
    separator
    prompt "Choice:"; read -r bk_choice

    mkdir -p "$BACKUP_DIR"

    case "$bk_choice" in
        1)
            local ts; ts=$(date +%Y%m%d-%H%M%S)
            local count=0
            while IFS= read -r f; do
                cp "$f" "$BACKUP_DIR/$(basename "$f").bak.$ts"
                count=$(( count + 1 ))
            done < <(find "$INSTALL_DIR" -maxdepth 1 -name "*.toml" 2>/dev/null)
            success "Backed up $count config file(s) → $BACKUP_DIR"
            ;;
        2)
            echo -e "\n  ${BOLD}${WHITE}Backups in $BACKUP_DIR:${NC}"
            ls -lh "$BACKUP_DIR" 2>/dev/null | tail -n +2 | \
                awk '{print "  " $NF "  \033[2m" $5 "  " $6 " " $7"\033[0m"}'
            ;;
        3)
            local bk_files=()
            while IFS= read -r f; do bk_files+=("$f"); done \
                < <(ls -t "$BACKUP_DIR"/*.bak.* 2>/dev/null)
            [[ ${#bk_files[@]} -eq 0 ]] && { warn "No backups found."; press_enter; return; }

            local i=1
            for f in "${bk_files[@]}"; do
                echo -e "  ${WHITE}[$i]${NC} ${CYAN}$(basename "$f")${NC}"
                i=$(( i + 1 ))
            done
            echo -e "  ${WHITE}[0]${NC} Cancel"
            separator
            prompt "Select backup to restore:"; read -r bk_sel
            [[ "$bk_sel" == "0" ]] && return
            if [[ "$bk_sel" =~ ^[0-9]+$ ]] && [[ "$bk_sel" -ge 1 ]] && [[ "$bk_sel" -lt "$i" ]]; then
                local chosen="${bk_files[$((bk_sel-1))]}"
                local orig_name; orig_name=$(basename "$chosen" | sed 's/\.bak\.[0-9-]*$//')
                cp "$chosen" "$INSTALL_DIR/$orig_name"
                success "Restored: $orig_name"
            fi
            ;;
        0) return ;;
    esac
    press_enter
}

# ─── FIREWALL HELPER ─────────────────────────────────────────────────────────
menu_firewall() {
    section "Firewall Helper"

    local svcs=()
    list_tunnels svcs

    # Extract ports from config files
    local ports_to_open=()
    while IFS= read -r toml; do
        local bp
        bp=$(grep -m1 'bind_addr' "$toml" 2>/dev/null | grep -oE ':[0-9]+' | tr -d ':')
        [[ -n "$bp" ]] && ports_to_open+=("$bp/tcp")
    done < <(find "$INSTALL_DIR" -maxdepth 1 -name "*.toml" 2>/dev/null)

    echo -e "  ${BOLD}${WHITE}Detected tunnel ports:${NC}"
    for p in "${ports_to_open[@]}"; do
        echo -e "  ${BULLET} ${LYELLOW}$p${NC}"
    done

    echo ""
    echo -e "  ${WHITE}[1]${NC} Open all tunnel ports with UFW"
    echo -e "  ${WHITE}[2]${NC} Open all tunnel ports with iptables"
    echo -e "  ${WHITE}[3]${NC} Open a custom port"
    echo -e "  ${WHITE}[0]${NC} Back"
    separator
    prompt "Choice:"; read -r fw_choice

    case "$fw_choice" in
        1)
            command -v ufw &>/dev/null || die "UFW not installed."
            for p in "${ports_to_open[@]}"; do
                ufw allow "$p" 2>/dev/null && echo -e "  ${OK} Allowed $p"
            done
            success "UFW rules applied."
            ;;
        2)
            for p in "${ports_to_open[@]}"; do
                local port="${p%%/*}"
                iptables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null \
                    && echo -e "  ${OK} iptables: allowed $p"
            done
            success "iptables rules applied."
            ;;
        3)
            prompt "Port (e.g. 8443/tcp):"; read -r custom_port
            [[ -z "$custom_port" ]] && return
            custom_port="${custom_port,,}"
            if [[ "$custom_port" =~ ^([0-9]+)(/(tcp|udp))?$ ]]; then
                local port="${BASH_REMATCH[1]}"
                local proto="${BASH_REMATCH[3]:-tcp}"
                if ! is_valid_port "$port"; then
                    warn "Invalid port: $port"
                    press_enter
                    return
                fi
                custom_port="$port/$proto"
            else
                warn "Invalid port format. Use 8443, 8443/tcp, or 8443/udp."
                press_enter
                return
            fi
            if command -v ufw &>/dev/null; then
                ufw allow "$custom_port" && success "UFW: allowed $custom_port"
            else
                iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT \
                    && success "iptables: allowed $custom_port"
            fi
            ;;
        0) return ;;
    esac
    press_enter
}

# ─── TWO-WAY LINK TEST ───────────────────────────────────────────────────────
linktest_valid_host() {
    local host="$1"
    [[ -n "$host" ]] && [[ "$host" != -* ]] && [[ "$host" =~ ^[A-Za-z0-9._:-]+$ ]]
}

linktest_normalize_ports() {
    printf '%s\n' "$1" | tr ',' ' ' | awk '{$1=$1; print}'
}

linktest_ask_default() {
    local label="$1" def="$2" ans
    echo -ne "${ARROW} ${WHITE}${label} ${DIM}[${def}]${NC}: " >&2
    read -r ans
    echo "${ans:-$def}"
}

linktest_public_ip() {
    local ip=""
    if command -v curl >/dev/null 2>&1; then
        ip="$(timeout 4 curl -4 -sS https://api.ipify.org 2>/dev/null || true)"
    fi
    [[ -n "$ip" ]] && echo "$ip" || echo "unknown"
}

linktest_tcp_connect() {
    local host="$1" port="$2" timeout_sec="$3"
    if command -v nc >/dev/null 2>&1; then
        timeout "$timeout_sec" nc -z -w "$timeout_sec" "$host" "$port" >/dev/null 2>&1
    else
        timeout "$timeout_sec" bash -c 'exec 3<>"/dev/tcp/$1/$2"' bash "$host" "$port" >/dev/null 2>&1
    fi
}

linktest_tcp_banner() {
    local host="$1" port="$2" timeout_sec="$3"
    if command -v nc >/dev/null 2>&1; then
        printf '\n' | timeout "$timeout_sec" nc -w 1 "$host" "$port" 2>/dev/null | head -c 128 | tr -d '\r'
    else
        timeout "$timeout_sec" bash -c '
            exec 3<>"/dev/tcp/$1/$2" || exit 1
            timeout 1 head -c 128 <&3 2>/dev/null || true
            exec 3<&-
            exec 3>&-
        ' bash "$host" "$port" 2>/dev/null | tr -d '\r'
    fi
}

linktest_port_in_use() {
    command -v ss >/dev/null 2>&1 || return 1
    ss -lntu 2>/dev/null | awk '{print $5}' | grep -qE ":$1$"
}

linktest_start_listener() {
    local bind_ip="$1" port="$2" tmp_dir="$3" pids_ref="$4"
    local -n _pids="$pids_ref"

    if linktest_port_in_use "$port"; then
        warn "Port $port is already in use - skipped."
        return 0
    fi

    cat > "$tmp_dir/listener-$port.py" <<'PY'
import socket, sys, time, signal

def handle_sigterm(sig, frame):
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_sigterm)

bind_ip = sys.argv[1]
port = int(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((bind_ip, port))
s.listen(1024)

while True:
    conn, addr = s.accept()
    now = time.strftime("%H:%M:%S")
    peer = f"{addr[0]}:{addr[1]}"
    print(f"  [{now}]  {peer}  connected on port {port}", flush=True)
    try:
        conn.sendall(b"LINKTEST_OK\n")
    except Exception:
        pass
    finally:
        conn.close()
PY

    python3 "$tmp_dir/listener-$port.py" "$bind_ip" "$port" &
    local pid="$!"
    _pids+=("$pid")
    sleep 0.3

    if kill -0 "$pid" 2>/dev/null; then
        success "Port $port is now listening (pid $pid)"
    else
        warn "Port $port failed to bind."
    fi
}

linktest_cleanup_listeners() {
    local tmp_dir="$1" pids_ref="$2"
    local -n _pids="$pids_ref"
    local pid

    for pid in "${_pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -rf "$tmp_dir" 2>/dev/null || true
}

menu_link_test() {
    section "Two-Way Link Test"

    echo -e "  ${BOLD}${WHITE}Local Network:${NC}"
    echo -e "  ${BULLET} Hostname  : ${CYAN}$(hostname)${NC}"
    echo -e "  ${BULLET} Local IPs : ${CYAN}$(hostname -I 2>/dev/null | awk '{$1=$1; print}')${NC}"
    echo -e "  ${BULLET} Public IP : ${CYAN}$(linktest_public_ip)${NC}"
    echo -e "  ${BULLET} Role      : ${LYELLOW}${SERVER_ROLE}${NC}"
    separator

    echo -e "  ${WHITE}[1]${NC} Listen  - open temporary TCP test ports on this server"
    echo -e "  ${WHITE}[2]${NC} Test    - test ping + TCP reachability to a peer"
    echo -e "  ${WHITE}[3]${NC} Info    - show listening TCP ports"
    echo -e "  ${WHITE}[0]${NC} Back"
    separator
    prompt "Choice:"; read -r lt_choice

    case "$lt_choice" in
        1)
            if ! command -v python3 >/dev/null 2>&1; then
                warn "python3 not found. Listener mode requires python3."
                press_enter
                return
            fi

            local bind_ip ports_raw duration peer_hint
            bind_ip="$(linktest_ask_default "Bind IP" "0.0.0.0")"
            ports_raw="$(linktest_ask_default "Ports (space or comma separated)" "80 443 2052 2053 2082 2083 2086 2087 2095 2096 8080 8443 8880")"
            ports_raw="$(linktest_normalize_ports "$ports_raw")"
            peer_hint="$(linktest_ask_default "Peer IP for display only" "AUTO")"
            duration="$(linktest_ask_default "Auto-stop after seconds" "300")"
            [[ "$duration" =~ ^[0-9]+$ ]] || duration=300

            local tmp_dir; tmp_dir="$(mktemp -d /tmp/backhaul-linktest.XXXXXX)"
            local listener_pids=()
            local valid_ports=()
            local p
            for p in $ports_raw; do
                if is_valid_port "$p"; then
                    valid_ports+=("$p")
                else
                    warn "Invalid port skipped: $p"
                fi
            done

            if [[ ${#valid_ports[@]} -eq 0 ]]; then
                warn "No valid ports were provided."
                rm -rf "$tmp_dir" 2>/dev/null || true
                press_enter
                return
            fi

            separator
            for p in "${valid_ports[@]}"; do
                linktest_start_listener "$bind_ip" "$p" "$tmp_dir" listener_pids
            done

            echo ""
            echo -e "  ${BOLD}${WHITE}Listening:${NC}"
            [[ "$peer_hint" != "AUTO" ]] && echo -e "  ${BULLET} Peer hint : ${CYAN}${peer_hint}${NC}"
            echo -e "  ${BULLET} Ports     : ${WHITE}${valid_ports[*]}${NC}"
            echo -e "  ${BULLET} Duration  : ${WHITE}${duration}s${NC}"
            echo -e "  ${DIM}Incoming connections will appear below. Press Enter to stop.${NC}"
            separator

            trap 'echo; warn "Interrupted. Stopping link test listeners..."; linktest_cleanup_listeners "$tmp_dir" listener_pids; trap - INT TERM; return 130' INT TERM
            read -r -t "$duration" _ || true
            trap - INT TERM
            linktest_cleanup_listeners "$tmp_dir" listener_pids
            success "Link test listeners stopped."
            press_enter
            ;;
        2)
            local peer ports_raw timeout_sec ping_count
            peer="$(linktest_ask_default "Peer IP / domain" "")"
            if ! linktest_valid_host "$peer"; then
                warn "A valid peer IP/domain is required."
                press_enter
                return
            fi

            ports_raw="$(linktest_ask_default "TCP ports (space or comma separated)" "80 443 2052 2053 2082 2083 2086 2087 2095 2096 8080 8443 8880")"
            ports_raw="$(linktest_normalize_ports "$ports_raw")"
            timeout_sec="$(linktest_ask_default "TCP timeout seconds" "3")"
            [[ "$timeout_sec" =~ ^[0-9]+$ ]] || timeout_sec=3
            ping_count="$(linktest_ask_default "Ping count" "4")"
            [[ "$ping_count" =~ ^[0-9]+$ ]] || ping_count=4

            echo ""
            section "Ping Test"
            if command -v ping >/dev/null 2>&1; then
                local ping_out loss
                ping_out="$(ping -c "$ping_count" -W 1 "$peer" 2>&1 || true)"
                echo "$ping_out" | grep -E "^(PING|[0-9]+ bytes|---)" | sed 's/^/  /' || true
                loss="$(echo "$ping_out" | grep -oE '[0-9]+% packet loss' || echo "?")"
                if echo "$ping_out" | grep -q ", 0% packet loss"; then
                    success "Ping: no loss ($loss)"
                elif echo "$ping_out" | grep -q "100% packet loss"; then
                    warn "Ping: all packets lost ($loss)"
                else
                    warn "Ping: partial loss ($loss)"
                fi
            else
                warn "ping not found."
            fi

            echo ""
            section "TCP Reachability"
            local ok_count=0 fail_count=0 banner=""
            local p
            for p in $ports_raw; do
                if ! is_valid_port "$p"; then
                    warn "Invalid port skipped: $p"
                    continue
                fi

                if linktest_tcp_connect "$peer" "$p" "$timeout_sec"; then
                    ok_count=$((ok_count + 1))
                    banner="$(linktest_tcp_banner "$peer" "$p" "$timeout_sec" | head -n 1 || true)"
                    if [[ -n "${banner:-}" ]]; then
                        success "Port $p OPEN - banner: $banner"
                    else
                        success "Port $p OPEN"
                    fi
                else
                    fail_count=$((fail_count + 1))
                    warn "Port $p BLOCKED"
                fi
            done

            separator
            if (( ok_count > 0 && fail_count == 0 )); then
                success "ALL OPEN - all $ok_count tested port(s) are reachable."
            elif (( ok_count > 0 && fail_count > 0 )); then
                warn "PARTIAL - $ok_count open / $fail_count blocked"
            else
                warn "ALL BLOCKED - no tested port is reachable."
                echo -e "  ${DIM}Likely cause: firewall, routing issue, provider filtering, or wrong peer address.${NC}"
            fi
            press_enter
            ;;
        3)
            echo ""
            section "Listening TCP Ports"
            ss -lntp 2>/dev/null | awk 'NR>1 {
                split($5, a, ":");
                port = a[length(a)];
                proc = $0; gsub(/.*users:\(\("/, "", proc); gsub(/".*/, "", proc);
                printf "  %-6s  %s\n", port, proc
            }' || true
            press_enter
            ;;
        0) return ;;
        *)
            warn "Invalid option"
            sleep 1
            ;;
    esac
}

# ─── INFO PANEL ──────────────────────────────────────────────────────────────
menu_info() {
    section "System & Tunnel Info"
    local ip; ip=$(get_local_ip)

    echo -e "  ${BOLD}${WHITE}System:${NC}"
    echo -e "  ${BULLET} Hostname  : ${CYAN}$(hostname)${NC}"
    echo -e "  ${BULLET} IP        : ${CYAN}$ip${NC}"
    echo -e "  ${BULLET} Role      : ${LYELLOW}${SERVER_ROLE}${NC}"
    echo -e "  ${BULLET} OS        : ${DIM}$(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY | cut -d= -f2 | tr -d '"')${NC}"
    echo -e "  ${BULLET} Kernel    : ${DIM}$(uname -r)${NC}"
    echo -e "  ${BULLET} Load      : ${DIM}$(cut -d' ' -f1-3 /proc/loadavg)${NC}"
    echo -e "  ${BULLET} Memory    : ${DIM}$(free -h | awk '/^Mem:/{print $3 " used / " $2}')${NC}"
    echo -e "  ${BULLET} Disk (/)  : ${DIM}$(df -h / | awk 'NR==2{print $3 " used / " $2}')${NC}"

    echo -e "\n  ${BOLD}${WHITE}Backhaul Binary:${NC}"
    if [[ -x "$BINARY" ]]; then
        echo -e "  ${BULLET} Path    : ${CYAN}$BINARY${NC}"
        echo -e "  ${BULLET} Version : ${LYELLOW}$("$BINARY" --version 2>/dev/null | head -1 || echo 'unknown')${NC}"
        echo -e "  ${BULLET} Size    : ${DIM}$(du -sh "$BINARY" | cut -f1)${NC}"
    else
        echo -e "  ${WARN} Binary not found at $BINARY"
    fi

    echo -e "\n  ${BOLD}${WHITE}Active Ports:${NC}"
    ss -tlnp 2>/dev/null | grep backhaul | while read -r line; do
        echo -e "  ${BULLET} ${DIM}$line${NC}"
    done

    press_enter
}

# ─── TUNNEL SUBMENU ──────────────────────────────────────────────────────────
# ─── Read tunnel connection status from journal ───────────────────────────────
_tunnel_conn_status() {
    local svc="$1"
    # Only look at logs since the last service start to avoid stale state
    local since_ts; since_ts=$(systemctl show -p ActiveEnterTimestamp --value "$svc" 2>/dev/null)
    local last_logs
    if [[ -n "$since_ts" ]] && [[ "$since_ts" != "n/a" ]]; then
        last_logs=$(journalctl -u "$svc" --no-pager -o cat --since "$since_ts" 2>/dev/null | tail -80)
    else
        last_logs=$(journalctl -u "$svc" --no-pager -o cat -n 80 2>/dev/null)
    fi

    # If service is not active at all → stopped
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo -e "${GRAY}— STOPPED${NC}"
        return
    fi

    # Find the LAST meaningful state line (tail so latest wins)
    local last_state
    last_state=$(echo "$last_logs" | grep -i \
        'control channel.*established\|listener started\|attempting to establish\|restarting client\|failed to.*connect\|fatal\|no route to host\|connection refused' \
        | tail -1)

    case "${last_state,,}" in
        *"control channel successfully established"*|*"control channel established successfully"*)
            local rtt; rtt=$(echo "$last_logs" | grep -i 'round trip\|RTT' | tail -1 | grep -oE '[0-9]+ ms' || true)
            [[ -n "$rtt" ]] && echo -e "${LGREEN}✔ CONNECTED${NC} ${DIM}RTT: ${rtt}${NC}" \
                             || echo -e "${LGREEN}✔ CONNECTED${NC}"
            ;;
        *"listener started"*)
            echo -e "${LGREEN}✔ CONNECTED${NC} ${DIM}(listener active)${NC}"
            ;;
        *"attempting to establish"*|*"restarting client"*)
            echo -e "${YELLOW}◎ CONNECTING${NC} ${DIM}(establishing...)${NC}"
            ;;
        *"failed to"*|*"fatal"*|*"no route"*|*"connection refused"*)
            echo -e "${LRED}✘ DISCONNECTED${NC}"
            ;;
        *)
            # fallback: service running but no clear signal yet
            if echo "$last_logs" | grep -qi 'server started successfully\|waiting for.*control channel'; then
                echo -e "${YELLOW}◎ LISTENING${NC} ${DIM}(waiting for client)${NC}"
            else
                echo -e "${YELLOW}◎ STARTING${NC}"
            fi
            ;;
    esac
}

# ─── AUTO-RESTART (Cron) ─────────────────────────────────────────────────────
CRON_MARKER="# backhaul-auto-restart"
CRON_CONFIG_DIR="$INSTALL_DIR/cron"

_cron_get_config_path() {
    local svc="$1"
    echo "$CRON_CONFIG_DIR/${svc}.conf"
}

_cron_is_active() {
    local svc="$1"
    crontab -l 2>/dev/null | grep -q "$CRON_MARKER.*$svc"
}

_cron_get_interval() {
    local svc="$1"
    local conf; conf=$(_cron_get_config_path "$svc")
    if [[ -f "$conf" ]]; then
        grep '^INTERVAL=' "$conf" 2>/dev/null | head -1 | cut -d= -f2
    else
        echo ""
    fi
}

_cron_install() {
    local svc="$1" interval_min="$2"
    local conf; conf=$(_cron_get_config_path "$svc")

    mkdir -p "$CRON_CONFIG_DIR"
    cat > "$conf" <<EOF
SERVICE=$svc
INTERVAL=$interval_min
EOF

    local cron_line="*/${interval_min} * * * * systemctl restart ${svc} ${CRON_MARKER} ${svc}"
    (crontab -l 2>/dev/null | grep -v "$CRON_MARKER.*$svc"; echo "$cron_line") | crontab -
}

_cron_remove() {
    local svc="$1"
    local conf; conf=$(_cron_get_config_path "$svc")

    crontab -l 2>/dev/null | grep -v "$CRON_MARKER.*$svc" | crontab -
    rm -f "$conf"
}

menu_auto_restart() {
    local svc="$1"
    section "Auto-Restart (Cron)"

    local is_active; is_active=$(_cron_is_active "$svc")
    local current_interval; current_interval=$(_cron_get_interval "$svc")

    if [[ "$is_active" == "true" ]] && [[ -n "$current_interval" ]]; then
        echo -e "  ${BOLD}${WHITE}Current Status:${NC}"
        echo -e "  ${BULLET} Service    : ${CYAN}$svc${NC}"
        echo -e "  ${BULLET} Status     : ${LGREEN}ACTIVE${NC}"
        echo -e "  ${BULLET} Interval   : ${LYELLOW}Every ${current_interval} minute(s)${NC}"
        echo -e "  ${BULLET} Next restart: ${DIM}$(date -d "+${current_interval} minutes" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')${NC}"
    else
        echo -e "  ${BOLD}${WHITE}Auto-Restart is NOT configured for: ${CYAN}$svc${NC}"
    fi

    separator
    echo -e "\n  ${BOLD}${WHITE}Schedule Options:${NC}"
    echo -e "  ${WHITE}[1]${NC} ${LGREEN}Every 30 minutes${NC}  — Clear cache frequently"
    echo -e "  ${WHITE}[2]${NC} ${LYELLOW}Every 1 hour${NC}      — Balanced (recommended)"
    echo -e "  ${WHITE}[3]${NC} ${LCYAN}Every 2 hours${NC}     — Less frequent"
    echo -e "  ${WHITE}[4]${NC} ${LMAGENTA}Every 6 hours${NC}     — Conservative"
    echo -e "  ${WHITE}[5]${NC} ${LRED}Custom interval${NC}   — Enter minutes manually"
    echo -e "  ${WHITE}[6]${NC} ${RED}Disable / Remove${NC}  — Stop auto-restart"
    echo -e "  ${WHITE}[0]${NC} Back"
    separator
    prompt "Choice:"; read -r cron_choice

    local interval_min=""
    case "$cron_choice" in
        1) interval_min=30 ;;
        2) interval_min=60 ;;
        3) interval_min=120 ;;
        4) interval_min=360 ;;
        5)
            prompt "Enter interval in minutes:"; read -r custom_min
            if [[ "$custom_min" =~ ^[0-9]+$ ]] && (( custom_min >= 1 && custom_min <= 1440 )); then
                interval_min="$custom_min"
            else
                warn "Invalid interval. Must be 1-1440 minutes."
                press_enter; return
            fi
            ;;
        6)
            if [[ "$is_active" == "true" ]]; then
                _cron_remove "$svc"
                success "Auto-restart disabled for $svc"
            else
                info "Auto-restart was not configured."
            fi
            press_enter; return
            ;;
        0) return ;;
        *) warn "Invalid choice"; press_enter; return ;;
    esac

    if [[ -n "$interval_min" ]]; then
        echo ""
        warn "This will restart the tunnel every ${interval_min} minute(s)."
        warn "The tunnel will briefly disconnect during restart."
        prompt "Continue? [Y/n]:"; read -r confirm
        if [[ "${confirm,,}" != "n" ]]; then
            _cron_install "$svc" "$interval_min"
            success "Auto-restart enabled: every ${interval_min} minute(s)"
            echo -e "  ${DIM}Cron job: systemctl restart $svc${NC}"
            echo -e "  ${DIM}Config: $(_cron_get_config_path "$svc")${NC}"
        else
            info "Cancelled."
        fi
    fi
    press_enter
}

menu_tunnel_manage() {
    local svc="$1"

    # Find config file for this service
    local cfg; cfg=$(get_service_config_path "$svc" || true)

    while true; do
        print_header
        local svc_status; svc_status=$(service_status_color "$svc")
        local conn_status; conn_status=$(_tunnel_conn_status "$svc")
        local pid; pid=$(systemctl show -p MainPID --value "$svc" 2>/dev/null || echo "0")
        local cpu="—" mem="—" uptime_str="—"
        if [[ "$pid" != "0" ]] && [[ -n "$pid" ]] && [[ -d "/proc/$pid" ]]; then
            cpu=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ' || echo "—")
            mem=$(ps -p "$pid" -o rss= 2>/dev/null | awk '{printf "%.1fM", $1/1024}' || echo "—")
            uptime_str=$(ps -p "$pid" -o etime= 2>/dev/null | tr -d ' ' || echo "—")
        fi

        echo -e "  ${BOLD}${WHITE}Tunnel: ${CYAN}${svc}${NC}"
        echo -e "  ${DIM}Config : ${cfg:-not found}${NC}"
        separator
        echo -e "  Service : ${svc_status}   CPU: ${LYELLOW}${cpu}%${NC}   Mem: ${LYELLOW}${mem}${NC}   Uptime: ${DIM}${uptime_str}${NC}"
        echo -e "  Tunnel  : ${conn_status}"
        separator
        echo ""
        echo -e "  ${LGREEN}[1]${NC}  Start"
        echo -e "  ${YELLOW}[2]${NC}  Stop"
        echo -e "  ${LCYAN}[3]${NC}  Restart"
        echo -e "  ${LBLUE}[4]${NC}  View Logs  ${DIM}(live)${NC}"
        echo -e "  ${MAGENTA}[5]${NC}  Edit Config"
        echo -e "  ${RED}[6]${NC}  Delete Tunnel"
        echo -e "  ${CYAN}[7]${NC}  Schedule Auto-Restart  ${DIM}(cron)${NC}"
        echo -e "  ${GRAY}[0]${NC}  Back"
        separator
        prompt "Choice:"; read -r sub_choice

        case "$sub_choice" in
            1)
                systemctl start "$svc" 2>/dev/null \
                    && success "Started: $svc" \
                    || warn "Failed to start $svc"
                sleep 1
                ;;
            2)
                systemctl stop "$svc" 2>/dev/null \
                    && success "Stopped: $svc" \
                    || warn "Failed to stop $svc"
                sleep 1
                ;;
            3)
                systemctl restart "$svc" 2>/dev/null \
                    && success "Restarted: $svc" \
                    || warn "Failed to restart $svc"
                sleep 1
                ;;
            4)
                clear
                echo -e "${BOLD}${WHITE}  Live Logs — ${CYAN}${svc}${NC}"
                separator
                echo -e "  ${WHITE}[1]${NC} All logs"
                echo -e "  ${WHITE}[2]${NC} Last 50 lines then follow"
                echo -e "  ${WHITE}[3]${NC} Errors & Warnings only"
                separator
                prompt "Filter [1-3]:"; read -r lf
                echo -e "\n${DIM}  Streaming live — Press Ctrl+C to return to menu${NC}\n"
                # Trap Ctrl+C to return to menu instead of exiting the script
                local _color_filter="s/\[INFO\]/$(printf '\033[0;32m')[INFO]$(printf '\033[0m')/g;s/\[ERROR\]/$(printf '\033[0;31m')[ERROR]$(printf '\033[0m')/g;s/\[WARN\]/$(printf '\033[1;33m')[WARN]$(printf '\033[0m')/g;s/\[DEBUG\]/$(printf '\033[2m')[DEBUG]$(printf '\033[0m')/g"
                (
                    trap 'exit 0' INT
                    if [[ "$lf" == "3" ]]; then
                        journalctl -u "$svc" -f --no-pager 2>/dev/null \
                            | grep --line-buffered -i 'error\|fail\|warn' \
                            | sed "$_color_filter"
                    elif [[ "$lf" == "2" ]]; then
                        journalctl -u "$svc" -n 50 -f --no-pager 2>/dev/null | sed "$_color_filter"
                    else
                        journalctl -u "$svc" -f --no-pager 2>/dev/null | sed "$_color_filter"
                    fi
                )
                echo -e "\n${DIM}  Returned to menu.${NC}"
                sleep 0.5
                ;;
            5)
                if [[ -z "$cfg" ]] || [[ ! -f "$cfg" ]]; then
                    warn "Config file not found."
                    press_enter; continue
                fi
                backup_config "$cfg"
                local editor="${EDITOR:-nano}"
                command -v "$editor" &>/dev/null || editor="vi"
                "$editor" "$cfg"
                prompt "Restart service to apply changes? [Y/n]:"; read -r do_restart
                if [[ "${do_restart,,}" != "n" ]]; then
                    systemctl restart "$svc" 2>/dev/null
                    info "Waiting for service to stabilize..."
                    sleep 3
                    success "Restarted: $svc"
                fi
                ;;
            6)
                echo ""
                echo -e "  ${LRED}${BOLD}WARNING: This will permanently delete:${NC}"
                echo -e "  ${BULLET} Service : ${CYAN}$svc${NC}"
                [[ -n "$cfg" ]] && echo -e "  ${BULLET} Config  : ${DIM}$cfg${NC}"
                echo ""
                prompt "Type 'yes' to confirm:"; read -r confirm
                if [[ "$confirm" == "yes" ]]; then
                    systemctl stop "$svc" 2>/dev/null || true
                    systemctl disable "$svc" 2>/dev/null || true
                    rm -f "$SERVICE_DIR/$svc"
                    systemctl daemon-reload
                    # Remove cron job if exists
                    if [[ -d "$CRON_CONFIG_DIR" ]]; then
                        _cron_remove "$svc" 2>/dev/null || true
                    fi
                    if [[ -n "$cfg" ]] && [[ -f "$cfg" ]]; then
                        backup_config "$cfg"
                        rm -f "$cfg"
                    fi
                    success "Tunnel deleted: $svc"
                    press_enter
                    return
                else
                    info "Cancelled."
                    sleep 1
                fi
                ;;
            0) return ;;
            7) menu_auto_restart "$svc" ;;
            *)
                warn "Invalid option"
                sleep 1
                ;;
        esac
    done
}

menu_manage_tunnels() {
    while true; do
        print_header
        section "Manage Tunnels"

        local svcs=()
        list_tunnels svcs

        if [[ ${#svcs[@]} -eq 0 ]]; then
            warn "No Backhaul tunnels found. Create one first."
            press_enter; return
        fi

        echo -e "  ${BOLD}${WHITE}Select a tunnel to manage:${NC}\n"
        local i=1
        for svc in "${svcs[@]}"; do
            local stat; stat=$(service_status_color "$svc")
            echo -e "  ${WHITE}[$i]${NC}  ${CYAN}${svc}${NC}  ${stat}"
            i=$(( i + 1 ))
        done
        echo ""
        echo -e "  ${WHITE}[0]${NC}  Back"
        separator
        prompt "Choice [0-$((i-1))]:"; read -r sel

        [[ "$sel" == "0" ]] && return
        if [[ "$sel" =~ ^[0-9]+$ ]] && [[ "$sel" -ge 1 ]] && [[ "$sel" -lt "$i" ]]; then
            menu_tunnel_manage "${svcs[$((sel-1))]}"
        else
            warn "Invalid selection"
            sleep 1
        fi
    done
}

# ─── WEB PANEL ────────────────────────────────────────────────────────────────
WEBPANEL_PORT=54321
WEBPANEL_DIR="$INSTALL_DIR/webpanel"
WEBPANEL_SCRIPT="$WEBPANEL_DIR/server.py"

menu_webpanel() {
    section "Web Panel"

    echo -e "  ${BOLD}${WHITE}BackhaulManager Web Panel${NC}"
    echo -e "  ${DIM}Beautiful web interface to manage your tunnels${NC}"
    separator

    local ip; ip=$(get_local_ip)

    # Check if webpanel is already running
    local running_pid=""
    if pgrep -f "python3.*server.py.*$WEBPANEL_PORT" >/dev/null 2>&1; then
        running_pid=$(pgrep -f "python3.*server.py.*$WEBPANEL_PORT" | head -1)
    fi

    if [[ -n "$running_pid" ]]; then
        echo -e "  ${OK} ${LGREEN}Web Panel is RUNNING${NC}"
        echo -e "  ${BULLET} URL     : ${CYAN}http://${ip}:${WEBPANEL_PORT}${NC}"
        echo -e "  ${BULLET} Login   : ${LYELLOW}admin / admin${NC}"
        echo -e "  ${BULLET} PID     : ${DIM}${running_pid}${NC}"
    else
        echo -e "  ${WARN} ${YELLOW}Web Panel is NOT running${NC}"
    fi

    separator
    echo -e "  ${WHITE}[1]${NC} ${LGREEN}Start${NC} Web Panel"
    echo -e "  ${WHITE}[2]${NC} ${RED}Stop${NC}  Web Panel"
    echo -e "  ${WHITE}[3]${NC} ${LCYAN}Start${NC} on boot (systemd service)"
    echo -e "  ${WHITE}[4]${NC} ${YELLOW}Install / Update${NC} Web Panel files"
    echo -e "  ${WHITE}[0]${NC} Back"
    separator
    prompt "Choice:"; read -r wp_choice

    case "$wp_choice" in
        1)
            if [[ -n "$running_pid" ]]; then
                warn "Web Panel is already running."
                press_enter; return
            fi

            # Check python3
            if ! command -v python3 &>/dev/null; then
                warn "python3 not found. Please install python3 first."
                press_enter; return
            fi

            # Check if webpanel files exist
            if [[ ! -f "$WEBPANEL_SCRIPT" ]]; then
                warn "Web Panel files not found. Please install first (option 4)."
                press_enter; return
            fi

            # Kill any process using port 54321
            local port_pid
            port_pid=$(ss -tlnp 2>/dev/null | grep ":${WEBPANEL_PORT} " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
            if [[ -n "$port_pid" ]]; then
                info "Killing old process on port $WEBPANEL_PORT (PID: $port_pid)..."
                kill "$port_pid" 2>/dev/null
                sleep 1
            fi
            # Also kill any leftover python server.py processes
            pkill -f "python3.*server.py.*${WEBPANEL_PORT}" 2>/dev/null
            sleep 1

            info "Starting Web Panel on port $WEBPANEL_PORT..."
            mkdir -p "$INSTALL_DIR" "$WEBPANEL_DIR"
            nohup python3 "$WEBPANEL_SCRIPT" > "$WEBPANEL_DIR/panel.log" 2>&1 &
            sleep 2

            if pgrep -f "python3.*server.py.*$WEBPANEL_PORT" >/dev/null 2>&1; then
                success "Web Panel started!"
                echo ""
                echo -e "  ${BOLD}${LGREEN}  ╔══════════════════════════════════════════════════════╗${NC}"
                echo -e "  ${BOLD}${LGREEN}  ║           Web Panel is LIVE!                        ║${NC}"
                echo -e "  ${BOLD}${LGREEN}  ╚══════════════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "  ${BULLET} URL     : ${CYAN}http://${ip}:${WEBPANEL_PORT}${NC}"
                echo -e "  ${BULLET} Login   : ${LYELLOW}admin / admin${NC}"
                echo ""
            else
                warn "Failed to start Web Panel. Check logs:"
                tail -5 "$WEBPANEL_DIR/panel.log" 2>/dev/null
            fi
            press_enter
            ;;
        2)
            if [[ -n "$running_pid" ]]; then
                kill "$running_pid" 2>/dev/null
                pkill -f "python3.*server.py.*$WEBPANEL_PORT" 2>/dev/null
                sleep 1
                success "Web Panel stopped."
            else
                info "Web Panel is not running."
            fi
            press_enter
            ;;
        3)
            info "Creating systemd service for Web Panel..."
            cat > "$SERVICE_DIR/backhaul-webpanel.service" <<SERVICE
[Unit]
Description=BackhaulManager Web Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$WEBPANEL_DIR
ExecStart=$(command -v python3) $WEBPANEL_SCRIPT
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
SERVICE
            systemctl daemon-reload
            systemctl enable backhaul-webpanel 2>/dev/null
            systemctl restart backhaul-webpanel
            sleep 2

            if systemctl is-active --quiet backhaul-webpanel 2>/dev/null; then
                success "Web Panel service installed and started!"
                echo -e "  ${BULLET} URL     : ${CYAN}http://${ip}:${WEBPANEL_PORT}${NC}"
                echo -e "  ${BULLET} Login   : ${LYELLOW}admin / admin${NC}"
                echo -e "  ${BULLET} Service : ${DIM}backhaul-webpanel.service${NC}"
                echo -e "  ${BULLET} Auto-start on boot: ${LGREEN}enabled${NC}"
            else
                warn "Service created but failed to start. Check: journalctl -u backhaul-webpanel"
            fi
            press_enter
            ;;
        4)
            info "Installing Web Panel files..."
            mkdir -p "$WEBPANEL_DIR"

            # Download from GitHub
            local raw_url="https://raw.githubusercontent.com/emad1381/BackhaulManager/master/webpanel/server.py"
            info "Downloading from: $raw_url"

            if command -v wget &>/dev/null; then
                wget -q -O "$WEBPANEL_SCRIPT" "$raw_url" 2>/dev/null
            elif command -v curl &>/dev/null; then
                curl -sL -o "$WEBPANEL_SCRIPT" "$raw_url" 2>/dev/null
            else
                warn "Neither wget nor curl found."
                press_enter; return
            fi

            if [[ -f "$WEBPANEL_SCRIPT" ]] && [[ -s "$WEBPANEL_SCRIPT" ]]; then
                chmod +x "$WEBPANEL_SCRIPT"
                success "Web Panel installed: $WEBPANEL_SCRIPT"
                echo -e "  ${BULLET} Port    : ${CYAN}$WEBPANEL_PORT${NC}"
                echo -e "  ${BULLET} Login   : ${LYELLOW}admin / admin${NC}"
            else
                warn "Download failed. Please check your internet connection."
            fi
            press_enter
            ;;
        0) return ;;
        *) warn "Invalid choice"; press_enter ;;
    esac
}

# ─── MAIN MENU ───────────────────────────────────────────────────────────────
main_menu() {
    while true; do
        print_header
        echo -e "  ${BOLD}${WHITE}Main Menu${NC}\n"

        echo -e "  ${LGREEN}[1]${NC}  Create New Tunnel"
        echo -e "  ${LCYAN}[2]${NC}  Manage Tunnels"
        echo -e "            ${DIM}(start / stop / restart / logs / edit / delete)${NC}"
        echo -e "  ${LMAGENTA}[3]${NC}  Web Panel"
        echo -e "            ${DIM}(install & run web interface on port 54321)${NC}"
        echo -e "  ${MAGENTA}[4]${NC}  Backup & Restore Configs"
        echo -e "  ${MAGENTA}[5]${NC}  Firewall Helper"
        echo -e "  ${LCYAN}[6]${NC}  Two-Way Link Test"
        echo -e "  ${GRAY}[7]${NC}  System Info"
        echo -e "  ${GRAY}[8]${NC}  Install / Update Binary"
        echo -e "  ${RED}[0]${NC}  Exit"
        separator
        prompt "Choice:"; read -r main_choice

        case "$main_choice" in
            1) menu_create_tunnel ;;
            2) menu_manage_tunnels ;;
            3) menu_webpanel ;;
            4) menu_backup ;;
            5) menu_firewall ;;
            6) menu_link_test ;;
            7) menu_info ;;
            8) menu_install ;;
            0)
                echo -e "\n${DIM}Bye!${NC}\n"
                exit 0
                ;;
            *)
                warn "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# ─── Entry Point ─────────────────────────────────────────────────────────────
require_root
ask_server_role
main_menu
