#!/usr/bin/env bash
# =============================================================================
#  Two-Way Link Test
#  Part of BackhaulManager
#  Author  : emad1381
# =============================================================================

set -uo pipefail

APP_NAME="Two-Way Link Test"
TMP_DIR="$(mktemp -d /tmp/linktest.XXXXXX)"
LISTENER_PIDS=()
CLEANED="no"

R='\033[0;31m'
G='\033[0;32m'
Y='\033[0;33m'
B='\033[0;34m'
C='\033[0;36m'
W='\033[1;37m'
DIM='\033[2m'
NC='\033[0m'

line()  { echo -e "${DIM}------------------------------------------------------------${NC}"; }
hline() { echo -e "${B}============================================================${NC}"; }
info()  { echo -e "  ${C}>${NC} $*"; }
ok()    { echo -e "  ${G}OK${NC}   $*"; }
warn()  { echo -e "  ${Y}SKIP${NC} $*"; }
err()   { echo -e "  ${R}FAIL${NC} $*"; }

cleanup() {
  [[ "${CLEANED:-no}" == "yes" ]] && return 0
  CLEANED="yes"
  trap - INT TERM EXIT

  if [[ ${#LISTENER_PIDS[@]} -gt 0 ]]; then
    echo
    info "Stopping listeners and cleaning up..."
  fi

  for pid in "${LISTENER_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  pkill -P $$ 2>/dev/null || true
  rm -rf "$TMP_DIR" 2>/dev/null || true

  [[ ${#LISTENER_PIDS[@]} -gt 0 ]] && echo -e "  ${G}Done.${NC}"
}

on_interrupt() {
  echo
  warn "Interrupted."
  exit 130
}

trap cleanup EXIT
trap on_interrupt INT TERM

ask_default() {
  local prompt="$1"
  local def="$2"
  local ans
  local ps="${W}  ${prompt}${NC} ${DIM}[${def}]${NC}: "
  read -r -p "$(printf '%b' "$ps")" ans
  echo "${ans:-$def}"
}

valid_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 ))
}

valid_host() {
  local host="$1"
  [[ -n "$host" ]] && [[ "$host" != -* ]] && [[ "$host" =~ ^[A-Za-z0-9._:-]+$ ]]
}

normalize_ports() {
  printf '%s\n' "$1" | tr ',' ' ' | awk '{$1=$1; print}'
}

get_public_ip() {
  local ip=""
  if command -v curl >/dev/null 2>&1; then
    ip="$(timeout 4 curl -4 -sS https://api.ipify.org 2>/dev/null || true)"
  fi
  [[ -n "$ip" ]] && echo "$ip" || echo "unknown"
}

tcp_connect_test() {
  local host="$1" port="$2" timeout_sec="$3"
  if command -v nc >/dev/null 2>&1; then
    timeout "$timeout_sec" nc -z -w "$timeout_sec" "$host" "$port" >/dev/null 2>&1
  else
    timeout "$timeout_sec" bash -c 'exec 3<>"/dev/tcp/$1/$2"' bash "$host" "$port" >/dev/null 2>&1
  fi
}

tcp_banner_test() {
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

port_in_use() {
  command -v ss >/dev/null 2>&1 || return 1
  ss -lntu 2>/dev/null | awk '{print $5}' | grep -qE ":$1$"
}

start_python_listener() {
  local bind_ip="$1"
  local port="$2"

  if port_in_use "$port"; then
    warn "Port ${W}${port}${NC} already in use - skipping."
    return 0
  fi

  cat > "$TMP_DIR/listener-$port.py" <<'PY'
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

  python3 "$TMP_DIR/listener-$port.py" "$bind_ip" "$port" &
  local pid="$!"
  LISTENER_PIDS+=("$pid")
  sleep 0.3

  if kill -0 "$pid" 2>/dev/null; then
    ok "Port ${W}${port}${NC} is now listening  ${DIM}(pid $pid)${NC}"
  else
    err "Port ${W}${port}${NC} failed to bind."
  fi
}

show_local_info() {
  clear 2>/dev/null || true
  hline
  echo -e "  ${W}${APP_NAME}${NC}"
  hline
  echo -e "  ${DIM}Hostname  ${NC}  $(hostname)"
  echo -e "  ${DIM}Date      ${NC}  $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo -e "  ${DIM}Local IPs ${NC}  $(hostname -I 2>/dev/null | awk '{$1=$1; print}')"
  echo -e "  ${DIM}Public IP ${NC}  $(get_public_ip)"
  echo -e "  ${DIM}Kernel    ${NC}  $(uname -srmo)"
  hline
}

listener_mode() {
  local role="$1"

  echo
  echo -e "  ${B}Mode :${NC} LISTENER   ${B}Role :${NC} ${W}${role}${NC}"
  line

  if ! command -v python3 >/dev/null 2>&1; then
    err "python3 not found. Listener mode requires python3."
    return 1
  fi

  local bind_ip ports_raw peer_hint duration
  bind_ip="$(ask_default "Bind IP" "0.0.0.0")"
  ports_raw="$(ask_default "Ports (space or comma separated)" "80 443 2052 2053 2082 2083 2086 2087 2095 2096 8080 8443 8880")"
  ports_raw="$(normalize_ports "$ports_raw")"
  peer_hint="$(ask_default "Peer IP for display only" "AUTO")"
  duration="$(ask_default "Auto-stop after (seconds)" "300")"
  [[ "$duration" =~ ^[0-9]+$ ]] || duration=300

  local valid_ports=()
  local p
  for p in $ports_raw; do
    if valid_port "$p"; then
      valid_ports+=("$p")
    else
      warn "Invalid port: $p"
    fi
  done

  if [[ ${#valid_ports[@]} -eq 0 ]]; then
    err "No valid ports were provided."
    return 1
  fi

  echo
  line
  echo
  for p in "${valid_ports[@]}"; do
    start_python_listener "$bind_ip" "$p"
  done

  echo
  line
  echo -e "  ${W}Active ports on this server:${NC}"
  line
  local pat
  pat="$(printf '%s|' "${valid_ports[@]}")"
  pat="${pat%|}"
  ss -lntp 2>/dev/null | grep -E ":($pat)\b" | awk '{
      split($5, a, ":");
      port = a[length(a)];
      proc = $0; gsub(/.*users:\(\("/, "", proc); gsub(/".*/, "", proc);
      printf "  %-6s  %s\n", port, proc
    }' || true

  echo
  hline
  [[ "$peer_hint" != "AUTO" ]] && echo -e "  ${DIM}Peer :${NC} ${W}${peer_hint}${NC}"
  echo -e "  ${DIM}Ports:${NC} ${W}${valid_ports[*]}${NC}"
  echo
  echo -e "  Listening. Press ${W}ENTER${NC} to stop, or wait ${W}${duration}s${NC} for auto-stop."
  echo -e "  ${DIM}(incoming connections will appear below)${NC}"
  hline
  echo

  read -r -t "$duration" _ || true

  echo
  info "Shutting down listeners..."
}

tester_mode() {
  local role="$1"

  echo
  echo -e "  ${B}Mode :${NC} TESTER   ${B}Role :${NC} ${W}${role}${NC}"
  line
  echo

  local peer ports_raw timeout_sec ping_count
  peer="$(ask_default "Peer IP / domain" "")"
  if ! valid_host "$peer"; then
    err "A valid peer IP/domain is required."
    return 1
  fi

  ports_raw="$(ask_default "TCP ports (space or comma)" "80 443 2052 2053 2082 2083 2086 2087 2095 2096 8080 8443 8880")"
  ports_raw="$(normalize_ports "$ports_raw")"
  timeout_sec="$(ask_default "TCP timeout (seconds)" "3")"
  [[ "$timeout_sec" =~ ^[0-9]+$ ]] || timeout_sec=3
  ping_count="$(ask_default "Ping count" "4")"
  [[ "$ping_count" =~ ^[0-9]+$ ]] || ping_count=4

  echo
  line
  echo -e "  ${W}Ping  >>  ${peer}${NC}"
  line
  if command -v ping >/dev/null 2>&1; then
    local ping_out loss
    ping_out="$(ping -c "$ping_count" -W 1 "$peer" 2>&1 || true)"
    echo "$ping_out" | grep -E "^(PING|[0-9]+ bytes|---)" | sed 's/^/  /'
    loss="$(echo "$ping_out" | grep -oE '[0-9]+% packet loss' || echo "?")"
    echo
    if echo "$ping_out" | grep -q ", 0% packet loss"; then
      ok "Ping: ${G}no loss${NC}  ${DIM}(${loss})${NC}"
    elif echo "$ping_out" | grep -q "100% packet loss"; then
      err "Ping: ${R}all lost${NC}  ${DIM}(${loss})${NC}"
    else
      warn "Ping: ${Y}partial loss${NC}  ${DIM}(${loss})${NC}"
    fi
  else
    warn "ping not found."
  fi

  echo
  line
  echo -e "  ${W}TCP   >>  ${peer}${NC}"
  line
  echo

  local ok_count=0 fail_count=0 banner="" p
  for p in $ports_raw; do
    if ! valid_port "$p"; then
      warn "Port $p is invalid - skipped."
      continue
    fi

    if tcp_connect_test "$peer" "$p" "$timeout_sec"; then
      ok_count=$((ok_count + 1))
      banner="$(tcp_banner_test "$peer" "$p" "$timeout_sec" | head -n 1 || true)"
      if [[ -n "${banner:-}" ]]; then
        ok "Port ${W}${p}${NC}  ${G}OPEN${NC}   ${DIM}banner: ${banner}${NC}"
      else
        ok "Port ${W}${p}${NC}  ${G}OPEN${NC}"
      fi
    else
      fail_count=$((fail_count + 1))
      err "Port ${W}${p}${NC}  ${R}BLOCKED${NC}"
    fi
  done

  echo
  hline
  if (( ok_count > 0 && fail_count == 0 )); then
    echo -e "  ${G}ALL OPEN${NC}   all ${ok_count} tested ports are reachable."
  elif (( ok_count > 0 && fail_count > 0 )); then
    echo -e "  ${Y}PARTIAL${NC}    ${ok_count} open / ${fail_count} blocked"
  else
    echo -e "  ${R}ALL BLOCKED${NC}   no tested port is reachable."
    echo -e "  ${DIM}Likely cause: firewall, routing issue, or provider filtering.${NC}"
  fi
  hline
  echo
}

main() {
  show_local_info

  echo
  echo -e "  ${W}Server role:${NC}"
  echo -e "  ${C}1)${NC} IRAN"
  echo -e "  ${C}2)${NC} KHAREJ"
  echo -e "  ${C}3)${NC} CUSTOM"
  echo
  read -r -p "  Select [1-3]: " role_choice

  local role
  case "$role_choice" in
    1) role="IRAN" ;;
    2) role="KHAREJ" ;;
    3) role="$(ask_default "Custom role name" "CUSTOM")" ;;
    *) role="UNKNOWN" ;;
  esac

  echo
  line
  echo
  echo -e "  ${W}Operation mode:${NC}"
  echo -e "  ${C}1)${NC} LISTEN  - open temporary TCP ports on this server"
  echo -e "  ${C}2)${NC} TEST    - test ping + TCP to peer"
  echo -e "  ${C}3)${NC} INFO    - show local network info only"
  echo
  read -r -p "  Select [1-3]: " mode_choice

  case "$mode_choice" in
    1) listener_mode "$role" ;;
    2) tester_mode "$role" ;;
    3)
      echo
      line
      echo -e "  ${W}Listening TCP ports:${NC}"
      line
      ss -lntp 2>/dev/null | awk 'NR>1 {
        split($5, a, ":");
        port = a[length(a)];
        proc = $0; gsub(/.*users:\(\("/, "", proc); gsub(/".*/, "", proc);
        printf "  %-6s  %s\n", port, proc
      }' || true
      ;;
    *)
      err "Invalid selection."
      return 1
      ;;
  esac
}

main "$@"
