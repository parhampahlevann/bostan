#!/usr/bin/env bash
# =============================================================================
#  TAQ-BOSTAN - Hysteria 2 tunnel manager (Iran <-> Foreign server)
#  Developed by Parsa => https://github.com/ParsaKSH
#  Sponsored by DigitalVPS.ir
#
#  Iran server    : runs "hysteria client"  (tcpForwarding / udpForwarding)
#  Foreign server : runs "hysteria server"
#
#  Optional environment variable:
#    HYSTERIA_MIRROR=https://your-mirror/   (prefix used for GitHub downloads)
# =============================================================================

SCRIPT_VERSION="2.0"
FALLBACK_VERSION="v2.12.3"          # used only if the latest version cannot be looked up
CONF_DIR="${HY_CONF_DIR:-/etc/hysteria}"
BIN="${HY_BIN:-/usr/local/bin/hysteria}"
UNIT_DIR="${HY_UNIT_DIR:-/etc/systemd/system}"
SERVER_UNIT="hysteria"
SERVER_CFG="$CONF_DIR/server-config.yaml"
SERVER_ENV="$CONF_DIR/server.env"
CERT="$CONF_DIR/self.crt"
KEY="$CONF_DIR/self.key"
FW_FILE="$CONF_DIR/.firewall-ports"
SYSCTL_FILE="/etc/sysctl.d/99-hysteria.conf"
CRON_CMD='0 4 * * * /usr/bin/systemctl restart hysteria'

RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; CYAN=$'\e[36m'
WHITE=$'\e[97m'; BOLD_GREEN=$'\e[1;32m'; RESET=$'\e[0m'

# ------------------------------- helpers -------------------------------------
info() { echo "${CYAN}$*${RESET}"; }
ok()   { echo "${GREEN}$*${RESET}"; }
warn() { echo "${YELLOW}$*${RESET}"; }
err()  { echo "${RED}$*${RESET}" >&2; }
pause() { echo; read -rp "Press Enter to continue..." _; }

print_art() {
  echo "$BOLD_GREEN"
  cat <<'ART'
@@@@@@@   @@@@@@    @@@@@@
@@@@@@@  @@@@@@@@  @@@@@@@@
  @@!    @@!  @@@  @@!  @@@
  !@!    !@!  @!@  !@!  @!@
  @!!    @!@!@!@!  @!@  !@!
  !!!    !!!@!!!!  !@!  !!!
  !!:    !!:  !!!  !!:!!:!:
  :!:    :!:  !:!  :!: :!:
   ::    ::   :::  ::::: :!
   :      :   : :   : :  :::
@@@@@@@    @@@@@@    @@@@@@  @@@@@@@   @@@@@@   @@@  @@@
@@@@@@@@  @@@@@@@@  @@@@@@@  @@@@@@@  @@@@@@@@  @@@@ @@@
@@!  @@@  @@!  @@@  !@@        @@!    @@!  @@@  @@!@!@@@
!@   @!@  !@!  @!@  !@!        !@!    !@!  @!@  !@!!@!@!
@!@!@!@   @!@  !@!  !!@@!!     @!!    @!@!@!@!  @!@ !!@!
!!!@!!!!  !@!  !!!   !!@!!!    !!!    !!!@!!!!  !@!  !!!
!!:  !!!  !!:  !!!       !:!   !!:    !!:  !!!  !!:  !!!
:!:  !:!  :!:  !:!      !:!    :!:    :!:  !:!  :!:  !:!
 :: ::::  ::::: ::  :::: ::     ::    ::   :::   ::   ::
:: : ::    : :  :   :: : :      :      :   : :  ::    :
ART
  echo "${YELLOW}=========================================================="
  echo "Developed by Parsa => https://github.com/ParsaKSH"
  echo "${RED}Sponsored by DigitalVPS.ir"
  echo "${YELLOW}Love Iran :)${RESET}"
  echo
}

draw_menu() {
  local title="$1"; shift
  local inner=56 line pad_l pad_r o
  line=$(printf '%*s' "$inner" '' | sed 's/ /═/g')
  pad_l=$(( (inner - ${#title}) / 2 )); pad_r=$(( inner - ${#title} - pad_l ))
  echo "${GREEN}╔${line}╗${RESET}"
  printf '%s║%s%*s%s%*s%s║%s\n' "$GREEN" "$WHITE" "$pad_l" '' "$title" "$pad_r" '' "$GREEN" "$RESET"
  echo "${GREEN}╠${line}╣${RESET}"
  for o in "$@"; do
    printf '%s║ %s%-*s%s ║%s\n' "$GREEN" "$WHITE" $((inner - 2)) "$o" "$GREEN" "$RESET"
  done
  echo "${GREEN}╚${line}╝${RESET}"
}

# ask VAR "Prompt" "default"   (all whitespace is stripped from the answer)
ask() {
  local __v="$1" __p="$2" __d="${3-}" __r
  if [[ -n $__d ]]; then read -rp "$__p [$__d]: " __r; __r="${__r:-$__d}"
  else read -rp "$__p: " __r; fi
  __r="${__r//[[:space:]]/}"
  printf -v "$__v" '%s' "$__r"
}

yesno() {   # yesno "Prompt" default(y|n)  -> exit 0 on yes
  local d="${2:-n}" r hint="y/N"
  [[ $d == y ]] && hint="Y/n"
  read -rp "$1 [$hint]: " r
  r="${r:-$d}"; r="${r,,}"
  [[ $r == y || $r == yes ]]
}

read_choice() {   # read_choice VAR default max
  local __c
  read -rp "Choice [$2]: " __c; __c="${__c:-$2}"
  [[ $__c =~ ^[0-9]+$ ]] && (( __c >= 1 && __c <= $3 )) || __c="$2"
  printf -v "$1" '%s' "$__c"
}

# ------------------------------- validation ----------------------------------
valid_port() { [[ $1 =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
valid_pass() { [[ $1 =~ ^[A-Za-z0-9._~@%+=-]{1,128}$ ]]; }
valid_sni()  { [[ $1 =~ ^[A-Za-z0-9.-]{1,253}$ ]]; }
valid_pin()  { [[ -z $1 || $1 =~ ^[A-Fa-f0-9:]{64,95}$ ]]; }
rand_pass()  { tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24; }

is_ipv4() {
  [[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local i; for i in 1 2 3 4; do (( 10#${BASH_REMATCH[i]} <= 255 )) || return 1; done
}

normalize_host() {   # prints host (IPv6 wrapped in [ ]) or fails
  local h="${1#\[}"; h="${h%\]}"
  if is_ipv4 "$h"; then echo "$h"
  elif [[ $h == *:* && $h =~ ^[0-9A-Fa-f:.]+$ ]]; then echo "[$h]"
  elif [[ $h =~ ^[0-9.]+$ ]]; then return 1          # looks like an IPv4 but is not valid
  elif [[ $h =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then echo "$h"
  else return 1; fi
}

parse_ports() {      # "443, 8443,443" -> "443,8443"
  local raw="${1//[[:space:]]/}" p arr out=() seen=" "
  [[ -n $raw ]] || return 1
  IFS=',' read -ra arr <<< "$raw"
  for p in "${arr[@]}"; do
    valid_port "$p" || return 1
    p=$((10#$p))
    [[ $seen == *" $p "* ]] && continue
    seen+="$p "; out+=("$p")
  done
  (IFS=,; echo "${out[*]}")
}

port_in_use() {      # port proto(tcp|udp)
  local flag="-ltn"; [[ $2 == udp ]] && flag="-lun"
  ss $flag 2>/dev/null | awk 'NR>1{print $4}' | grep -Eq "[:.]$1\$"
}

# ------------------------------- system prep ---------------------------------
need_root() {
  [[ $EUID -eq 0 ]] || { err "Please run this script as root (sudo -i)."; exit 1; }
  [[ -d /run/systemd/system ]] || { err "systemd is required."; exit 1; }
}

ensure_deps() {
  local need=() pm="" ss_pkg="iproute2"
  if command -v apt-get >/dev/null 2>&1; then pm=apt
  elif command -v dnf >/dev/null 2>&1; then pm=dnf; ss_pkg="iproute"
  elif command -v yum >/dev/null 2>&1; then pm=yum; ss_pkg="iproute"; fi
  command -v curl    >/dev/null 2>&1 || need+=(curl)
  command -v openssl >/dev/null 2>&1 || need+=(openssl)
  command -v ss      >/dev/null 2>&1 || need+=("$ss_pkg")
  (( ${#need[@]} )) || return 0
  info "Installing required packages: ${need[*]}"
  case "$pm" in
    apt) apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}" >/dev/null 2>&1 ;;
    dnf|yum) "$pm" install -y -q "${need[@]}" >/dev/null 2>&1 ;;
  esac
  command -v curl >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 && return 0
  err "Could not install curl/openssl automatically. Install them manually and run again."
  return 1
}

tune_sysctl() {   # QUIC needs large UDP socket buffers
  cat > "$SYSCTL_FILE" <<'EOF'
net.core.rmem_max=16777216
net.core.wmem_max=16777216
EOF
  sysctl -q -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
}

fw_record() { grep -qxF "$1" "$FW_FILE" 2>/dev/null || echo "$1" >> "$FW_FILE"; }

fw_open() {   # port proto
  local e="$1/$2"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    ufw status 2>/dev/null | grep -Eq "^$1/$2[[:space:]]+ALLOW" || { ufw allow "$e" >/dev/null 2>&1 && fw_record "$e"; }
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --query-port="$e" >/dev/null 2>&1 || {
      firewall-cmd --permanent --add-port="$e" >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1 && fw_record "$e"; }
  fi
}

fw_close() {  # only closes rules that this script opened
  local e="$1/$2"
  grep -qxF "$e" "$FW_FILE" 2>/dev/null || return 0
  command -v ufw >/dev/null 2>&1 && ufw --force delete allow "$e" >/dev/null 2>&1
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-port="$e" >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1
  fi
  sed -i "\#^${e}\$#d" "$FW_FILE"
}

set_cron() {  # on|off  - optional daily restart of the foreign server
  command -v crontab >/dev/null 2>&1 || return 0
  local tmp; tmp=$(mktemp)
  crontab -l 2>/dev/null | grep -vF "$CRON_CMD" > "$tmp"
  [[ $1 == on ]] && echo "$CRON_CMD" >> "$tmp"
  crontab "$tmp" 2>/dev/null; rm -f "$tmp"
}

# ------------------------------- Hysteria binary -----------------------------
detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)           echo amd64 ;;
    aarch64|arm64)          echo arm64 ;;
    armv7l|armv7|armv6l|armv6) echo arm ;;
    armv5*)                 echo armv5 ;;
    i386|i686)              echo 386 ;;
    riscv64)                echo riscv64 ;;
    s390x)                  echo s390x ;;
    loongarch64)            echo loong64 ;;
    *) return 1 ;;
  esac
}

bin_version() {
  [[ -x $BIN ]] || return 1
  "$BIN" version 2>/dev/null | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

get_latest_version() {
  local repo v
  for repo in HyNetworks/hysteria apernet/hysteria; do
    v=$(curl -fsSL --connect-timeout 6 --max-time 15 "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null \
        | sed -nE 's#.*"tag_name"[[:space:]]*:[[:space:]]*"app/(v[0-9]+\.[0-9]+\.[0-9]+)".*#\1#p' | head -n1)
    [[ -n $v ]] && { echo "$v"; return 0; }
    v=$(curl -fsSLI -o /dev/null -w '%{url_effective}' --connect-timeout 6 --max-time 15 "https://github.com/$repo/releases/latest" 2>/dev/null \
        | sed -nE 's#.*/tag/app(%2F|/)(v[0-9]+\.[0-9]+\.[0-9]+)$#\2#p')
    [[ -n $v ]] && { echo "$v"; return 0; }
  done
  echo "$FALLBACK_VERSION"
}

fetch() { curl -fL --progress-bar --connect-timeout 10 --max-time 900 --retry 2 --retry-delay 2 -o "$2" "$1"; }

verify_binary() { chmod +x "$1" && "$1" version >/dev/null 2>&1; }

check_hash() {   # base arch file   (returns 0 when hashes are unavailable)
  local hs expected got
  hs=$(curl -fsSL --connect-timeout 10 --max-time 30 "$1/hashes.txt" 2>/dev/null) || { warn "  checksum list unreachable - skipping checksum"; return 0; }
  expected=$(awk -v f="hysteria-linux-$2" '{n=$2; sub(/^\*/,"",n); sub(/^.*\//,"",n)} n==f{print $1; exit}' <<<"$hs")
  [[ -n $expected ]] || return 0
  got=$(sha256sum "$3" | awk '{print $1}')
  [[ $expected == "$got" ]]
}

manual_binary() {   # arch tmp
  local c u f
  warn "Automatic download failed (GitHub is often unreachable from Iranian servers)."
  echo "  1) Enter a direct download URL / mirror for hysteria-linux-$1"
  echo "  2) Use a hysteria binary that is already on this server (upload it with scp)"
  echo "  3) Cancel"
  read_choice c 3 3
  case "$c" in
    1) read -rp "URL: " u; [[ -n $u ]] && fetch "$u" "$2" && verify_binary "$2" ;;
    2) read -rp "Path to the hysteria binary: " f
       [[ -f $f ]] && cp -f "$f" "$2" && verify_binary "$2" ;;
    *) return 1 ;;
  esac
}

install_binary() {   # version allow_manual(0|1)
  local ver="$1" manual="$2" arch tmp base got=0
  arch=$(detect_arch) || { err "Unsupported CPU architecture: $(uname -m)"; return 1; }
  mkdir -p "$(dirname "$BIN")"
  tmp=$(mktemp "${BIN}.dl.XXXXXX") || return 1
  local -a bases=(
    "https://github.com/HyNetworks/hysteria/releases/download/app%2F${ver}"
    "https://github.com/apernet/hysteria/releases/download/app%2F${ver}"
  )
  [[ -n ${HYSTERIA_MIRROR:-} ]] && bases=("${HYSTERIA_MIRROR%/}/${bases[0]}" "${bases[@]}")
  for base in "${bases[@]}"; do
    info "Downloading hysteria-linux-$arch $ver ..."
    fetch "$base/hysteria-linux-$arch" "$tmp" || { warn "  download failed: ${base%%/releases*}"; continue; }
    check_hash "$base" "$arch" "$tmp" || { warn "  checksum mismatch - discarding file"; continue; }
    verify_binary "$tmp" || { warn "  downloaded file cannot run on this server"; continue; }
    got=1; break
  done
  (( got )) || { [[ $manual == 1 ]] && manual_binary "$arch" "$tmp" && got=1; }
  if (( got )); then mv -f "$tmp" "$BIN" && chmod 755 "$BIN"; return 0; fi
  rm -f "$tmp"; return 1
}

ensure_binary() {
  local cur latest newest
  cur=$(bin_version)
  info "Checking the latest Hysteria 2 release ..."
  latest=$(get_latest_version)
  if [[ -n $cur ]]; then
    newest=$(printf '%s\n%s\n' "$cur" "$latest" | sort -V | tail -n1)
    if [[ $newest == "$cur" ]]; then ok "Hysteria $cur is installed and up to date."; return 0; fi
    info "Installed: $cur  ->  latest: $latest"
    if install_binary "$latest" 0; then ok "Hysteria updated to $(bin_version)."; BIN_UPDATED=1
    else warn "Update failed - continuing with $cur."; fi
    return 0
  fi
  if install_binary "$latest" 1; then ok "Hysteria $(bin_version) installed."; BIN_UPDATED=1; return 0; fi
  err "Hysteria binary is not installed. Cannot continue."
  return 1
}

# ------------------------------- config builders -----------------------------
obfs_block() {   # y|n password
  [[ $1 == y ]] || return 0
  printf 'obfs:\n  type: salamander\n  salamander:\n    password: "%s"\n' "$2"
}

quic_block() {   # server|client  profile(1|2|3)
  local a b c d s
  case "$2" in
    2) a=50331648;  b=100663296; c=100663296; d=201326592; s=8192  ;;
    3) a=100663296; b=201326592; c=201326592; d=402653184; s=24576 ;;
    *) a=25165824;  b=50331648;  c=50331648;  d=100663296; s=4096  ;;
  esac
  echo "quic:"
  echo "  initStreamReceiveWindow: $a"
  echo "  maxStreamReceiveWindow: $b"
  echo "  initConnReceiveWindow: $c"
  echo "  maxConnReceiveWindow: $d"
  echo "  maxIdleTimeout: 30s"
  if [[ $1 == server ]]; then echo "  maxIncomingStreams: $s"; else echo "  keepAlivePeriod: 10s"; fi
  echo "  disablePathMTUDiscovery: false"
}

choose_profile() {   # VAR default
  draw_menu "Expected Simultaneous Users" \
    "1 | 1 to 50 users    (light load)" \
    "2 | 50 to 100 users  (medium load, more RAM)" \
    "3 | 100 to 300 users (heavy load, most RAM)"
  read_choice "$1" "${2:-1}" 3
}

write_unit() {   # name description exec-arguments
  cat > "$UNIT_DIR/$1.service" <<EOF
[Unit]
Description=$2
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN $3
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

# ------------------------------- foreign server ------------------------------
ensure_cert() {
  mkdir -p "$CONF_DIR"
  # Chrome-parroting Hysteria clients (>= 2.11) cannot handshake with Ed25519 certificates
  if [[ -s $CERT && -s $KEY ]] && ! openssl x509 -in "$CERT" -noout -text 2>/dev/null | grep -qi 'ed25519'; then
    ok "Reusing the existing TLS certificate."; return 0
  fi
  [[ -s $CERT ]] && warn "Old Ed25519 certificate found - replacing it with an ECDSA (P-256) certificate."
  openssl req -x509 -nodes -days 3650 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$KEY" -out "$CERT" -subj "/CN=hysteria" >/dev/null 2>&1 \
    || { err "Failed to generate the TLS certificate."; return 1; }
  chmod 600 "$KEY" "$CERT"
  ok "TLS certificate generated."
}

cert_pin() { openssl x509 -in "$CERT" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2; }

setup_foreign() {
  echo; info "=== Foreign server setup (Hysteria 2 server) ==="
  ensure_deps || return 1
  ensure_binary || return 1
  tune_sysctl
  ensure_cert || return 1
  mkdir -p "$CONF_DIR"

  local S_PORT="" S_PASS="" S_OBFS="" S_PROFILE="" pass_in
  [[ -f $SERVER_ENV ]] && . "$SERVER_ENV"

  while :; do
    ask S_PORT "Hysteria UDP port (1-65535)" "${S_PORT:-443}"
    if ! valid_port "$S_PORT"; then err "Invalid port."; S_PORT=""; continue; fi
    if ! systemctl is-active --quiet "$SERVER_UNIT" 2>/dev/null && port_in_use "$S_PORT" udp; then
      err "UDP port $S_PORT is already used by another program."; S_PORT=""; continue
    fi
    break
  done
  local def_pass="${S_PASS:-$(rand_pass)}"
  while :; do
    ask pass_in "Tunnel password (A-Z a-z 0-9 . _ ~ @ % + = -)" "$def_pass"
    valid_pass "$pass_in" && break
    err "Invalid password."; def_pass="$(rand_pass)"
  done
  S_PASS="$pass_in"
  if yesno "Enable Salamander obfuscation? (Iran side must use the same setting)" "${S_OBFS:-n}"; then S_OBFS=y; else S_OBFS=n; fi
  choose_profile S_PROFILE "${S_PROFILE:-1}"

  {
    cat <<EOF
listen: ":${S_PORT}"
tls:
  cert: ${CERT}
  key: ${KEY}
  sniGuard: disable
auth:
  type: password
  password: "${S_PASS}"
EOF
    obfs_block "$S_OBFS" "$S_PASS"
    quic_block server "$S_PROFILE"
    echo "speedTest: true"
  } > "$SERVER_CFG"
  chmod 600 "$SERVER_CFG"
  printf 'S_PORT=%q\nS_PASS=%q\nS_OBFS=%q\nS_PROFILE=%q\n' "$S_PORT" "$S_PASS" "$S_OBFS" "$S_PROFILE" > "$SERVER_ENV"
  chmod 600 "$SERVER_ENV"

  write_unit "$SERVER_UNIT" "Hysteria2 Tunnel Server" "server -c $SERVER_CFG"
  systemctl daemon-reload
  systemctl enable "$SERVER_UNIT" >/dev/null 2>&1
  systemctl restart "$SERVER_UNIT"
  fw_open "$S_PORT" udp
  if yesno "Restart the server automatically every day at 04:00?" n; then set_cron on; else set_cron off; fi

  sleep 2
  if systemctl is-active --quiet "$SERVER_UNIT" && port_in_use "$S_PORT" udp; then
    ok "Foreign server is running."
  else
    err "The server did not start correctly. Last log lines:"
    journalctl -u "$SERVER_UNIT" -n 15 --no-pager 2>/dev/null | cut -c1-220
    return 1
  fi
  echo
  echo "${BOLD_GREEN}Use these values on the Iran server:${RESET}"
  echo "  UDP port    : $S_PORT"
  echo "  Password    : $S_PASS"
  echo "  Obfuscation : $([[ $S_OBFS == y ]] && echo "enabled (key = password)" || echo disabled)"
  echo "  Cert pin    : $(cert_pin)   (optional - pins the certificate)"
  warn "If you use a cloud firewall / security group, allow UDP $S_PORT there as well."
}

# ------------------------------- Iran tunnels --------------------------------
tunnel_env() { echo "$CONF_DIR/tunnel$1.env"; }
tunnel_cfg() { echo "$CONF_DIR/iran-config$1.yaml"; }

list_tunnel_numbers() {
  local f x
  for f in "$CONF_DIR"/iran-config*.yaml; do
    [[ -e $f ]] || continue
    x="${f##*iran-config}"; x="${x%.yaml}"
    [[ $x =~ ^[0-9]+$ ]] && echo "$((10#$x))"
  done | sort -n
}

next_tunnel_number() {
  local n=1 x
  for x in $(list_tunnel_numbers); do (( x >= n )) && n=$((x + 1)); done
  echo "$n"
}

tunnel_ports() {   # works for tunnels created by older versions of the script too
  local p=""
  [[ -f $(tunnel_env "$1") ]] && p=$( . "$(tunnel_env "$1")" 2>/dev/null; echo "${T_PORTS:-}" )
  if [[ -z $p && -f $(tunnel_cfg "$1") ]]; then
    p=$(grep -oE 'listen: *[^ ]*:[0-9]+' "$(tunnel_cfg "$1")" | grep -oE '[0-9]+$' | sort -un | paste -sd, -)
  fi
  echo "$p"
}

tunnel_mode() {
  local m=""
  [[ -f $(tunnel_env "$1") ]] && m=$( . "$(tunnel_env "$1")" 2>/dev/null; echo "${T_MODE:-}" )
  echo "${m:-both}"
}

tunnel_server() {
  local s=""
  [[ -f $(tunnel_env "$1") ]] && s=$( . "$(tunnel_env "$1")" 2>/dev/null; echo "${T_SERVER:-}:${T_PORT:-}" )
  if [[ -z $s || $s == ":" ]]; then s=$(grep -m1 '^server:' "$(tunnel_cfg "$1")" 2>/dev/null | cut -d'"' -f2); fi
  echo "$s"
}

ports_used_by_others() {   # tunnel-number
  local n
  for n in $(list_tunnel_numbers); do
    [[ $n == "$1" ]] && continue
    tunnel_ports "$n" | tr ',' ' '
  done
}

check_ports_free() {   # n mode ports
  local n="$1" mode="$2" ports="$3" p rc=0 active=0 others
  systemctl is-active --quiet "hysteria$n" 2>/dev/null && active=1
  others=" $(ports_used_by_others "$n" | tr '\n' ' ') "
  for p in ${ports//,/ }; do
    if [[ $others == *" $p "* ]]; then err "Port $p is already used by another tunnel."; rc=1; continue; fi
    (( active )) && continue
    if [[ $mode != udp ]] && port_in_use "$p" tcp; then err "TCP port $p is already in use on this server."; rc=1; fi
    if [[ $mode != tcp ]] && port_in_use "$p" udp; then err "UDP port $p is already in use on this server."; rc=1; fi
  done
  return $rc
}

write_client_config() {   # n   (reads the T_* variables of create_tunnel)
  local n="$1" remote="127.0.0.1" p
  [[ $T_IPV == 2 ]] && remote="[::1]"
  {
    echo "server: \"${T_SERVER}:${T_PORT}\""
    echo "auth: \"${T_PASS}\""
    echo "tls:"
    echo "  sni: \"${T_SNI}\""
    echo "  insecure: true"
    [[ -n $T_PIN ]] && echo "  pinSHA256: \"${T_PIN}\""
    obfs_block "$T_OBFS" "$T_PASS"
    quic_block client "$T_PROFILE"
    if [[ $T_MODE != udp ]]; then
      echo "tcpForwarding:"
      for p in ${T_PORTS//,/ }; do
        printf '  - listen: 0.0.0.0:%s\n    remote: "%s:%s"\n' "$p" "$remote" "$p"
      done
    fi
    if [[ $T_MODE != tcp ]]; then
      echo "udpForwarding:"
      for p in ${T_PORTS//,/ }; do
        printf '  - listen: 0.0.0.0:%s\n    remote: "%s:%s"\n    timeout: 60s\n' "$p" "$remote" "$p"
      done
    fi
  } > "$(tunnel_cfg "$n")"
  chmod 600 "$(tunnel_cfg "$n")"
}

verify_tunnel() {   # n since-timestamp
  local svc="hysteria$1" i
  info "Waiting for the tunnel to connect ..."
  for i in 1 2 3 4 5 6 7 8; do
    sleep 2
    systemctl is-active --quiet "$svc" || continue
    if journalctl -u "$svc" --since "$2" --no-pager 2>/dev/null | grep -q 'connected to server'; then
      ok "Tunnel #$1 is CONNECTED to the foreign server."
      return 0
    fi
  done
  err "Tunnel #$1 did not connect. Last log lines:"
  journalctl -u "$svc" -n 8 --no-pager 2>/dev/null | cut -c1-200 | sed 's/^/   /'
  cat <<EOF
${YELLOW}Common causes:
  1) The UDP port of the foreign server is blocked (cloud firewall / security group / ufw / iptables).
  2) Password or obfuscation setting is different on the two servers.
  3) The foreign server still uses an old setup (Ed25519 certificate) - run "Setup FOREIGN server" again there.
  4) The ISP drops QUIC/UDP to this IP - try another port, or enable obfuscation on both sides.${RESET}
EOF
  return 1
}

create_tunnel() {   # n  (also used to edit an existing tunnel)
  local n="$1" f_env; f_env=$(tunnel_env "$n")
  local T_SERVER="" T_PORT="" T_PASS="" T_OBFS="" T_SNI="" T_PIN="" T_IPV="" T_PORTS="" T_MODE="" T_PROFILE=""
  [[ -f $f_env ]] && . "$f_env"
  local host portin pass sni pin ports old_ports="" ts p

  echo; info "--- Tunnel #$n ---"
  while :; do
    ask host "Foreign server IP or domain" "$T_SERVER"
    host=$(normalize_host "$host") && break
    err "Invalid address."
  done
  while :; do
    ask portin "Hysteria port on the foreign server" "${T_PORT:-443}"
    valid_port "$portin" && break; err "Invalid port."
  done
  while :; do
    ask pass "Password (same as on the foreign server)" "$T_PASS"
    valid_pass "$pass" && break; err "Invalid password (allowed: A-Z a-z 0-9 . _ ~ @ % + = -)."
  done
  if yesno "Is obfuscation enabled on the foreign server?" "${T_OBFS:-n}"; then T_OBFS=y; else T_OBFS=n; fi
  while :; do
    ask sni "SNI" "${T_SNI:-google.com}"
    valid_sni "$sni" && break; err "Invalid SNI."
  done
  while :; do
    ask pin "Certificate SHA256 pin shown on the foreign server (optional, Enter to skip, - to clear)" "$T_PIN"
    [[ $pin == "-" ]] && pin=""
    valid_pin "$pin" && break; err "Invalid fingerprint."
  done
  draw_menu "Forward target on the foreign server" "1 | IPv4  (127.0.0.1)" "2 | IPv6  ([::1])"
  read_choice T_IPV "${T_IPV:-1}" 2
  draw_menu "Protocol to forward" "1 | TCP + UDP" "2 | TCP only" "3 | UDP only"
  local mode_n=1; [[ $T_MODE == tcp ]] && mode_n=2; [[ $T_MODE == udp ]] && mode_n=3
  read_choice mode_n "$mode_n" 3
  case "$mode_n" in 2) T_MODE=tcp ;; 3) T_MODE=udp ;; *) T_MODE=both ;; esac
  while :; do
    ask ports "Ports to tunnel (comma separated, e.g. 443,8443,2053)" "$T_PORTS"
    ports=$(parse_ports "$ports") || { err "Invalid port list."; continue; }
    check_ports_free "$n" "$T_MODE" "$ports" && break
  done
  choose_profile T_PROFILE "${T_PROFILE:-1}"

  old_ports=$(tunnel_ports "$n")
  T_SERVER="$host"; T_PORT="$portin"; T_PASS="$pass"; T_SNI="$sni"; T_PIN="$pin"; T_PORTS="$ports"

  mkdir -p "$CONF_DIR"
  write_client_config "$n"
  printf 'T_SERVER=%q\nT_PORT=%q\nT_PASS=%q\nT_OBFS=%q\nT_SNI=%q\nT_PIN=%q\nT_IPV=%q\nT_PORTS=%q\nT_MODE=%q\nT_PROFILE=%q\n' \
    "$T_SERVER" "$T_PORT" "$T_PASS" "$T_OBFS" "$T_SNI" "$T_PIN" "$T_IPV" "$T_PORTS" "$T_MODE" "$T_PROFILE" > "$f_env"
  chmod 600 "$f_env"

  write_unit "hysteria$n" "Hysteria2 Client $n" "client -c $(tunnel_cfg "$n")"
  systemctl daemon-reload
  systemctl enable "hysteria$n" >/dev/null 2>&1
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  systemctl restart "hysteria$n"

  for p in ${old_ports//,/ }; do fw_close "$p" tcp; fw_close "$p" udp; done
  for p in ${T_PORTS//,/ }; do
    [[ $T_MODE != udp ]] && fw_open "$p" tcp
    [[ $T_MODE != tcp ]] && fw_open "$p" udp
  done
  verify_tunnel "$n" "$ts"
}

setup_iran() {
  echo; info "=== Iran server setup (Hysteria 2 client tunnels) ==="
  ensure_deps || return 1
  ensure_binary || return 1
  tune_sysctl
  local n
  while :; do
    n=$(next_tunnel_number)
    create_tunnel "$n"
    yesno "Add another foreign server (another tunnel)?" n || break
  done
}

delete_tunnel() {   # n
  local n="$1" ports p mode
  ports=$(tunnel_ports "$n"); mode=$(tunnel_mode "$n")
  systemctl disable --now "hysteria$n" >/dev/null 2>&1
  rm -f "$UNIT_DIR/hysteria$n.service" "$(tunnel_cfg "$n")" "$(tunnel_env "$n")"
  systemctl daemon-reload
  for p in ${ports//,/ }; do fw_close "$p" tcp; fw_close "$p" udp; done
  ok "Tunnel #$n deleted."
}

list_tunnels() {
  local n any=0
  for n in $(list_tunnel_numbers); do
    any=1
    printf '  #%-3s server=%-28s ports=%-24s service=%s\n' "$n" "$(tunnel_server "$n")" "$(tunnel_ports "$n")" \
      "$(systemctl is-active "hysteria$n" 2>/dev/null)"
  done
  (( any )) || warn "  (no tunnels)"
}

PICKED=""
pick_tunnel() {
  local x; read -rp "Tunnel number: " x
  if [[ $x =~ ^[0-9]+$ ]] && [[ -f $(tunnel_cfg "$((10#$x))") ]]; then PICKED=$((10#$x)); return 0; fi
  err "Tunnel #$x does not exist."; return 1
}

manage_tunnels() {
  local c n
  while :; do
    echo; info "Existing tunnels:"; list_tunnels
    [[ -n $(list_tunnel_numbers) ]] || return 0
    draw_menu "Manage Tunnels" "1 | Edit a tunnel" "2 | Restart a tunnel" "3 | Restart all tunnels" "4 | Delete a tunnel" "0 | Back"
    read -rp "Select an option: " c
    case "$c" in
      1) pick_tunnel && create_tunnel "$PICKED" ;;
      2) pick_tunnel && { systemctl restart "hysteria$PICKED"; ok "Tunnel #$PICKED restarted."; } ;;
      3) for n in $(list_tunnel_numbers); do systemctl restart "hysteria$n"; done; ok "All tunnels restarted." ;;
      4) pick_tunnel && yesno "Delete tunnel #$PICKED?" n && delete_tunnel "$PICKED" ;;
      0) return 0 ;;
      *) err "Invalid option." ;;
    esac
  done
}

# ------------------------------- status / tools ------------------------------
show_status() {
  local n p mode ports tcp udp
  echo; info "Hysteria binary : $(bin_version || echo 'not installed')"
  if [[ -f $UNIT_DIR/$SERVER_UNIT.service ]]; then
    p=$(grep -m1 '^listen:' "$SERVER_CFG" 2>/dev/null | grep -oE '[0-9]+' | head -n1)
    echo; echo "Foreign server service : $(systemctl is-active "$SERVER_UNIT" 2>/dev/null)"
    echo "  UDP port ${p:-?} listening : $(port_in_use "${p:-0}" udp && echo yes || echo NO)"
  fi
  for n in $(list_tunnel_numbers); do
    ports=$(tunnel_ports "$n"); mode=$(tunnel_mode "$n")
    echo; echo "Tunnel #$n  ->  $(tunnel_server "$n")   service: $(systemctl is-active "hysteria$n" 2>/dev/null)"
    for p in ${ports//,/ }; do
      tcp="-"; udp="-"
      [[ $mode != udp ]] && { port_in_use "$p" tcp && tcp="listening" || tcp="NOT listening"; }
      [[ $mode != tcp ]] && { port_in_use "$p" udp && udp="listening" || udp="NOT listening"; }
      printf '   port %-6s tcp: %-14s udp: %s\n' "$p" "$tcp" "$udp"
    done
  done
  [[ ! -f $UNIT_DIR/$SERVER_UNIT.service && -z $(list_tunnel_numbers) ]] && warn "Nothing is installed yet."
  return 0
}

run_speedtest() {
  [[ -x $BIN ]] || { err "Hysteria is not installed."; return 1; }
  [[ -n $(list_tunnel_numbers) ]] || { err "No tunnel exists. Run this on the Iran server."; return 1; }
  list_tunnels
  pick_tunnel || return 1
  info "Running speed test through tunnel #$PICKED (Ctrl+C to stop) ..."
  trap ':' INT
  "$BIN" speedtest -c "$(tunnel_cfg "$PICKED")"
  trap 'echo; exit 130' INT
}

show_logs() {
  local c n
  echo "  0) Foreign server (hysteria)"
  list_tunnels
  read -rp "Service (0 = server, or tunnel number): " c
  if [[ $c == 0 ]]; then n="$SERVER_UNIT"
  elif [[ $c =~ ^[0-9]+$ ]]; then n="hysteria$((10#$c))"
  else err "Invalid choice."; return 1; fi
  journalctl -u "$n" -n 60 --no-pager 2>/dev/null | cut -c1-220
}

update_binary() {
  local n BIN_UPDATED=0
  ensure_deps || return 1
  ensure_binary || return 1
  if (( BIN_UPDATED )); then
    systemctl is-active --quiet "$SERVER_UNIT" 2>/dev/null && systemctl restart "$SERVER_UNIT" && ok "Server restarted."
    for n in $(list_tunnel_numbers); do
      systemctl is-active --quiet "hysteria$n" 2>/dev/null && systemctl restart "hysteria$n" && ok "Tunnel #$n restarted."
    done
  fi
}

cleanup_legacy_iptables() {   # counters created by older versions of this script
  command -v iptables >/dev/null 2>&1 || return 0
  local rule chain
  iptables -t mangle -S OUTPUT 2>/dev/null | grep -E -- '-j HYST[0-9]+' | sed 's/^-A/-D/' | while read -r rule; do
    iptables -t mangle $rule 2>/dev/null
  done
  for chain in $(iptables -t mangle -S 2>/dev/null | awk '/^-N HYST/{print $2}'); do
    iptables -t mangle -F "$chain" 2>/dev/null; iptables -t mangle -X "$chain" 2>/dev/null
  done
}

uninstall_all() {
  local u e name
  warn "This removes ALL Hysteria services, configs, firewall rules opened by this script, and the binary."
  read -rp "Type YES to continue: " e
  [[ $e == YES ]] || { info "Cancelled."; return 0; }
  for u in "$UNIT_DIR"/hysteria*.service; do
    [[ -e $u ]] || continue
    name=$(basename "$u" .service)
    systemctl disable --now "$name" >/dev/null 2>&1
    rm -f "$u"
  done
  systemctl daemon-reload
  if [[ -f $FW_FILE ]]; then
    while read -r e; do [[ -n $e ]] && fw_close "${e%/*}" "${e#*/}"; done < <(cat "$FW_FILE")
  fi
  set_cron off
  cleanup_legacy_iptables
  rm -f "$SYSCTL_FILE"
  rm -rf "$CONF_DIR" /var/log/hysteria /var/log/hysteria*.log /var/log/hysteria*.err
  rm -f "$BIN"
  ok "Everything has been removed."
}

# ------------------------------- main menu -----------------------------------
main() {
  need_root
  trap 'echo; exit 130' INT
  print_art
  local c
  while :; do
    draw_menu "TAQ-BOSTAN - Hysteria 2 Tunnel  v$SCRIPT_VERSION" \
      "1 | Setup FOREIGN server  (Hysteria server)" \
      "2 | Setup IRAN server     (create tunnel)" \
      "3 | Manage Iran tunnels   (edit/restart/delete)" \
      "4 | Status and port monitor" \
      "5 | Speedtest             (run on Iran server)" \
      "6 | Update Hysteria binary" \
      "7 | View logs" \
      "8 | Uninstall everything" \
      "0 | Exit"
    read -rp "Select an option [0-8]: " c
    case "$c" in
      1) setup_foreign; pause ;;
      2) setup_iran; pause ;;
      3) manage_tunnels ;;
      4) show_status; pause ;;
      5) run_speedtest; pause ;;
      6) update_binary; pause ;;
      7) show_logs; pause ;;
      8) uninstall_all; pause ;;
      0) exit 0 ;;
      *) err "Invalid option." ;;
    esac
  done
}

[[ -n ${HY_SOURCED:-} ]] || main "$@"
