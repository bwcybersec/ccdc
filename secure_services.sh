#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Baseline Linux Hardening for: HTTP + FTP + DNS + MySQL/MariaDB
# - Supports: Debian/Ubuntu (apt), RHEL/Rocky/Alma/Fedora (dnf/yum)
# - Services: Apache (apache2/httpd) OR Nginx, vsftpd, bind9/named, mysql/mariadb
#
# Usage:
#   sudo bash secure_services.sh
# Optional:
#   DRY_RUN=1 sudo bash secure_services.sh
#   MYSQL_ALLOW_CIDR="10.0.0.0/8" sudo bash secure_services.sh
###############################################################################

# ---------- Operator toggles (safe defaults) ----------
: "${DRY_RUN:=0}"

# Firewall openings
: "${ALLOW_SSH:=1}"
: "${ALLOW_HTTP:=1}"      # 80/tcp
: "${ALLOW_HTTPS:=1}"     # 443/tcp
: "${ALLOW_FTP:=1}"       # 21/tcp (+ passive range)
: "${ALLOW_DNS:=1}"       # 53/tcp+udp
: "${ALLOW_MYSQL:=0}"     # 3306/tcp exposed? default NO

# If exposing MySQL, restrict to this CIDR (or "0.0.0.0/0" if you insist)
: "${MYSQL_ALLOW_CIDR:=127.0.0.1/32}"

# FTP passive port range (must match firewall + vsftpd config)
: "${FTP_PASV_MIN:=30000}"
: "${FTP_PASV_MAX:=31000}"

# FTP write access (uploads). Default off.
: "${FTP_ALLOW_WRITE:=0}"

# DNS role: "authoritative" (recursion off) or "resolver" (recursion on but restricted)
: "${DNS_ROLE:=authoritative}"
: "${DNS_RECURSION_ALLOW_CIDR:=127.0.0.1/32}"  # only relevant if DNS_ROLE=resolver

# SSH hardening (keep conservative to avoid lockouts)
: "${SSH_DISABLE_ROOT_LOGIN:=1}"
: "${SSH_PASSWORD_AUTH:=1}"  # set 0 to disable password auth (key-only) - can lock you out!

# ---------- Helpers ----------
log() { echo -e "[+] $*"; }
warn() { echo -e "[!] $*" >&2; }
die() { echo -e "[x] $*" >&2; exit 1; }

run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[DRY_RUN] $*"
  else
    eval "$@"
  fi
}

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root (use sudo)."
}

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  else
    die "No supported package manager found (apt/dnf/yum)."
  fi
}

pkg_install() {
  local mgr="$1"; shift
  local pkgs=("$@")

  case "$mgr" in
    apt)
      run "DEBIAN_FRONTEND=noninteractive apt-get update -y"
      run "DEBIAN_FRONTEND=noninteractive apt-get install -y ${pkgs[*]}"
      ;;
    dnf)
      run "dnf -y makecache"
      run "dnf -y install ${pkgs[*]}"
      ;;
    yum)
      run "yum -y makecache"
      run "yum -y install ${pkgs[*]}"
      ;;
  esac
}

enable_service() {
  local svc="$1"
  if systemctl list-unit-files | grep -qE "^${svc}\.service"; then
    run "systemctl enable --now ${svc} || true"
  fi
}

restart_service_if_exists() {
  local svc="$1"
  if systemctl list-unit-files | grep -qE "^${svc}\.service"; then
    run "systemctl restart ${svc} || true"
  fi
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  run "cp -a '$f' '${f}.bak.${ts}'"
}

file_has_line() {
  local f="$1" line="$2"
  [[ -f "$f" ]] && grep -qF -- "$line" "$f"
}

append_line_if_missing() {
  local f="$1" line="$2"
  if ! file_has_line "$f" "$line"; then
    run "printf '%s\n' '$line' >> '$f'"
  fi
}

set_kv_conf() {
