#!/usr/bin/env bash
# deploy.sh - Deploy Slipstream + Shadowsocks directly to a server (without Docker)
#
# This script provides the same deployment experience as the slipstream-docker install.sh
# but installs and runs the services natively using systemd for reliability.
#
# Usage:
#   Interactive:     sudo ./deploy.sh
#   Non-interactive: sudo DOMAIN=tunnel.example.com MODE=recursive ./deploy.sh
#
# Environment variables (same as slipstream-docker):
#   DOMAIN              - Required: Your DNS tunnel domain
#   MODE                - recursive (default) or authoritative
#   RESOLVER            - DNS resolver for recursive mode (default: 8.8.8.8)
#   SERVER_IP           - Required for authoritative mode
#   SS_PASSWORD         - Shadowsocks password (auto-generated if not set)
#   SS_METHOD           - Encryption method (default: chacha20-ietf-poly1305)
#   KEEP_ALIVE_INTERVAL - Keep-alive interval in seconds (default: 25)
#   NON_INTERACTIVE     - Set to 'true' to skip prompts
#   FORCE_RECONFIGURE   - Set to 'true' to ignore existing config
#   SKIP_DNS_CHECK      - Set to 'true' to skip DNS preflight check
#   EXPECTED_PUBLIC_IP  - Expected IP for DNS preflight (optional)

set -euo pipefail
IFS=$'\n\t'

# Version configuration
SHADOWSOCKS_VERSION="${SHADOWSOCKS_VERSION:-1.21.2}"

# Installation paths
INSTALL_DIR="/opt/slipstream"
CONFIG_DIR="/etc/slipstream"
DATA_DIR="/var/lib/slipstream"
LOG_DIR="/var/log/slipstream"
BIN_DIR="/usr/local/bin"

# Config file paths
CONFIG_FILE="$CONFIG_DIR/settings.env"
SS_CONFIG="$CONFIG_DIR/ss-config.json"
CLIENT_CONFIG_FILE="$CONFIG_DIR/client-config.txt"
CERT_PATH="$CONFIG_DIR/cert.pem"
KEY_PATH="$CONFIG_DIR/key.pem"
RESET_SEED_PATH="$CONFIG_DIR/reset-seed"

# Service defaults
SS_METHOD="${SS_METHOD:-chacha20-ietf-poly1305}"
SS_PORT="7749"
DNS_PORT="${DNS_PORT:-53}"
KEEP_ALIVE_INTERVAL="${KEEP_ALIVE_INTERVAL:-25}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------

log() { printf '\n[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf "${YELLOW}WARNING: %s${NC}\n" "$*" >&2; }
die() { printf "${RED}ERROR: %s${NC}\n" "$*" >&2; exit 1; }

print_info() { echo -e "${BLUE}$*${NC}"; }
print_success() { echo -e "${GREEN}$*${NC}"; }
print_warning() { echo -e "${YELLOW}$*${NC}"; }
print_error() { echo -e "${RED}$*${NC}"; }
print_bold() { echo -e "${BOLD}$*${NC}"; }

print_line() {
    local char="${1:-=}"
    local width="${2:-60}"
    printf '%*s\n' "$width" '' | tr ' ' "$char"
}

print_header() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}   Slipstream + Shadowsocks Deploy${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

# -----------------------------------------------------------------------------
# Prompt Functions (same interface as slipstream-docker)
# -----------------------------------------------------------------------------

tty_device_available() {
    [ -r /dev/tty ] && [ -w /dev/tty ]
}

has_tty() {
    [ -t 0 ] && [ -t 1 ]
}

setup_prompt_fd() {
    if [ -t 0 ]; then
        PROMPT_FD=0
    elif [ -r /dev/tty ]; then
        exec 3</dev/tty
        PROMPT_FD=3
    else
        PROMPT_FD=""
    fi
}

is_non_interactive() {
    [ "${NON_INTERACTIVE:-false}" = "true" ] || [ -z "${PROMPT_FD:-}" ]
}

prompt_yn() {
    local prompt="$1"
    local default="$2"
    local reply=""
    local suffix=""

    if [ "$default" = "Y" ] || [ "$default" = "y" ]; then
        suffix="[Y/n]"
    else
        suffix="[y/N]"
    fi

    while true; do
        read -r -u "$PROMPT_FD" -p "$prompt $suffix " reply || die "Input cancelled."
        reply="${reply:-$default}"
        case "$reply" in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
        esac
    done
}

prompt_input() {
    local prompt="$1"
    local default="${2:-}"
    local reply=""

    if [ -n "$default" ]; then
        read -r -u "$PROMPT_FD" -p "$prompt [$default]: " reply || die "Input cancelled."
        reply="${reply:-$default}"
    else
        read -r -u "$PROMPT_FD" -p "$prompt: " reply || die "Input cancelled."
    fi
    printf '%s' "$reply"
}

prompt_choice() {
    local prompt="$1"
    local var_name="$2"
    local result

    while true; do
        echo -n -e "${BOLD}$prompt${NC}: "
        read -r -u "$PROMPT_FD" result || die "Input cancelled."

        if [ "$result" = "1" ] || [ "$result" = "2" ]; then
            eval "$var_name=\"$result\""
            return 0
        else
            print_error "Please enter 1 or 2"
        fi
    done
}

# -----------------------------------------------------------------------------
# Validation Functions
# -----------------------------------------------------------------------------

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "This script must be run as root. Example: sudo ./deploy.sh"
    fi
}

validate_domain() {
    local domain="$1"
    if [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]]; then
        return 0
    fi
    return 1
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    fi
    return 1
}

is_valid_port() {
    local port="$1"
    case "$port" in
        ''|*[!0-9]*) return 1 ;;
    esac
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
}

is_udp_port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -lunH "sport = :$port" 2>/dev/null | grep -q .
        return $?
    fi
    if command -v netstat >/dev/null 2>&1; then
        netstat -lun 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$port$"
        return $?
    fi
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -i UDP:"$port" >/dev/null 2>&1
        return $?
    fi
    return 2
}

# -----------------------------------------------------------------------------
# OS Detection & Package Management
# -----------------------------------------------------------------------------

detect_os() {
    OS_ID=""
    OS_LIKE=""
    OS_VERSION_CODENAME=""
    UBUNTU_CODENAME=""
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-}"
        OS_LIKE="${ID_LIKE:-}"
        OS_VERSION_CODENAME="${VERSION_CODENAME:-}"
        UBUNTU_CODENAME="${UBUNTU_CODENAME:-}"
    fi

    OS_FAMILY="unknown"
    case "$OS_ID" in
        ubuntu|debian|raspbian|linuxmint) OS_FAMILY="debian" ;;
        fedora) OS_FAMILY="fedora" ;;
        rhel|centos|rocky|almalinux|ol) OS_FAMILY="rhel" ;;
        arch|manjaro|endeavouros) OS_FAMILY="arch" ;;
        opensuse*|sles|sled) OS_FAMILY="suse" ;;
        alpine) OS_FAMILY="alpine" ;;
    esac

    if [ "$OS_FAMILY" = "unknown" ]; then
        if echo "$OS_LIKE" | grep -qi "debian"; then
            OS_FAMILY="debian"
        elif echo "$OS_LIKE" | grep -Eqi "rhel|fedora|centos"; then
            OS_FAMILY="rhel"
        elif echo "$OS_LIKE" | grep -qi "arch"; then
            OS_FAMILY="arch"
        fi
    fi

    if [ "$OS_FAMILY" = "unknown" ]; then
        die "Unsupported Linux distribution. Supported: Debian/Ubuntu, RHEL/CentOS/Fedora, Arch, openSUSE, Alpine"
    fi

    log "Detected OS family: $OS_FAMILY"
}

install_build_deps() {
    log "Installing build dependencies..."

    case "$OS_FAMILY" in
        debian)
            apt-get update
            apt-get install -y --no-install-recommends \
                build-essential \
                cmake \
                pkg-config \
                libssl-dev \
                git \
                clang \
                curl \
                ca-certificates \
                jq \
                openssl \
                xz-utils
            ;;
        fedora)
            dnf -y install \
                gcc gcc-c++ make \
                cmake \
                pkg-config \
                openssl-devel \
                git \
                clang \
                curl \
                ca-certificates \
                jq \
                openssl \
                xz
            ;;
        rhel)
            if command -v dnf >/dev/null 2>&1; then
                dnf -y install epel-release || true
                dnf -y install \
                    gcc gcc-c++ make \
                    cmake \
                    pkg-config \
                    openssl-devel \
                    git \
                    clang \
                    curl \
                    ca-certificates \
                    jq \
                    openssl \
                    xz
            else
                yum -y install epel-release || true
                yum -y install \
                    gcc gcc-c++ make \
                    cmake \
                    pkgconfig \
                    openssl-devel \
                    git \
                    clang \
                    curl \
                    ca-certificates \
                    jq \
                    openssl \
                    xz
            fi
            ;;
        arch)
            pacman -Sy --noconfirm \
                base-devel \
                cmake \
                pkg-config \
                openssl \
                git \
                clang \
                curl \
                ca-certificates \
                jq \
                xz
            ;;
        suse)
            zypper refresh
            zypper install -y \
                gcc gcc-c++ make \
                cmake \
                pkg-config \
                libopenssl-devel \
                git \
                clang \
                curl \
                ca-certificates \
                jq \
                openssl \
                xz
            ;;
        alpine)
            apk add --no-cache \
                build-base \
                cmake \
                pkgconfig \
                openssl-dev \
                git \
                clang \
                curl \
                ca-certificates \
                jq \
                openssl \
                xz \
                bash
            ;;
    esac
}

install_rust() {
    if command -v rustc >/dev/null 2>&1 && command -v cargo >/dev/null 2>&1; then
        local rust_version
        rust_version=$(rustc --version | cut -d' ' -f2)
        log "Rust $rust_version already installed"
        return 0
    fi

    log "Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

    # Source cargo environment
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env" 2>/dev/null || true
    export PATH="$HOME/.cargo/bin:$PATH"

    if ! command -v cargo >/dev/null 2>&1; then
        die "Failed to install Rust. Please install manually: https://rustup.rs"
    fi

    log "Rust installed: $(rustc --version)"
}

# -----------------------------------------------------------------------------
# Architecture Detection & Shadowsocks Binary Download
# -----------------------------------------------------------------------------

detect_ss_arch() {
    local arch
    arch="$(uname -m)"

    case "$arch" in
        x86_64|amd64)
            echo "x86_64-unknown-linux-musl"
            ;;
        aarch64|arm64)
            echo "aarch64-unknown-linux-musl"
            ;;
        i686|i386)
            echo "i686-unknown-linux-musl"
            ;;
        armv7l|armv7|armhf)
            echo "armv7-unknown-linux-musleabihf"
            ;;
        armv6l|arm)
            echo "arm-unknown-linux-musleabihf"
            ;;
        *)
            die "Unsupported architecture: $arch"
            ;;
    esac
}

download_shadowsocks() {
    local ss_arch
    ss_arch=$(detect_ss_arch)
    local version="${SHADOWSOCKS_VERSION#v}"
    local file="shadowsocks-v${version}.${ss_arch}.tar.xz"
    local url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${version}/${file}"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    log "Downloading Shadowsocks v${version} for ${ss_arch}..."

    # Download binary and checksum
    curl -fsSL "$url" -o "$tmp_dir/$file" || die "Failed to download Shadowsocks"
    curl -fsSL "${url}.sha256" -o "$tmp_dir/${file}.sha256" || die "Failed to download checksum"

    # Verify checksum
    log "Verifying checksum..."
    (cd "$tmp_dir" && sha256sum -c "${file}.sha256") || die "Checksum verification failed"

    # Extract
    log "Extracting..."
    tar -xJf "$tmp_dir/$file" -C "$tmp_dir"

    # Find and install ssserver
    local ss_bin
    ss_bin=$(find "$tmp_dir" -type f -name "ssserver" -perm -111 | head -n 1)
    if [ -z "$ss_bin" ]; then
        die "ssserver binary not found in archive"
    fi

    install -m 755 "$ss_bin" "$BIN_DIR/ssserver"
    rm -rf "$tmp_dir"

    log "Shadowsocks installed to $BIN_DIR/ssserver"
}

# -----------------------------------------------------------------------------
# Slipstream Build
# -----------------------------------------------------------------------------

detect_repo_dir() {
    local script_dir=""

    if [ -n "${BASH_SOURCE[0]-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    fi

    # Check if we're in the slipstream-rust repo
    if [ -n "$script_dir" ] && [ -f "$script_dir/Cargo.toml" ]; then
        if grep -q 'slipstream-server' "$script_dir/Cargo.toml" 2>/dev/null; then
            REPO_DIR="$script_dir"
            return 0
        fi
    fi

    # Check current directory
    if [ -f "Cargo.toml" ] && grep -q 'slipstream-server' "Cargo.toml" 2>/dev/null; then
        REPO_DIR="$(pwd)"
        return 0
    fi

    die "This script must be run from the slipstream-rust repository root, or the repo must be specified."
}

ensure_submodules() {
    if [ ! -f "$REPO_DIR/vendor/picoquic/CMakeLists.txt" ]; then
        log "Initializing git submodules..."
        git -C "$REPO_DIR" submodule update --init --recursive
    fi
}

build_slipstream() {
    log "Building slipstream-server (this may take a while on first build)..."

    cd "$REPO_DIR"

    # Ensure cargo is available
    export PATH="$HOME/.cargo/bin:$PATH"
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env" 2>/dev/null || true

    # Build with release profile
    cargo build -p slipstream-server --release

    local binary="$REPO_DIR/target/release/slipstream-server"
    if [ ! -f "$binary" ]; then
        die "Build failed: slipstream-server binary not found"
    fi

    install -m 755 "$binary" "$BIN_DIR/slipstream-server"
    log "Slipstream installed to $BIN_DIR/slipstream-server"
}

# -----------------------------------------------------------------------------
# Configuration & TLS
# -----------------------------------------------------------------------------

generate_password() {
    openssl rand -base64 32 | tr -d '/+=' | head -c 32
}

ensure_cert_key() {
    if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
        print_info "Generating self-signed TLS certificate..."
        mkdir -p "$CONFIG_DIR"
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$KEY_PATH" \
            -out "$CERT_PATH" \
            -days 3650 \
            -subj "/CN=slipstream" >/dev/null 2>&1
        chmod 600 "$KEY_PATH"
    fi
}

ensure_reset_seed() {
    if [ ! -f "$RESET_SEED_PATH" ]; then
        print_info "Generating reset seed..."
        mkdir -p "$CONFIG_DIR"
        openssl rand -hex 16 > "$RESET_SEED_PATH"
        chmod 600 "$RESET_SEED_PATH"
    fi
}

get_cert_sha256() {
    local output
    output=$("$BIN_DIR/slipstream-server" \
        --domain "$DOMAIN" \
        --cert "$CERT_PATH" \
        --key "$KEY_PATH" \
        --print-ss-plugin 2>&1 || true)
    CERT_SHA256=$(echo "$output" | grep -oP 'cert-sha256=\K[a-fA-F0-9]+' | head -1)

    if [ -z "$CERT_SHA256" ]; then
        print_error "Failed to get cert-sha256 from slipstream-server"
        print_error "Output: $output"
        exit 1
    fi
}

create_ss_config() {
    mkdir -p "$CONFIG_DIR"
    cat > "$SS_CONFIG" << EOF
{
    "server": "127.0.0.1",
    "server_port": $SS_PORT,
    "password": "$SS_PASSWORD",
    "method": "$SS_METHOD"
}
EOF
    chmod 600 "$SS_CONFIG"
}

save_config() {
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" << EOF
# Slipstream Configuration
# Generated on $(date)

DOMAIN="$DOMAIN"
MODE="$MODE"
RESOLVER="${RESOLVER:-}"
SERVER_IP="${SERVER_IP:-}"
SS_PASSWORD="$SS_PASSWORD"
SS_METHOD="$SS_METHOD"
KEEP_ALIVE_INTERVAL="$KEEP_ALIVE_INTERVAL"
CERT_SHA256="$CERT_SHA256"
CERT_PATH="$CERT_PATH"
KEY_PATH="$KEY_PATH"
RESET_SEED_PATH="$RESET_SEED_PATH"
EXPECTED_PUBLIC_IP="${EXPECTED_PUBLIC_IP:-}"
DNS_PORT="$DNS_PORT"
SS_PORT="$SS_PORT"
EOF
    chmod 600 "$CONFIG_FILE"
}

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        # shellcheck disable=SC1090
        source "$CONFIG_FILE"
        return 0
    fi
    return 1
}

config_exists() {
    [ -f "$CONFIG_FILE" ]
}

build_plugin_opts() {
    local opts="domain=$DOMAIN;cert-sha256=$CERT_SHA256"

    if [ "$MODE" = "recursive" ]; then
        opts="${opts}"
    else
        opts="${opts};authoritative=${SERVER_IP}:$DNS_PORT"
    fi
    opts="${opts};keep-alive-interval=${KEEP_ALIVE_INTERVAL}"

    echo "$opts"
}

get_ss_server_host() {
    if [ "$MODE" = "recursive" ]; then
        echo "${RESOLVER:-$DOMAIN}"
    else
        echo "${SERVER_IP:-$DOMAIN}"
    fi
}

generate_ss_url() {
    local method="$1"
    local password="$2"
    local server="$3"
    local port="$4"
    local plugin_opts="$5"
    local name="$6"

    # Base64 encode method:password
    local userinfo
    userinfo=$(echo -n "$method:$password" | base64 -w 0)

    # URL encode plugin opts
    local encoded_opts
    encoded_opts=$(echo -n "$plugin_opts" | jq -sRr @uri)

    # URL encode name
    local encoded_name
    encoded_name=$(echo -n "$name" | jq -sRr @uri)

    echo "ss://${userinfo}@${server}:${port}/?plugin=slipstream%3B${encoded_opts}#${encoded_name}"
}

save_client_config() {
    local ss_url="$1"
    local plugin_opts="$2"
    local mode_display

    if [ "$MODE" = "recursive" ]; then
        mode_display="Recursive (via ${RESOLVER:-8.8.8.8})"
    else
        mode_display="Authoritative ($SERVER_IP)"
    fi

    mkdir -p "$CONFIG_DIR"
    cat > "$CLIENT_CONFIG_FILE" << EOF
=== Slipstream + Shadowsocks Client Configuration ===
Generated on: $(date)

Domain:      $DOMAIN
Password:    $SS_PASSWORD
Method:      $SS_METHOD
Keep Alive:  $KEEP_ALIVE_INTERVAL
Mode:        $mode_display
Cert SHA256: $CERT_SHA256

=== ss:// URL (copy to Android Shadowsocks app) ===

$ss_url

=== Plugin Options (for manual setup) ===

$plugin_opts
EOF
    chmod 600 "$CLIENT_CONFIG_FILE"
}

print_client_config() {
    local ss_url="$1"
    local plugin_opts="$2"

    local mode_display
    if [ "$MODE" = "recursive" ]; then
        mode_display="Recursive (via ${RESOLVER:-8.8.8.8})"
    else
        mode_display="Authoritative ($SERVER_IP)"
    fi

    echo ""
    echo -e "${CYAN}+==============================================================+${NC}"
    echo -e "${CYAN}|${NC}                  ${BOLD}CLIENT CONFIGURATION${NC}                       ${CYAN}|${NC}"
    echo -e "${CYAN}+==============================================================+${NC}"
    echo -e "${CYAN}|${NC}                                                              ${CYAN}|${NC}"
    printf "${CYAN}|${NC}  Domain:      ${GREEN}%-44s${NC} ${CYAN}|${NC}\n" "$DOMAIN"
    printf "${CYAN}|${NC}  Password:    ${GREEN}%-44s${NC} ${CYAN}|${NC}\n" "$SS_PASSWORD"
    printf "${CYAN}|${NC}  Method:      ${GREEN}%-44s${NC} ${CYAN}|${NC}\n" "$SS_METHOD"
    printf "${CYAN}|${NC}  Mode:        ${GREEN}%-44s${NC} ${CYAN}|${NC}\n" "$mode_display"
    printf "${CYAN}|${NC}  Cert SHA256: ${GREEN}%-44s${NC} ${CYAN}|${NC}\n" "${CERT_SHA256:0:44}"
    if [ ${#CERT_SHA256} -gt 44 ]; then
        printf "${CYAN}|${NC}               ${GREEN}%-44s${NC} ${CYAN}|${NC}\n" "${CERT_SHA256:44}"
    fi
    echo -e "${CYAN}|${NC}                                                              ${CYAN}|${NC}"
    echo -e "${CYAN}+--------------------------------------------------------------+${NC}"
    echo -e "${CYAN}|${NC}  ${BOLD}COPY THIS ss:// URL TO YOUR ANDROID SHADOWSOCKS APP:${NC}        ${CYAN}|${NC}"
    echo -e "${CYAN}+--------------------------------------------------------------+${NC}"
    echo -e "${CYAN}|${NC}                                                              ${CYAN}|${NC}"
    echo -e "${YELLOW}$ss_url${NC}"
    echo -e "${CYAN}|${NC}                                                              ${CYAN}|${NC}"
    echo -e "${CYAN}+--------------------------------------------------------------+${NC}"
    echo -e "${CYAN}|${NC}  ${BOLD}Plugin Options (for manual setup):${NC}                         ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  $plugin_opts"
    echo -e "${CYAN}|${NC}                                                              ${CYAN}|${NC}"
    printf "${CYAN}|${NC}  Config saved to: ${BLUE}%-40s${NC} ${CYAN}|${NC}\n" "$CLIENT_CONFIG_FILE"
    echo -e "${CYAN}+==============================================================+${NC}"
    echo ""
}

# -----------------------------------------------------------------------------
# DNS Port Handling
# -----------------------------------------------------------------------------

disable_systemd_resolved() {
    log "Disabling systemd-resolved to free port 53..."
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true

    # Configure static DNS since systemd-resolved is disabled
    if [ -L /etc/resolv.conf ]; then
        rm -f /etc/resolv.conf
    fi
    cat > /etc/resolv.conf << EOF
# Generated by slipstream deploy script
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
    log "Configured /etc/resolv.conf with public DNS servers"
}

choose_dns_port() {
    DNS_PORT="${DNS_PORT:-53}"
    if ! is_valid_port "$DNS_PORT"; then
        warn "Invalid DNS_PORT='$DNS_PORT'. Falling back to 53."
        DNS_PORT="53"
    fi

    if [ "$DNS_PORT" != "53" ]; then
        return
    fi

    local systemd_resolved_active=false
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
            systemd_resolved_active=true
        fi
    fi

    if is_udp_port_in_use "53"; then
        warn "UDP port 53 appears to be in use."

        if is_non_interactive; then
            if [ "$systemd_resolved_active" = true ]; then
                log "Disabling systemd-resolved automatically (non-interactive mode)..."
                disable_systemd_resolved
                sleep 1
            else
                warn "Port 53 is in use by another service. Continuing anyway..."
            fi
        else
            if [ "$systemd_resolved_active" = true ]; then
                warn "systemd-resolved is using port 53."
                printf '\n'
                printf 'Slipstream requires port 53 for recursive DNS mode.\n'
                printf 'Options:\n'
                printf '  1) Disable systemd-resolved (recommended for servers)\n'
                printf '  2) Use alternate port (breaks recursive DNS mode)\n'
                printf '\n'

                if prompt_yn "Disable systemd-resolved to free port 53?" "Y"; then
                    disable_systemd_resolved
                    sleep 1
                    if is_udp_port_in_use "53"; then
                        warn "Port 53 still in use after disabling systemd-resolved."
                        warn "Another service may be using the port."
                    else
                        log "Port 53 is now available"
                    fi
                else
                    if prompt_yn "Use alternate port instead? (breaks recursive DNS)" "N"; then
                        while true; do
                            local port
                            port="$(prompt_input "Enter alternate UDP port" "5353")"
                            if is_valid_port "$port"; then
                                DNS_PORT="$port"
                                break
                            fi
                            warn "Invalid port. Please enter a number between 1 and 65535."
                        done
                    else
                        warn "Continuing with port 53 (this may fail if the port is busy)."
                    fi
                fi
            else
                warn "Another service is using port 53."
                if prompt_yn "Use an alternate UDP port instead?" "Y"; then
                    while true; do
                        local port
                        port="$(prompt_input "Enter alternate UDP port" "5353")"
                        if is_valid_port "$port"; then
                            DNS_PORT="$port"
                            break
                        fi
                        warn "Invalid port. Please enter a number between 1 and 65535."
                    done
                else
                    warn "Continuing with port 53 (this may fail if the port is busy)."
                fi
            fi
        fi
    elif [ "$?" -eq 2 ]; then
        warn "Unable to check whether UDP port 53 is in use. Continuing."
    fi
}

# -----------------------------------------------------------------------------
# Interactive Wizard
# -----------------------------------------------------------------------------

run_wizard() {
    print_header

    # Step 1: Domain Configuration
    print_bold "Step 1: Domain Configuration"
    echo ""
    while true; do
        DOMAIN=$(prompt_input "Enter your DNS tunnel domain (e.g., tunnel.example.com)" "")
        if [ -z "$DOMAIN" ]; then
            print_error "Domain is required"
        elif validate_domain "$DOMAIN"; then
            break
        else
            print_error "Invalid domain format. Please enter a valid domain."
        fi
    done
    echo ""

    # Step 2: Connection Mode
    print_bold "Step 2: Connection Mode"
    echo ""
    echo "How will clients connect to this server?"
    echo ""
    echo -e "${GREEN}1) Recursive DNS (Recommended)${NC}"
    echo "   - Clients query public DNS (e.g., 8.8.8.8) which resolves your domain"
    echo "   - Works behind most firewalls, more stealthy"
    echo "   - Requires domain DNS records pointing to this server"
    echo ""
    echo -e "${GREEN}2) Authoritative/Direct${NC}"
    echo "   - Clients connect directly to your server IP"
    echo "   - Higher performance with pacing-based polling"
    echo "   - Best for servers you fully control"
    echo "   - Requires clients can reach port 53 directly"
    echo ""

    local MODE_CHOICE
    prompt_choice "Choose [1/2]" MODE_CHOICE

    if [ "$MODE_CHOICE" = "1" ]; then
        MODE="recursive"
        echo ""
        print_bold "Step 2a: DNS Resolver"
        echo "Enter the public DNS resolver clients should use:"
        echo "  Examples: 8.8.8.8, 1.1.1.1, 9.9.9.9"
        echo "  (Note: Android plugin currently supports only one resolver)"
        echo ""
        RESOLVER=$(prompt_input "Resolver" "8.8.8.8")
    else
        MODE="authoritative"
        echo ""
        print_warning "NOTE: Authoritative mode uses BBR congestion control with pacing-based"
        print_warning "polling. This works best when you control both endpoints and can handle"
        print_warning "high query rates. Only use this if this is your own server."
        echo ""
        print_bold "Step 2b: Server IP"
        while true; do
            SERVER_IP=$(prompt_input "Enter this server's public IP address" "")
            if [ -z "$SERVER_IP" ]; then
                print_error "Server IP is required for authoritative mode"
            elif validate_ip "$SERVER_IP"; then
                break
            else
                print_error "Invalid IP address format"
            fi
        done
    fi
    echo ""

    # Step 3: Shadowsocks Password
    print_bold "Step 3: Shadowsocks Password"
    echo ""
    echo "Shadowsocks password configuration:"
    echo ""
    echo -e "${GREEN}1) Generate secure random password (Recommended)${NC}"
    echo -e "${GREEN}2) Enter custom password${NC}"
    echo ""

    local PASS_CHOICE
    prompt_choice "Choose [1/2]" PASS_CHOICE

    if [ "$PASS_CHOICE" = "1" ]; then
        SS_PASSWORD=$(generate_password)
        echo ""
        print_success "Generated password: $SS_PASSWORD"
    else
        echo ""
        while true; do
            SS_PASSWORD=$(prompt_input "Enter password (min 8 characters)" "")
            if [ ${#SS_PASSWORD} -ge 8 ]; then
                break
            else
                print_error "Password must be at least 8 characters"
            fi
        done
    fi
    echo ""

    # Step 4: Confirmation
    print_bold "=== Configuration Summary ==="
    echo ""
    echo -e "Domain:     ${GREEN}$DOMAIN${NC}"
    if [ "$MODE" = "recursive" ]; then
        echo -e "Mode:       ${GREEN}Recursive (via $RESOLVER)${NC}"
    else
        echo -e "Mode:       ${GREEN}Authoritative ($SERVER_IP)${NC}"
    fi
    echo -e "SS Method:  ${GREEN}$SS_METHOD${NC}"
    echo -e "Password:   ${GREEN}$SS_PASSWORD${NC}"
    echo ""
    echo -n "Press Enter to continue setup, or Ctrl+C to abort..."
    read -r
}

run_non_interactive() {
    print_info "Running in non-interactive mode..."

    # Validate required variables
    if [ -z "${DOMAIN:-}" ]; then
        print_error "DOMAIN environment variable is required in non-interactive mode"
        exit 1
    fi

    # Set defaults
    MODE="${MODE:-recursive}"
    RESOLVER="${RESOLVER:-8.8.8.8}"
    SS_PASSWORD="${SS_PASSWORD:-$(generate_password)}"
    KEEP_ALIVE_INTERVAL="${KEEP_ALIVE_INTERVAL:-25}"

    # Validate mode-specific requirements
    if [ "$MODE" = "authoritative" ] && [ -z "${SERVER_IP:-}" ]; then
        print_error "SERVER_IP is required for authoritative mode"
        exit 1
    fi

    print_info "Configuration:"
    print_info "  Domain: $DOMAIN"
    print_info "  Mode: $MODE"
    if [ "$MODE" = "recursive" ]; then
        print_info "  Resolver: $RESOLVER"
    else
        print_info "  Server IP: $SERVER_IP"
    fi
}

# -----------------------------------------------------------------------------
# DNS Preflight Check
# -----------------------------------------------------------------------------

maybe_dns_check() {
    if [ "$MODE" != "recursive" ]; then
        return 0
    fi
    if [ "${SKIP_DNS_CHECK:-false}" = "true" ]; then
        print_info "Skipping DNS preflight check (SKIP_DNS_CHECK=true)"
        return 0
    fi
    if ! command -v getent >/dev/null 2>&1; then
        print_warning "Skipping DNS preflight check (getent not available)"
        return 0
    fi
    local resolved
    resolved=$(getent ahosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
    if [ -z "$resolved" ]; then
        print_warning "DNS preflight: $DOMAIN does not resolve yet"
        return 0
    fi
    if [ -n "${EXPECTED_PUBLIC_IP:-}" ]; then
        if echo "$resolved" | grep -q "$EXPECTED_PUBLIC_IP"; then
            print_success "DNS preflight: $DOMAIN resolves to expected IP $EXPECTED_PUBLIC_IP"
        else
            print_warning "DNS preflight: $DOMAIN resolves to $resolved (expected $EXPECTED_PUBLIC_IP)"
        fi
    else
        print_info "DNS preflight: $DOMAIN resolves to $resolved"
    fi
}

# -----------------------------------------------------------------------------
# Systemd Service Management
# -----------------------------------------------------------------------------

create_systemd_services() {
    log "Creating systemd services for reliability..."

    mkdir -p "$LOG_DIR"

    # Create ssserver service
    cat > /etc/systemd/system/ssserver.service << EOF
[Unit]
Description=Shadowsocks Server
Documentation=https://github.com/shadowsocks/shadowsocks-rust
After=network.target
Wants=network.target

[Service]
Type=simple
EnvironmentFile=$CONFIG_FILE
ExecStart=$BIN_DIR/ssserver -c $SS_CONFIG
Restart=always
RestartSec=5
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$CONFIG_DIR $LOG_DIR

[Install]
WantedBy=multi-user.target
EOF

    # Create slipstream-server service
    cat > /etc/systemd/system/slipstream-server.service << EOF
[Unit]
Description=Slipstream DNS Tunnel Server
Documentation=https://github.com/dalisyron/slipstream-rust
After=network.target ssserver.service
Wants=network.target
Requires=ssserver.service

[Service]
Type=simple
EnvironmentFile=$CONFIG_FILE
ExecStart=$BIN_DIR/slipstream-server \\
    --target-address 127.0.0.1:\${SS_PORT} \\
    --domain \${DOMAIN} \\
    --cert \${CERT_PATH} \\
    --key \${KEY_PATH} \\
    --dns-listen-port \${DNS_PORT} \\
    --reset-seed \${RESET_SEED_PATH}
Restart=always
RestartSec=5
LimitNOFILE=65536

# Allow binding to privileged port 53
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$CONFIG_DIR $LOG_DIR

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload

    log "Systemd services created"
}

start_services() {
    log "Starting services..."

    # Enable and start ssserver
    systemctl enable ssserver.service
    systemctl start ssserver.service
    sleep 1

    if ! systemctl is-active --quiet ssserver.service; then
        print_error "Failed to start ssserver"
        journalctl -u ssserver.service --no-pager -n 20
        exit 1
    fi
    print_success "Shadowsocks server started"

    # Enable and start slipstream-server
    systemctl enable slipstream-server.service
    systemctl start slipstream-server.service
    sleep 1

    if ! systemctl is-active --quiet slipstream-server.service; then
        print_error "Failed to start slipstream-server"
        journalctl -u slipstream-server.service --no-pager -n 20
        exit 1
    fi
    print_success "Slipstream server started"
}

stop_services() {
    log "Stopping existing services..."
    systemctl stop slipstream-server.service 2>/dev/null || true
    systemctl stop ssserver.service 2>/dev/null || true
}

print_service_info() {
    echo ""
    print_bold "=== Service Management ==="
    echo ""
    echo "The following systemd services have been created:"
    echo "  - ssserver.service (Shadowsocks)"
    echo "  - slipstream-server.service (DNS Tunnel)"
    echo ""
    echo "Both services are configured to:"
    echo "  - Start automatically on boot"
    echo "  - Restart automatically on failure"
    echo ""
    echo "Useful commands:"
    echo "  View status:      systemctl status slipstream-server ssserver"
    echo "  View logs:        journalctl -u slipstream-server -u ssserver -f"
    echo "  Stop services:    systemctl stop slipstream-server ssserver"
    echo "  Start services:   systemctl start ssserver slipstream-server"
    echo "  Restart services: systemctl restart ssserver slipstream-server"
    echo ""
    echo "  View config:      cat $CLIENT_CONFIG_FILE"
    echo ""
}

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${CYAN}Slipstream + Shadowsocks Direct Deployment${NC}"
    echo ""

    require_root
    setup_prompt_fd
    detect_os

    # Find repo directory
    detect_repo_dir
    log "Using repository: $REPO_DIR"

    # Install dependencies
    if ! command -v cargo >/dev/null 2>&1 || ! command -v cmake >/dev/null 2>&1; then
        if is_non_interactive; then
            log "Installing dependencies (non-interactive mode)..."
            install_build_deps
            install_rust
        else
            if prompt_yn "Build dependencies (Rust, cmake, etc.) are required. Install them now?" "Y"; then
                install_build_deps
                install_rust
            else
                die "Build dependencies are required to continue."
            fi
        fi
    fi

    # Ensure cargo is in PATH
    export PATH="$HOME/.cargo/bin:$PATH"
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env" 2>/dev/null || true

    # Handle existing configuration
    if config_exists; then
        print_info "Found existing configuration at $CONFIG_FILE"

        if [ "${FORCE_RECONFIGURE:-false}" = "true" ]; then
            print_warning "FORCE_RECONFIGURE=true; ignoring existing configuration"
        elif is_non_interactive; then
            print_info "Using existing configuration..."
            load_config
        else
            if prompt_yn "Use existing configuration?" "Y"; then
                load_config
                print_success "Loaded existing configuration"
            fi
        fi
    fi

    # Run configuration if needed
    if ! config_exists || [ "${FORCE_RECONFIGURE:-false}" = "true" ]; then
        if is_non_interactive; then
            run_non_interactive
        else
            run_wizard
        fi
    fi

    # Handle DNS port
    choose_dns_port

    # DNS preflight check
    maybe_dns_check

    # Build/install binaries
    if [ ! -f "$BIN_DIR/slipstream-server" ]; then
        ensure_submodules
        build_slipstream
    else
        if ! is_non_interactive; then
            if prompt_yn "slipstream-server already installed. Rebuild?" "N"; then
                ensure_submodules
                build_slipstream
            fi
        fi
    fi

    if [ ! -f "$BIN_DIR/ssserver" ]; then
        download_shadowsocks
    else
        if ! is_non_interactive; then
            if prompt_yn "ssserver already installed. Re-download?" "N"; then
                download_shadowsocks
            fi
        fi
    fi

    # Setup configuration
    echo ""
    print_info "Setting up configuration..."

    mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

    ensure_cert_key
    get_cert_sha256
    print_success "Cert SHA256: $CERT_SHA256"

    ensure_reset_seed
    save_config
    create_ss_config

    # Build plugin options and generate ss:// URL
    PLUGIN_OPTS=$(build_plugin_opts)
    SS_SERVER_HOST=$(get_ss_server_host)
    SS_URL=$(generate_ss_url "$SS_METHOD" "$SS_PASSWORD" "$SS_SERVER_HOST" "$DNS_PORT" "$PLUGIN_OPTS" "Slipstream-$DOMAIN")

    # Save and display client configuration
    save_client_config "$SS_URL" "$PLUGIN_OPTS"
    print_client_config "$SS_URL" "$PLUGIN_OPTS"

    # Stop any existing services
    stop_services

    # Create and start systemd services
    create_systemd_services
    start_services

    # Print service management info
    print_service_info

    print_success "Deployment complete! The tunnel is now running."
    echo ""
}

main "$@"
