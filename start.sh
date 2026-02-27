#!/usr/bin/env bash
set -euo pipefail

REPO="lieyanc/warp-proxies"
BINARY="warp-proxies"
DATA_DIR="./data"
SETTINGS_FILE="${DATA_DIR}/settings.json"
LOG_FILE="./warp-proxies.log"

# ── Colors ──────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Detect architecture ────────────────────────────────
detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) error "Unsupported architecture: $arch" ;;
    esac
}

# ── Read JSON field (jq with grep fallback) ────────────
json_field() {
    local file="$1" key="$2"
    if command -v jq &>/dev/null; then
        jq -r ".$key // empty" "$file" 2>/dev/null
    else
        grep -o "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$file" 2>/dev/null \
            | head -1 | sed 's/.*:.*"\(.*\)"/\1/'
    fi
}

# ── Parse port from web_addr ───────────────────────────
parse_port() {
    local addr="$1"
    echo "$addr" | grep -oE '[0-9]+$'
}

# ── Determine update channel ──────────────────────────
get_channel() {
    if [[ -f "$SETTINGS_FILE" ]]; then
        local ch
        ch=$(json_field "$SETTINGS_FILE" "update_channel")
        if [[ -n "$ch" ]]; then
            info "Update channel: ${ch} (from settings.json)" >&2
            echo "$ch"
            return
        fi
    fi

    # First run — interactive prompt
    echo "" >&2
    echo -e "${CYAN}First run detected. No configuration found.${NC}" >&2
    echo -e "Default update channel: ${YELLOW}dev${NC} (pre-release builds from master)" >&2
    echo -e "Alternative: ${GREEN}stable${NC} (tagged releases only)" >&2
    echo "" >&2
    read -rp "Use dev channel? [Y/n] " answer
    case "$answer" in
        [nN]|[nN][oO])
            info "Using stable channel" >&2
            echo "stable"
            ;;
        *)
            info "Using dev channel" >&2
            echo "dev"
            ;;
    esac
}

# ── Build download URL ────────────────────────────────
get_download_url() {
    local channel="$1" arch="$2"
    local tag asset_name

    asset_name="${BINARY}-linux-${arch}"

    if [[ "$channel" == "stable" ]]; then
        # Stable: need API to resolve latest tag
        info "Fetching latest stable release tag..."
        local api_url="https://api.github.com/repos/${REPO}/releases/latest"
        local response
        response=$(curl -fsSL "$api_url") || error "Failed to fetch release info from GitHub"
        if command -v jq &>/dev/null; then
            tag=$(echo "$response" | jq -r ".tag_name")
        else
            tag=$(echo "$response" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' \
                | head -1 | sed 's/.*"\(v[^"]*\)".*/\1/')
        fi
        [[ -z "$tag" || "$tag" == "null" ]] && error "Failed to determine latest stable tag"
    else
        tag="dev"
    fi

    echo "https://github.com/${REPO}/releases/download/${tag}/${asset_name}"
}

# ── Kill existing process on port ─────────────────────
kill_existing() {
    local port="$1"
    local pids

    if command -v lsof &>/dev/null; then
        pids=$(lsof -ti :"$port" 2>/dev/null || true)
    elif command -v fuser &>/dev/null; then
        pids=$(fuser "$port/tcp" 2>/dev/null || true)
    elif command -v ss &>/dev/null; then
        pids=$(ss -tlnp "sport = :$port" 2>/dev/null | grep -oP 'pid=\K[0-9]+' || true)
    fi

    if [[ -n "$pids" ]]; then
        info "Stopping existing process on port ${port} (PID: ${pids})..."
        echo "$pids" | xargs kill 2>/dev/null || true
        sleep 1
        # Force kill if still alive
        echo "$pids" | while read -r pid; do
            if kill -0 "$pid" 2>/dev/null; then
                warn "Force killing PID ${pid}..."
                kill -9 "$pid" 2>/dev/null || true
            fi
        done
    fi
}

# ── Main ──────────────────────────────────────────────
main() {
    echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     warp-proxies deploy script       ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
    echo ""

    local arch channel web_addr web_port download_url

    # Detect architecture
    arch=$(detect_arch)
    info "Architecture: linux/${arch}"

    # Determine channel
    channel=$(get_channel)

    # Read web port from config (default 9090)
    if [[ -f "$SETTINGS_FILE" ]]; then
        web_addr=$(json_field "$SETTINGS_FILE" "web_addr")
    fi
    if [[ -n "${web_addr:-}" ]]; then
        info "Web address: ${web_addr} (from settings.json)"
    fi
    web_addr="${web_addr:-:9090}"
    web_port=$(parse_port "$web_addr")
    web_port="${web_port:-9090}"

    # Get download URL
    download_url=$(get_download_url "$channel" "$arch")
    info "Downloading: ${download_url}"

    # Download binary
    curl -fSL -o "${BINARY}.tmp" "$download_url" || error "Download failed"
    chmod +x "${BINARY}.tmp"

    # Check version of new binary
    local new_version
    new_version=$("./${BINARY}.tmp" -version 2>/dev/null | awk '{print $2}') || true
    if [[ -n "$new_version" ]]; then
        info "New version: ${new_version}"
    fi

    # Kill existing process
    kill_existing "$web_port"

    # Replace binary
    mv -f "${BINARY}.tmp" "$BINARY"

    # Ensure data directory exists
    mkdir -p "$DATA_DIR"

    # Start
    info "Starting warp-proxies..."
    nohup "./$BINARY" -data "$DATA_DIR" >> "$LOG_FILE" 2>&1 &
    local pid=$!

    # Verify
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
        echo ""
        info "warp-proxies is running (PID: ${pid})"
        info "WebUI: http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):${web_port}"
        info "Log:   ${LOG_FILE}"
    else
        error "Process exited unexpectedly. Check ${LOG_FILE} for details."
    fi
}

main "$@"
