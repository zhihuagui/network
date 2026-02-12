#!/bin/sh
# Clash Subscription Converter (Shell + Lua)
# Compatible: Windows (Git Bash/WSL) | Linux | macOS
# Usage: bash convert.sh

# ===================== 自定义配置（修改这里）=====================
SUBSCRIBE_URL="https://dingyue.site/s/04c43a8c922c4431e357ae559ae62d6d"
LUA_SCRIPT_PATH="./convert.lua"
OUTPUT_YAML="./clash-config.yaml"
TEMP_FILE="./subscription.tmp"
CURL_TIMEOUT=30
# =================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO] $(date +%H:%M:%S) $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}[WARN] $(date +%H:%M:%S) $1${NC}"
}

log_error() {
    echo -e "${RED}[ERROR] $(date +%H:%M:%S) $1${NC}"
}

log_info "=== Step 1: Check dependencies ==="

if ! command -v curl &> /dev/null; then
    log_error "curl is not installed! Please install curl first."
    log_error "Windows: Install Git Bash (自带curl) | WSL: sudo apt install curl"
    exit 1
fi

if ! command -v lua &> /dev/null; then
    log_error "lua is not installed! Please install Lua 5.1+"
    log_error "Windows: Download from https://sourceforge.net/projects/luabinaries/files/5.1.5/Windows%20Libraries/"
    exit 1
fi

if [ ! -f "$LUA_SCRIPT_PATH" ]; then
    log_error "Lua script not found: $LUA_SCRIPT_PATH"
    exit 1
fi

log_info "=== Step 2: Download subscription ==="
log_info "Downloading from: $SUBSCRIBE_URL"

curl -s -f -L --insecure --show-error \
     -m $CURL_TIMEOUT \
     -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
     -o "$TEMP_FILE" \
     "$SUBSCRIBE_URL"

if [ $? -ne 0 ]; then
    log_error "Failed to download subscription (curl error)"
    [ -f "$TEMP_FILE" ] && rm -f "$TEMP_FILE"
    exit 1
fi

if [ ! -s "$TEMP_FILE" ]; then
    log_error "Downloaded content is empty!"
    [ -f "$TEMP_FILE" ] && rm -f "$TEMP_FILE"
    exit 1
fi

log_info "Subscription downloaded successfully (size: $(du -h $TEMP_FILE | awk '{print $1}'))"

log_info "=== Step 3: Generate YAML via Lua ==="
lua "$LUA_SCRIPT_PATH" "$TEMP_FILE" "$OUTPUT_YAML"

if [ $? -eq 0 ]; then
    log_info "${GREEN}✅ Success! YAML file generated: $OUTPUT_YAML${NC}"
    mv "$OUTPUT_YAML" config.yaml
else
    log_error "Lua script execution failed!"
    [ -f "$TEMP_FILE" ] && rm -f "$TEMP_FILE"
    exit 1
fi

log_info "=== Step 4: Clean up ==="
rm -f "$TEMP_FILE"
log_info "Temporary file deleted: $TEMP_FILE"

log_info "=== All done! ==="
exit 0
