#!/bin/sh
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  CI5.HOST BOOTSTRAP STUB v1.1 (PATCHED)                                   ║
# ║  https://github.com/dreamswag/ci5.host                                    ║
# ║                                                                           ║
# ║  ISOLATED TRUST ANCHOR FOR AUDIT SYSTEM                                   ║
# ║  Separate signing key from ci5.run for security isolation                 ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

set -e

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
CI5_HOST_VERSION="1.1.0"
CI5_HOST_RAW="https://raw.githubusercontent.com/dreamswag/ci5.host/main"

# [CRITICAL] CI5.HOST Public Key - DIFFERENT from ci5.run!
# This key must sign audit.sh in the ci5.host repo
CI5_HOST_PUBKEY="-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
REPLACE_WITH_ACTUAL_CI5_HOST_KEY
-----END PUBLIC KEY-----"

# Colors
if [ -t 1 ]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'
    B='\033[1m'; N='\033[0m'; M='\033[0;35m'
else
    R=''; G=''; Y=''; C=''; B=''; N=''; M=''
fi

# ─────────────────────────────────────────────────────────────────────────────
# CORE FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
die() { printf "${R}[✗] ERROR: %s${N}\n" "$1" >&2; exit 1; }
info() { printf "${G}[→]${N} %s\n" "$1"; }
warn() { printf "${Y}[!]${N} %s\n" "$1"; }

verify_signature() {
    local file="$1"
    local sig="$2"
    
    [ -f "$file" ] && [ -f "$sig" ] || return 1
    
    echo "$CI5_HOST_PUBKEY" > /tmp/ci5-host.pub
    if openssl dgst -sha256 -verify /tmp/ci5-host.pub -signature "$sig" "$file" >/dev/null 2>&1; then
        rm -f /tmp/ci5-host.pub
        return 0
    else
        rm -f /tmp/ci5-host.pub
        return 1
    fi
}

download_verified() {
    local name="$1"
    local url="$2"
    local dest="$3"
    
    info "Downloading $name..."
    curl -fsSL "$url" -o "$dest" || die "Failed to download $name"
    
    # SECURITY FIX: Enforce signature presence
    curl -fsSL "${url}.sig" -o "${dest}.sig" || {
        die "SECURITY FAIL: Signature missing for $name. Audit requires strict verification."
    }
    
    info "Verifying $name signature..."
    if ! verify_signature "$dest" "${dest}.sig"; then
        rm -f "$dest" "${dest}.sig"
        die "SIGNATURE VERIFICATION FAILED for $name"
    fi
    
    printf "${G}[✓]${N} %s verified\n" "$name"
    rm -f "${dest}.sig"
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
check_requirements() {
    [ "$(id -u)" -eq 0 ] || die "Must run as root"
    command -v curl >/dev/null 2>&1 || die "curl not found"
    command -v openssl >/dev/null 2>&1 || die "openssl not found"
}

show_menu() {
    cat << 'BANNER'
    ╔═══════════════════════════════════════════════════════════════════╗
    ║              CI5.HOST — Security Audit System                     ║
    ║                 Isolated • Independent • Verified                 ║
    ╚═══════════════════════════════════════════════════════════════════╝
BANNER
    printf "\n"
    printf "    ${B}[1] AUDIT${N}        Full system security scan\n"
    printf "    ${B}[2] BASELINE${N}     Create clean system baseline\n"
    printf "    ${B}[3] INTEGRITY${N}    Check file integrity vs manifest\n"
    printf "    ${B}[4] MANIFEST${N}     Generate security manifest\n\n"
}

main() {
    check_requirements
    
    local cmd="${1:-audit}"
    
    # LOGIC FIX: Everything maps to audit.sh because it is a monolith
    local target_script="audit.sh"
    
    printf "${C}═══ CI5.HOST: $cmd ═══${N}\n\n"
    
    download_verified "$target_script" "${CI5_HOST_RAW}/${target_script}" "/tmp/ci5-host-exec.sh"
    chmod +x /tmp/ci5-host-exec.sh
    
    # Pass all arguments to the monolith script
    exec /tmp/ci5-host-exec.sh "$@"
}

main "$@"