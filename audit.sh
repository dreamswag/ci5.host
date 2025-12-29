#!/bin/sh
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  CI5.HOST SECURITY AUDIT v1.0                                             ║
# ║  https://github.com/dreamswag/ci5.host                                    ║
# ║                                                                           ║
# ║  Comprehensive security scanning with Pure state integration              ║
# ║  - Pre-install baseline capture                                           ║
# ║  - Post-install manifest generation                                       ║
# ║  - Ongoing integrity verification                                         ║
# ║  - Anomaly detection                                                      ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

set -e

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
AUDIT_VERSION="1.0.0"
CI5_DIR="/etc/ci5"
STATE_DIR="$CI5_DIR/state"
CORK_STATE_DIR="$STATE_DIR/corks"
AUDIT_DIR="$CI5_DIR/audit"
BASELINE_DIR="$AUDIT_DIR/baseline"
MANIFESTS_DIR="$AUDIT_DIR/manifests"
AUDIT_LOG="/var/log/ci5-audit.log"

# Risk categories
RISK_ETC_CHANGES="etc-changes"
RISK_KERNEL_MODULES="kernel-modules"
RISK_SETUID="setuid-files"
RISK_WORLD_WRITABLE="world-writable"
RISK_NETWORK_LISTENERS="network-listeners"
RISK_CRON_CHANGES="cron-changes"
RISK_SSH_KEYS="ssh-keys"

# Colors
if [ -t 1 ]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'
    B='\033[1m'; N='\033[0m'; M='\033[0;35m'; D='\033[0;90m'
else
    R=''; G=''; Y=''; C=''; B=''; N=''; M=''; D=''
fi

# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────
die() { printf "${R}[✗] %s${N}\n" "$1" >&2; exit 1; }
info() { printf "${G}[✓]${N} %s\n" "$1"; }
warn() { printf "${Y}[!]${N} %s\n" "$1"; }
fail() { printf "${R}[✗]${N} %s\n" "$1"; }
step() { printf "\n${C}═══ %s ═══${N}\n\n" "$1"; }

log() {
    mkdir -p "$(dirname "$AUDIT_LOG")"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" >> "$AUDIT_LOG"
}

init_dirs() {
    mkdir -p "$CI5_DIR" "$STATE_DIR" "$CORK_STATE_DIR" "$AUDIT_DIR" "$BASELINE_DIR" "$MANIFESTS_DIR"
}

# Check if risk is accepted
is_risk_accepted() {
    local risk="$1"
    echo "$ACCEPT_RISKS" | tr ',' '\n' | grep -q "^${risk}$"
}

# ─────────────────────────────────────────────────────────────────────────────
# BASELINE CAPTURE
# ─────────────────────────────────────────────────────────────────────────────

capture_file_hashes() {
    local output="$1"
    local dirs="${2:-/etc /usr/local/bin /opt}"
    
    info "Hashing system files..."
    
    for dir in $dirs; do
        [ -d "$dir" ] || continue
        find "$dir" -type f -size -10M 2>/dev/null | while read f; do
            local hash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
            local perms=$(stat -c '%a' "$f" 2>/dev/null)
            local owner=$(stat -c '%U:%G' "$f" 2>/dev/null)
            local size=$(stat -c '%s' "$f" 2>/dev/null)
            echo "$hash|$perms|$owner|$size|$f"
        done
    done > "$output"
    
    local count=$(wc -l < "$output")
    info "Captured $count file hashes"
}

capture_network_state() {
    local output="$1"
    
    info "Capturing network state..."
    
    {
        echo "# Listening ports"
        ss -tlnp 2>/dev/null | awk 'NR>1 {print "LISTEN|" $4 "|" $6}'
        
        echo "# Established connections"
        ss -tnp 2>/dev/null | awk 'NR>1 && /ESTAB/ {print "ESTAB|" $4 "|" $5 "|" $6}' | head -50
        
        echo "# Network interfaces"
        ip -o link show 2>/dev/null | awk -F': ' '{print "IFACE|" $2}'
        
        echo "# iptables rule count"
        echo "IPTABLES|$(iptables-save 2>/dev/null | wc -l)"
        
        echo "# nftables rule count"
        echo "NFTABLES|$(nft list ruleset 2>/dev/null | wc -l)"
    } > "$output"
}

capture_process_state() {
    local output="$1"
    
    info "Capturing process state..."
    
    {
        echo "# Running services"
        systemctl list-units --type=service --state=running 2>/dev/null | \
            awk '/running/ {print "SERVICE|" $1}'
        
        echo "# Enabled services"
        systemctl list-unit-files --type=service --state=enabled 2>/dev/null | \
            awk 'NR>1 && !/listed/ {print "ENABLED|" $1}'
        
        echo "# Docker containers"
        if command -v docker >/dev/null 2>&1; then
            docker ps -a --format '{{.Names}}|{{.State}}|{{.Image}}' 2>/dev/null | \
                sed 's/^/DOCKER|/'
        fi
        
        echo "# Cron jobs"
        for user in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
            crontab -l -u "$user" 2>/dev/null | grep -v '^#' | grep -v '^$' | \
                sed "s/^/CRON|$user|/"
        done
        
        echo "# System cron"
        cat /etc/crontab 2>/dev/null | grep -v '^#' | grep -v '^$' | \
            sed 's/^/CRON|system|/'
    } > "$output"
}

capture_security_state() {
    local output="$1"
    
    info "Capturing security state..."
    
    {
        echo "# SUID/SGID files"
        find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | \
            while read f; do
                echo "SUID|$f|$(stat -c '%a' "$f" 2>/dev/null)"
            done
        
        echo "# World-writable files in sensitive locations"
        find /etc /usr -type f -perm -002 2>/dev/null | sed 's/^/WORLD_WRITE|/'
        
        echo "# SSH authorized keys"
        find /root /home -name "authorized_keys" 2>/dev/null | while read f; do
            wc -l < "$f" 2>/dev/null | xargs -I{} echo "SSH_KEYS|$f|{}"
        done
        
        echo "# Kernel modules"
        lsmod 2>/dev/null | awk 'NR>1 {print "KMOD|" $1}'
        
        echo "# Users with UID 0"
        awk -F: '$3==0 {print "ROOT_USER|" $1}' /etc/passwd 2>/dev/null
        
        echo "# Recent password changes"
        for user in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
            chage -l "$user" 2>/dev/null | grep "Last password change" | \
                sed "s/^/PASSWD_CHANGE|$user|/"
        done | head -20
    } > "$output"
}

create_baseline() {
    step "CREATING SYSTEM BASELINE"
    
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local baseline="$BASELINE_DIR/$timestamp"
    mkdir -p "$baseline"
    
    capture_file_hashes "$baseline/files.txt"
    capture_network_state "$baseline/network.txt"
    capture_process_state "$baseline/processes.txt"
    capture_security_state "$baseline/security.txt"
    
    # Create summary
    cat > "$baseline/summary.json" << EOF
{
    "created": "$(date -Iseconds)",
    "hostname": "$(hostname)",
    "kernel": "$(uname -r)",
    "files_tracked": $(wc -l < "$baseline/files.txt"),
    "services_running": $(grep -c "^SERVICE|" "$baseline/processes.txt" || echo 0),
    "containers": $(grep -c "^DOCKER|" "$baseline/processes.txt" || echo 0),
    "suid_files": $(grep -c "^SUID|" "$baseline/security.txt" || echo 0),
    "listening_ports": $(grep -c "^LISTEN|" "$baseline/network.txt" || echo 0)
}
EOF

    # Link as current baseline
    ln -sf "$baseline" "$BASELINE_DIR/current"
    
    info "Baseline created: $baseline"
    log "INFO" "Baseline created: $baseline"
}

# ─────────────────────────────────────────────────────────────────────────────
# PRE-INSTALL AUDIT
# ─────────────────────────────────────────────────────────────────────────────

pre_install_audit() {
    local cork="$1"
    
    step "PRE-INSTALL AUDIT: $cork"
    
    local audit_dir="$CORK_STATE_DIR/$cork/audit"
    mkdir -p "$audit_dir"
    
    local warnings=0
    local errors=0
    
    # Capture pre-install state
    info "Capturing pre-install security state..."
    capture_file_hashes "$audit_dir/pre-files.txt" "/etc /opt /var/lib"
    capture_network_state "$audit_dir/pre-network.txt"
    capture_security_state "$audit_dir/pre-security.txt"
    
    # Check for existing anomalies
    info "Checking for existing anomalies..."
    
    # Check for unexpected root users
    local extra_root=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)
    if [ -n "$extra_root" ]; then
        fail "Found non-root users with UID 0: $extra_root"
        errors=$((errors + 1))
    fi
    
    # Check for suspicious processes
    if pgrep -f "cryptominer\|xmrig\|minerd" >/dev/null 2>&1; then
        fail "Potential cryptocurrency miner detected!"
        errors=$((errors + 1))
    fi
    
    # Check for reverse shells
    if ss -tlnp 2>/dev/null | grep -qE "nc|ncat|netcat|socat"; then
        warn "Potential reverse shell listener detected"
        warnings=$((warnings + 1))
    fi
    
    # Check disk space
    local free_space=$(df / 2>/dev/null | awk 'NR==2 {print $4}')
    if [ "${free_space:-0}" -lt 524288 ]; then  # 512MB
        warn "Low disk space: ${free_space}KB available"
        warnings=$((warnings + 1))
    fi
    
    # Check system load
    local load=$(cat /proc/loadavg 2>/dev/null | awk '{print $1}' | cut -d. -f1)
    if [ "${load:-0}" -gt 4 ]; then
        warn "High system load: $load"
        warnings=$((warnings + 1))
    fi
    
    # Summary
    echo ""
    if [ $errors -gt 0 ]; then
        fail "Pre-install audit found $errors error(s), $warnings warning(s)"
        log "ERROR" "Pre-install audit for $cork: $errors errors, $warnings warnings"
        return 1
    elif [ $warnings -gt 0 ]; then
        warn "Pre-install audit found $warnings warning(s)"
        log "WARN" "Pre-install audit for $cork: $warnings warnings"
        return 0
    else
        info "Pre-install audit passed"
        log "INFO" "Pre-install audit for $cork: passed"
        return 0
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# POST-INSTALL AUDIT
# ─────────────────────────────────────────────────────────────────────────────

post_install_audit() {
    local cork="$1"
    
    step "POST-INSTALL AUDIT: $cork"
    
    local audit_dir="$CORK_STATE_DIR/$cork/audit"
    mkdir -p "$audit_dir"
    
    # Capture post-install state
    info "Capturing post-install security state..."
    capture_file_hashes "$audit_dir/post-files.txt" "/etc /opt /var/lib"
    capture_network_state "$audit_dir/post-network.txt"
    capture_security_state "$audit_dir/post-security.txt"
    
    # Calculate changes
    if [ -f "$audit_dir/pre-files.txt" ]; then
        info "Calculating file changes..."
        
        # New files
        comm -13 <(awk -F'|' '{print $5}' "$audit_dir/pre-files.txt" | sort) \
                 <(awk -F'|' '{print $5}' "$audit_dir/post-files.txt" | sort) \
            > "$audit_dir/new-files.txt"
        
        # Modified files (different hash)
        awk -F'|' '{print $5 "|" $1}' "$audit_dir/pre-files.txt" | sort > /tmp/pre-hashes
        awk -F'|' '{print $5 "|" $1}' "$audit_dir/post-files.txt" | sort > /tmp/post-hashes
        
        comm -13 /tmp/pre-hashes /tmp/post-hashes | cut -d'|' -f1 > "$audit_dir/modified-files.txt"
        rm -f /tmp/pre-hashes /tmp/post-hashes
        
        local new_count=$(wc -l < "$audit_dir/new-files.txt")
        local mod_count=$(wc -l < "$audit_dir/modified-files.txt")
        
        info "Files created: $new_count"
        info "Files modified: $mod_count"
    fi
    
    # Calculate network changes
    if [ -f "$audit_dir/pre-network.txt" ]; then
        info "Calculating network changes..."
        
        local pre_ports=$(grep "^LISTEN|" "$audit_dir/pre-network.txt" | wc -l)
        local post_ports=$(grep "^LISTEN|" "$audit_dir/post-network.txt" | wc -l)
        local new_ports=$((post_ports - pre_ports))
        
        if [ $new_ports -gt 0 ]; then
            info "New listening ports: $new_ports"
            comm -13 <(grep "^LISTEN|" "$audit_dir/pre-network.txt" | sort) \
                     <(grep "^LISTEN|" "$audit_dir/post-network.txt" | sort) \
                > "$audit_dir/new-ports.txt"
        fi
    fi
    
    log "INFO" "Post-install audit for $cork completed"
}

# ─────────────────────────────────────────────────────────────────────────────
# MANIFEST GENERATION
# ─────────────────────────────────────────────────────────────────────────────

generate_manifest() {
    local cork="$1"
    
    step "GENERATING SECURITY MANIFEST: $cork"
    
    local audit_dir="$CORK_STATE_DIR/$cork/audit"
    local manifest="$MANIFESTS_DIR/${cork}.json"
    
    [ -f "$audit_dir/post-files.txt" ] || {
        warn "No post-install audit data found"
        return 1
    }
    
    info "Building manifest..."
    
    # Generate JSON manifest
    cat > "$manifest" << EOF
{
    "cork": "$cork",
    "generated": "$(date -Iseconds)",
    "version": "1.0",
    "files": {
EOF

    # Add file hashes
    local first=true
    while IFS='|' read -r hash perms owner size file; do
        [ -n "$file" ] || continue
        if [ "$first" = "true" ]; then
            first=false
        else
            echo ","
        fi
        printf '        "%s": {"sha256": "%s", "permissions": "%s", "owner": "%s", "size": %s}' \
            "$file" "$hash" "$perms" "$owner" "$size"
    done < "$audit_dir/post-files.txt" >> "$manifest"
    
    cat >> "$manifest" << EOF

    },
    "network": {
        "expected_listeners": [
EOF

    # Add expected ports
    first=true
    grep "^LISTEN|" "$audit_dir/post-network.txt" 2>/dev/null | while IFS='|' read -r type addr proc; do
        if [ "$first" = "true" ]; then
            first=false
        else
            echo ","
        fi
        printf '            "%s"' "$addr"
    done >> "$manifest"
    
    cat >> "$manifest" << EOF

        ]
    },
    "services": [
EOF

    # Add services
    first=true
    grep "^SERVICE|" "$audit_dir/post-security.txt" 2>/dev/null | cut -d'|' -f2 | while read svc; do
        if [ "$first" = "true" ]; then
            first=false
        else
            echo ","
        fi
        printf '        "%s"' "$svc"
    done >> "$manifest"

    cat >> "$manifest" << EOF

    ]
}
EOF

    info "Manifest generated: $manifest"
    
    # Copy to cork state dir
    cp "$manifest" "$CORK_STATE_DIR/$cork/manifest.json"
    
    log "INFO" "Manifest generated for $cork"
}

# ─────────────────────────────────────────────────────────────────────────────
# INTEGRITY CHECK
# ─────────────────────────────────────────────────────────────────────────────

check_integrity() {
    local cork="$1"
    
    step "INTEGRITY CHECK: ${cork:-all corks}"
    
    local warnings=0
    local errors=0
    
    # If cork specified, check just that one
    if [ -n "$cork" ]; then
        local manifest="$MANIFESTS_DIR/${cork}.json"
        if [ -f "$manifest" ]; then
            check_cork_integrity "$cork" "$manifest"
            return $?
        else
            warn "No manifest found for $cork"
            return 1
        fi
    fi
    
    # Check all corks with manifests
    for manifest in "$MANIFESTS_DIR"/*.json; do
        [ -f "$manifest" ] || continue
        local name=$(basename "$manifest" .json)
        
        printf "${C}Checking: %s${N}\n" "$name"
        if ! check_cork_integrity "$name" "$manifest"; then
            errors=$((errors + 1))
        fi
    done
    
    echo ""
    if [ $errors -gt 0 ]; then
        fail "Integrity check found issues in $errors cork(s)"
        return 1
    else
        info "All integrity checks passed"
        return 0
    fi
}

check_cork_integrity() {
    local cork="$1"
    local manifest="$2"
    
    local issues=0
    
    # Check file hashes
    if command -v jq >/dev/null 2>&1; then
        jq -r '.files | to_entries[] | "\(.key)|\(.value.sha256)"' "$manifest" 2>/dev/null | \
        while IFS='|' read -r file expected_hash; do
            [ -f "$file" ] || {
                warn "  Missing: $file"
                issues=$((issues + 1))
                continue
            }
            
            local actual_hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
            if [ "$actual_hash" != "$expected_hash" ]; then
                warn "  Modified: $file"
                issues=$((issues + 1))
            fi
        done
    fi
    
    if [ $issues -gt 0 ]; then
        return 1
    else
        info "  OK"
        return 0
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# FULL SYSTEM AUDIT
# ─────────────────────────────────────────────────────────────────────────────

full_audit() {
    step "FULL SYSTEM SECURITY AUDIT"
    
    local warnings=0
    local errors=0
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local report="$AUDIT_DIR/report-$timestamp.txt"
    
    {
        echo "CI5 Security Audit Report"
        echo "Generated: $(date)"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "=========================================="
        echo ""
    } > "$report"
    
    # 1. Check for rootkits (basic)
    printf "Checking for rootkits... "
    local rootkit_found=false
    
    # Hidden processes
    if [ $(ps aux 2>/dev/null | wc -l) -ne $(ls /proc 2>/dev/null | grep -c '^[0-9]') ]; then
        warn "Hidden processes detected!"
        rootkit_found=true
        errors=$((errors + 1))
    fi
    
    # Check /etc/ld.so.preload
    if [ -s /etc/ld.so.preload ]; then
        warn "ld.so.preload is not empty - potential library injection"
        rootkit_found=true
        warnings=$((warnings + 1))
    fi
    
    [ "$rootkit_found" = "false" ] && info "OK"
    
    # 2. Check SUID/SGID files
    printf "Checking SUID/SGID files... "
    local suid_count=$(find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)
    if [ $suid_count -gt 50 ]; then
        warn "Unusually high SUID/SGID count: $suid_count"
        warnings=$((warnings + 1))
    else
        info "OK ($suid_count files)"
    fi
    
    # 3. Check for suspicious network connections
    printf "Checking network connections... "
    local suspicious_conn=$(ss -tnp 2>/dev/null | grep -E ':4444|:5555|:6666|:31337' | wc -l)
    if [ $suspicious_conn -gt 0 ]; then
        fail "Suspicious ports detected!"
        errors=$((errors + 1))
    else
        info "OK"
    fi
    
    # 4. Check for unauthorized SSH keys
    printf "Checking SSH keys... "
    local total_keys=0
    for keyfile in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        [ -f "$keyfile" ] && total_keys=$((total_keys + $(wc -l < "$keyfile")))
    done
    if [ $total_keys -gt 10 ]; then
        warn "Many SSH keys found: $total_keys"
        warnings=$((warnings + 1))
    else
        info "OK ($total_keys keys)"
    fi
    
    # 5. Check Docker security
    if command -v docker >/dev/null 2>&1; then
        printf "Checking Docker security... "
        
        # Privileged containers
        local priv=$(docker ps --filter "label=com.docker.compose.project" --format '{{.Names}}' 2>/dev/null | \
            xargs -I{} docker inspect {} 2>/dev/null | grep -c '"Privileged": true' || echo 0)
        
        if [ $priv -gt 0 ]; then
            warn "$priv privileged container(s)"
            warnings=$((warnings + 1))
        else
            info "OK"
        fi
    fi
    
    # 6. Check file permissions
    printf "Checking file permissions... "
    local world_writable=$(find /etc -type f -perm -002 2>/dev/null | wc -l)
    if [ $world_writable -gt 0 ]; then
        warn "$world_writable world-writable files in /etc"
        warnings=$((warnings + 1))
    else
        info "OK"
    fi
    
    # 7. Check for pending updates
    if command -v apt-get >/dev/null 2>&1; then
        printf "Checking for security updates... "
        local updates=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst" || echo 0)
        if [ $updates -gt 20 ]; then
            warn "$updates pending updates"
            warnings=$((warnings + 1))
        else
            info "OK ($updates pending)"
        fi
    fi
    
    # Summary
    echo ""
    echo "=========================================="
    printf "Errors:   %d\n" $errors
    printf "Warnings: %d\n" $warnings
    echo "=========================================="
    
    {
        echo ""
        echo "Summary"
        echo "======="
        echo "Errors: $errors"
        echo "Warnings: $warnings"
    } >> "$report"
    
    info "Report saved: $report"
    log "INFO" "Full audit completed: $errors errors, $warnings warnings"
    
    if [ $errors -gt 0 ]; then
        return 1
    else
        return 0
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# USAGE
# ─────────────────────────────────────────────────────────────────────────────

usage() {
    cat << 'EOF'
CI5.HOST Security Audit v1.0

USAGE:
  audit.sh [OPTIONS] [COMMAND]

COMMANDS:
  (default)         Full system security audit
  baseline          Create system baseline snapshot
  integrity [cork]  Check file integrity against manifests
  
OPTIONS (for ci5.run integration):
  --pre-install     Run pre-install audit for cork
  --post-install    Run post-install audit for cork
  --generate-manifest  Generate security manifest after install
  --cork=NAME       Specify cork name
  --accept=RISKS    Accept specific risk categories (comma-separated)

RISK CATEGORIES:
  etc-changes       Changes to /etc directory
  kernel-modules    Kernel module loading
  setuid-files      SUID/SGID file changes
  world-writable    World-writable file changes
  network-listeners New network listeners
  cron-changes      Cron job modifications
  ssh-keys          SSH key additions

EXAMPLES:
  # Full system audit
  curl ci5.host | sh
  
  # Create baseline before any CI5 installation
  curl ci5.host | sh -s baseline
  
  # Check integrity of specific cork
  curl ci5.host | sh -s integrity mullvad
  
  # Pre-install audit (called by ci5.run stub)
  audit.sh --pre-install --cork=adguard
  
  # Accept specific risks
  audit.sh --pre-install --cork=wireguard --accept=etc-changes,kernel-modules
EOF
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

main() {
    # Parse options
    MODE=""
    CORK=""
    ACCEPT_RISKS=""
    GENERATE_MANIFEST=false
    
    while [ $# -gt 0 ]; do
        case "$1" in
            --pre-install)      MODE="pre-install"; shift ;;
            --post-install)     MODE="post-install"; shift ;;
            --generate-manifest) GENERATE_MANIFEST=true; shift ;;
            --cork=*)           CORK="${1#*=}"; shift ;;
            --accept=*)         ACCEPT_RISKS="${1#*=}"; shift ;;
            --help|-h)          usage; exit 0 ;;
            baseline)           MODE="baseline"; shift ;;
            integrity)          MODE="integrity"; shift; CORK="$1"; shift 2>/dev/null || true ;;
            *)                  shift ;;
        esac
    done
    
    init_dirs
    
    case "$MODE" in
        "pre-install")
            [ -n "$CORK" ] || die "Cork name required for pre-install audit"
            pre_install_audit "$CORK"
            ;;
        "post-install")
            [ -n "$CORK" ] || die "Cork name required for post-install audit"
            post_install_audit "$CORK"
            [ "$GENERATE_MANIFEST" = "true" ] && generate_manifest "$CORK"
            ;;
        "baseline")
            create_baseline
            ;;
        "integrity")
            check_integrity "$CORK"
            ;;
        *)
            full_audit
            ;;
    esac
}

main "$@"
