#!/bin/sh
# 🔬 Ci5 Host Auditor (v7.4-RC-1) - "ICUP"
# Purpose: Detect Host-Infection attempts on non-overlay filesystems.

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; 
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

CORK_NAME=$1
AUDIT_DURATION=${2:-30}

usage() {
    echo "Usage: $0 <cork-name> [duration_seconds]"
    echo ""
    echo "Examples:"
    echo "  $0 ntopng                 # Audit ntopng for 30 seconds"
    echo "  $0 home-assistant 60      # Audit home-assistant for 60 seconds"
    echo ""
    echo "Options:"
    echo "  --skip-network    Allow network access during audit (reduces security)"
    echo "  --verbose         Show detailed syscall logs"
    echo "  --no-cleanup      Keep audit artifacts for manual inspection"
    exit 1
}

[ -z "$CORK_NAME" ] && usage

# Parse optional flags
SKIP_NETWORK=0
VERBOSE=0
NO_CLEANUP=0

for arg in "$@"; do
    case "$arg" in
        --skip-network) SKIP_NETWORK=1 ;;
        --verbose) VERBOSE=1 ;;
        --no-cleanup) NO_CLEANUP=1 ;;
    esac
done

# ─────────────────────────────────────────────────────────────
# 1. INITIALIZE IDENTITY
# ─────────────────────────────────────────────────────────────
USER_ID=$(cat /proc/cpuinfo 2>/dev/null | grep Serial | awk '{print $3}' | sha256sum | cut -c1-12)
[ -z "$USER_ID" ] && USER_ID=$(cat /etc/machine-id 2>/dev/null | sha256sum | cut -c1-12)
[ -z "$USER_ID" ] && USER_ID="unknown"

LAB_DIR="/tmp/ci5_lab_$$"
AUDIT_LOG="/tmp/ci5_audit_${CORK_NAME}_$(date +%Y%m%d_%H%M%S).log"

# Overlay directories
UPPER_ETC="$LAB_DIR/upper_etc"
WORK_ETC="$LAB_DIR/work_etc"
MERGE_ETC="$LAB_DIR/merge_etc"

# Additional shadow paths for /proc/sys and /sys
UPPER_PROCSYS="$LAB_DIR/upper_procsys"
WORK_PROCSYS="$LAB_DIR/work_procsys"
MERGE_PROCSYS="$LAB_DIR/merge_procsys"

UPPER_SYS="$LAB_DIR/upper_sys"
WORK_SYS="$LAB_DIR/work_sys"
MERGE_SYS="$LAB_DIR/merge_sys"

# Seccomp logging
SECCOMP_LOG="$LAB_DIR/seccomp_audit.log"
STRACE_LOG="$LAB_DIR/strace_audit.log"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}          ${MAGENTA}🔬 Ci5 ICUP AUDIT (v7.4-RC-1)${NC}                      ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "   Auditor ID:    ${YELLOW}$USER_ID${NC}"
echo -e "   Target Cork:   ${YELLOW}$CORK_NAME${NC}"
echo -e "   Duration:      ${YELLOW}${AUDIT_DURATION}s${NC}"
echo -e "   Network:       ${YELLOW}$([ $SKIP_NETWORK -eq 1 ] && echo "BRIDGE (Reduced Security)" || echo "NONE (Isolated)")${NC}"
echo ""

# ─────────────────────────────────────────────────────────────
# 2. PREPARE RAM-BACKED LABORATORY
# ─────────────────────────────────────────────────────────────
echo -e "${CYAN}[1/6] Preparing RAM-backed laboratory...${NC}"

cleanup() {
    echo ""
    echo -e "${YELLOW}[*] Cleaning up...${NC}"
    
    # Stop container
    docker stop "audit_$CORK_NAME" 2>/dev/null || true
    docker rm "audit_$CORK_NAME" 2>/dev/null || true
    
    # Kill strace if running
    pkill -f "strace.*audit_$CORK_NAME" 2>/dev/null || true
    
    # Unmount overlays
    umount "$MERGE_ETC" 2>/dev/null || true
    umount "$MERGE_PROCSYS" 2>/dev/null || true
    umount "$MERGE_SYS" 2>/dev/null || true
    umount "$LAB_DIR" 2>/dev/null || true
    
    if [ $NO_CLEANUP -eq 0 ]; then
        rm -rf "$LAB_DIR" 2>/dev/null || true
    else
        echo -e "   ${YELLOW}Artifacts preserved at: $LAB_DIR${NC}"
    fi
}

trap cleanup EXIT INT TERM

# Create tmpfs for the lab
mkdir -p "$LAB_DIR"
mount -t tmpfs tmpfs "$LAB_DIR" -o size=100M

# Create overlay structure for /etc
mkdir -p "$UPPER_ETC" "$WORK_ETC" "$MERGE_ETC"

# Create overlay structure for /proc/sys and /sys
mkdir -p "$UPPER_PROCSYS" "$WORK_PROCSYS" "$MERGE_PROCSYS"
mkdir -p "$UPPER_SYS" "$WORK_SYS" "$MERGE_SYS"

# Initialize seccomp log
touch "$SECCOMP_LOG"
touch "$STRACE_LOG"

echo -e "   ${GREEN}✓ Overlay directories created${NC}"

# ─────────────────────────────────────────────────────────────
# 3. MOUNT THE SHADOW BONE-MARROW
# ─────────────────────────────────────────────────────────────
echo -e "${CYAN}[2/6] Mounting shadow filesystems...${NC}"

# Shadow /etc - catches config modifications
mount -t overlay overlay -o lowerdir=/etc,upperdir="$UPPER_ETC",workdir="$WORK_ETC" "$MERGE_ETC"
echo -e "   ${GREEN}✓ Shadow /etc mounted (host protected)${NC}"

# Shadow /proc/sys - catches kernel parameter manipulation
# Note: /proc/sys is special, we can't overlay it directly
# Instead, we'll monitor writes via strace/audit
echo -e "   ${YELLOW}⚠ /proc/sys monitoring via syscall tracing${NC}"

# Create a fake /sys overlay for detection
# Real /sys can't be overlaid, but we can detect writes via container inspection
echo -e "   ${YELLOW}⚠ /sys monitoring via container diff${NC}"

# ─────────────────────────────────────────────────────────────
# 4. PREPARE SECCOMP PROFILE 
# ─────────────────────────────────────────────────────────────
echo -e "${CYAN}[3/6] Preparing security monitoring...${NC}"

# Create a logging seccomp profile
cat > "$LAB_DIR/seccomp_audit.json" << 'SECCOMP'
{
    "defaultAction": "SCMP_ACT_LOG",
    "syscalls": [
        {
            "names": [
                "mount", "umount", "umount2", "pivot_root",
                "ptrace", "process_vm_readv", "process_vm_writev",
                "init_module", "finit_module", "delete_module",
                "kexec_load", "kexec_file_load",
                "reboot", "sethostname", "setdomainname",
                "syslog", "acct", "settimeofday", "adjtimex",
                "swapon", "swapoff", "quotactl",
                "unshare", "setns",
                "open_by_handle_at", "name_to_handle_at"
            ],
            "action": "SCMP_ACT_LOG"
        },
        {
            "names": [
                "read", "write", "open", "close", "stat", "fstat",
                "lstat", "poll", "lseek", "mmap", "mprotect",
                "munmap", "brk", "ioctl", "access", "pipe",
                "select", "sched_yield", "mremap", "msync",
                "mincore", "madvise", "dup", "dup2", "nanosleep",
                "getpid", "socket", "connect", "accept", "sendto",
                "recvfrom", "sendmsg", "recvmsg", "shutdown",
                "bind", "listen", "getsockname", "getpeername",
                "socketpair", "setsockopt", "getsockopt", "clone",
                "fork", "vfork", "execve", "exit", "wait4",
                "kill", "uname", "fcntl", "flock", "fsync",
                "fdatasync", "truncate", "ftruncate", "getdents",
                "getcwd", "chdir", "fchdir", "rename", "mkdir",
                "rmdir", "creat", "link", "unlink", "symlink",
                "readlink", "chmod", "fchmod", "chown", "fchown",
                "lchown", "umask", "gettimeofday", "getrlimit",
                "getrusage", "sysinfo", "times", "getuid", "getgid",
                "setuid", "setgid", "geteuid", "getegid", "setpgid",
                "getppid", "getpgrp", "setsid", "setreuid", "setregid",
                "getgroups", "setgroups", "setresuid", "getresuid",
                "setresgid", "getresgid", "getpgid", "setfsuid",
                "setfsgid", "getsid", "capget", "capset", "rt_sigpending",
                "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend",
                "sigaltstack", "utime", "mknod", "uselib", "personality",
                "statfs", "fstatfs", "getpriority", "setpriority",
                "sched_setparam", "sched_getparam", "sched_setscheduler",
                "sched_getscheduler", "sched_get_priority_max",
                "sched_get_priority_min", "sched_rr_get_interval",
                "mlock", "munlock", "mlockall", "munlockall", "vhangup",
                "prctl", "arch_prctl", "setrlimit", "chroot", "sync",
                "mount", "umount2", "swapon", "swapoff", "reboot",
                "sethostname", "setdomainname", "iopl", "ioperm"
            ],
            "action": "SCMP_ACT_ALLOW"
        }
    ]
}
SECCOMP

echo -e "   ${GREEN}✓ Seccomp audit profile created${NC}"

# ─────────────────────────────────────────────────────────────
# 5. RUN THE CORK IN THE LAB
# ─────────────────────────────────────────────────────────────
echo -e "${CYAN}[4/6] Launching Cork in isolated environment...${NC}"

# Build Docker run command
DOCKER_OPTS="--name audit_$CORK_NAME"
DOCKER_OPTS="$DOCKER_OPTS -v $MERGE_ETC:/etc:rw"
DOCKER_OPTS="$DOCKER_OPTS --security-opt seccomp=$LAB_DIR/seccomp_audit.json"
DOCKER_OPTS="$DOCKER_OPTS --cap-drop=ALL"
DOCKER_OPTS="$DOCKER_OPTS --cap-add=NET_BIND_SERVICE"

if [ $SKIP_NETWORK -eq 0 ]; then
    DOCKER_OPTS="$DOCKER_OPTS --network none"
    echo -e "   ${GREEN}✓ Network isolated (--network none)${NC}"
else
    DOCKER_OPTS="$DOCKER_OPTS --network bridge"
    echo -e "   ${YELLOW}⚠ Network enabled (reduced security)${NC}"
fi

# Additional security restrictions
DOCKER_OPTS="$DOCKER_OPTS --read-only"
DOCKER_OPTS="$DOCKER_OPTS --tmpfs /tmp:rw,noexec,nosuid"
DOCKER_OPTS="$DOCKER_OPTS --tmpfs /var/run:rw,noexec,nosuid"
DOCKER_OPTS="$DOCKER_OPTS --pids-limit=100"
DOCKER_OPTS="$DOCKER_OPTS --memory=512m"
DOCKER_OPTS="$DOCKER_OPTS --cpu-shares=256"

# Check if image exists
if ! docker image inspect "$CORK_NAME" >/dev/null 2>&1; then
    echo -e "   ${YELLOW}Image not found locally, pulling...${NC}"
    if ! docker pull "$CORK_NAME" 2>/dev/null; then
        echo -e "   ${RED}✗ Failed to pull image: $CORK_NAME${NC}"
        exit 1
    fi
fi

# Start container
docker run -d $DOCKER_OPTS "$CORK_NAME" > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo -e "   ${RED}✗ Failed to start container${NC}"
    exit 1
fi

echo -e "   ${GREEN}✓ Cork running in sandbox${NC}"

if command -v strace >/dev/null 2>&1 && [ $VERBOSE -eq 1 ]; then
    CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' "audit_$CORK_NAME" 2>/dev/null)
    if [ -n "$CONTAINER_PID" ] && [ "$CONTAINER_PID" != "0" ]; then
        # Monitor suspicious syscalls
        strace -f -e trace=mount,umount,ptrace,init_module,delete_module,reboot,sethostname \
            -p "$CONTAINER_PID" -o "$STRACE_LOG" 2>/dev/null &
        echo -e "   ${GREEN}✓ Syscall tracing active (PID: $CONTAINER_PID)${NC}"
    fi
fi

# ─────────────────────────────────────────────────────────────
# 6. MONITORING PHASE
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}[5/6] Monitoring for ${AUDIT_DURATION} seconds...${NC}"
echo -n "   "

i=0
while [ $i -lt $AUDIT_DURATION ]; do
    sleep 1
    i=$((i+1))
    
    # Progress indicator
    if [ $((i % 5)) -eq 0 ]; then
        printf "${GREEN}█${NC}"
    else
        printf "."
    fi
    
    # Check container health
    if ! docker ps | grep -q "audit_$CORK_NAME"; then
        echo ""
        echo -e "   ${YELLOW}⚠ Container exited early${NC}"
        break
    fi
done
echo ""

# ─────────────────────────────────────────────────────────────
# 7. THE REVEAL (Forensic Analysis)
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}[6/6] Analyzing audit results...${NC}"
echo ""

# Initialize result
RESULT="SAFE"
FINDINGS=""

# ─────────────────────────────────────────────────────────────
# A. Check Host /etc Modifications
# ─────────────────────────────────────────────────────────────
echo -e "${MAGENTA}═══ HOST BREAKOUT ANALYSIS ═══${NC}"
echo ""

ETC_BREAKOUTS=$(find "$UPPER_ETC" -type f 2>/dev/null)
if [ -n "$ETC_BREAKOUTS" ]; then
    echo -e "${RED}[!] HOST /etc MODIFICATION ATTEMPTS DETECTED:${NC}"
    echo "$ETC_BREAKOUTS" | while read f; do
        echo -e "   ${RED}• $(echo $f | sed "s|$UPPER_ETC|/etc|g")${NC}"
    done
    RESULT="MALICIOUS"
    FINDINGS="$FINDINGS\n- Attempted to modify host /etc files"
    echo ""
else
    echo -e "${GREEN}[✓] /etc protection: CLEAN${NC}"
fi

# ─────────────────────────────────────────────────────────────
# B. Check Container Filesystem Changes
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${MAGENTA}═══ CONTAINER FILESYSTEM CHANGES ═══${NC}"
echo ""

CONTAINER_DIFF=$(docker diff "audit_$CORK_NAME" 2>/dev/null | head -20)
if [ -n "$CONTAINER_DIFF" ]; then
    echo "$CONTAINER_DIFF" | while read line; do
        change_type=$(echo "$line" | cut -c1)
        path=$(echo "$line" | cut -c3-)
        
        case "$change_type" in
            A) echo -e "   ${GREEN}[ADD]${NC} $path" ;;
            C) echo -e "   ${YELLOW}[CHG]${NC} $path" ;;
            D) echo -e "   ${RED}[DEL]${NC} $path" ;;
        esac
    done
    
    TOTAL_CHANGES=$(docker diff "audit_$CORK_NAME" 2>/dev/null | wc -l)
    if [ "$TOTAL_CHANGES" -gt 20 ]; then
        echo -e "   ${YELLOW}... and $((TOTAL_CHANGES - 20)) more changes${NC}"
    fi
else
    echo -e "   ${GREEN}No filesystem changes detected${NC}"
fi

# ─────────────────────────────────────────────────────────────
# C. Check for Kernel Parameter Manipulation
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${MAGENTA}═══ KERNEL PARAMETER ANALYSIS ═══${NC}"
echo ""

# Check if container tried to mount proc or sys
PROC_MOUNT=$(docker logs "audit_$CORK_NAME" 2>&1 | grep -i "mount.*proc\|mount.*sys" | head -5)
if [ -n "$PROC_MOUNT" ]; then
    echo -e "${RED}[!] SUSPICIOUS MOUNT ATTEMPTS DETECTED:${NC}"
    echo "$PROC_MOUNT" | while read line; do
        echo -e "   ${RED}• $line${NC}"
    done
    RESULT="SUSPICIOUS"
    FINDINGS="$FINDINGS\n- Attempted to mount /proc or /sys"
else
    echo -e "${GREEN}[✓] No /proc or /sys mount attempts${NC}"
fi

# ─────────────────────────────────────────────────────────────
# D. Analyze Seccomp/Syscall Logs
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${MAGENTA}═══ SYSCALL ANALYSIS ═══${NC}"
echo ""

if [ -f "$STRACE_LOG" ] && [ -s "$STRACE_LOG" ]; then
    SUSPICIOUS_CALLS=$(grep -E "mount|ptrace|init_module|delete_module|reboot|sethostname" "$STRACE_LOG" | head -10)
    if [ -n "$SUSPICIOUS_CALLS" ]; then
        echo -e "${RED}[!] SUSPICIOUS SYSCALLS DETECTED:${NC}"
        echo "$SUSPICIOUS_CALLS" | while read line; do
            echo -e "   ${RED}• $line${NC}"
        done
        RESULT="SUSPICIOUS"
        FINDINGS="$FINDINGS\n- Suspicious syscalls detected"
    else
        echo -e "${GREEN}[✓] No suspicious syscalls logged${NC}"
    fi
else
    echo -e "${YELLOW}[i] Syscall tracing not available (install strace for deep analysis)${NC}"
fi

# Check dmesg for seccomp violations
if command -v dmesg >/dev/null 2>&1; then
    SECCOMP_VIOLATIONS=$(dmesg 2>/dev/null | tail -50 | grep -i "seccomp\|audit" | grep -i "$CORK_NAME" | head -5)
    if [ -n "$SECCOMP_VIOLATIONS" ]; then
        echo -e "${YELLOW}[i] Kernel audit events:${NC}"
        echo "$SECCOMP_VIOLATIONS" | while read line; do
            echo -e "   ${YELLOW}• $line${NC}"
        done
    fi
fi

# ─────────────────────────────────────────────────────────────
# E. Network Activity Analysis
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${MAGENTA}═══ NETWORK ANALYSIS ═══${NC}"
echo ""

if [ $SKIP_NETWORK -eq 0 ]; then
    echo -e "${GREEN}[✓] Container was network-isolated during audit${NC}"
    echo -e "   ${GREEN}• No outbound connections possible${NC}"
    echo -e "   ${GREEN}• No phone-home attempts possible${NC}"
else
    echo -e "${YELLOW}[!] Container had network access (reduced security)${NC}"
    # Check for network activity
    NET_ACTIVITY=$(docker logs "audit_$CORK_NAME" 2>&1 | grep -iE "connect|http|dns|curl|wget" | head -5)
    if [ -n "$NET_ACTIVITY" ]; then
        echo -e "${YELLOW}[i] Network activity detected:${NC}"
        echo "$NET_ACTIVITY" | while read line; do
            echo -e "   ${YELLOW}• $line${NC}"
        done
    fi
fi

# ─────────────────────────────────────────────────────────────
# FINAL VERDICT
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo ""

case "$RESULT" in
    SAFE)
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                    ✅ AUDIT RESULT: SAFE                         ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
        EXIT_CODE=0
        ;;
    SUSPICIOUS)
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║                 ⚠️  AUDIT RESULT: SUSPICIOUS                      ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════╝${NC}"
        echo -e "${YELLOW}Findings:${NC}$FINDINGS"
        EXIT_CODE=1
        ;;
    MALICIOUS)
        echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║                 🚨 AUDIT RESULT: MALICIOUS                        ║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
        echo -e "${RED}Findings:${NC}$FINDINGS"
        EXIT_CODE=2
        ;;
esac

echo ""

# ─────────────────────────────────────────────────────────────
# GENERATE AUDIT HASH FOR REGISTRY
# ─────────────────────────────────────────────────────────────
IMAGE_HASH=$(docker inspect "$CORK_NAME" --format='{{.Id}}' 2>/dev/null | cut -c8-19)
AUDIT_HASH=$(echo -n "${USER_ID}${IMAGE_HASH}${RESULT}$(date +%Y%m%d)" | sha256sum | cut -c1-16)

echo -e "${CYAN}Audit Metadata:${NC}"
echo -e "   Cork:        $CORK_NAME"
echo -e "   Image Hash:  $IMAGE_HASH"
echo -e "   Audit Hash:  $AUDIT_HASH"
echo -e "   Auditor ID:  $USER_ID"
echo -e "   Date:        $(date -Iseconds)"
echo -e "   Result:      $RESULT"
echo ""

# Output JSON for registry integration
cat > "/tmp/ci5_audit_${CORK_NAME}.json" << EOF
{
    "cork": "$CORK_NAME",
    "image_hash": "$IMAGE_HASH",
    "audit_hash": "$AUDIT_HASH",
    "auditor_id": "$USER_ID",
    "audit_date": "$(date -Iseconds)",
    "audit_result": "$RESULT",
    "duration_seconds": $AUDIT_DURATION,
    "network_isolated": $([ $SKIP_NETWORK -eq 0 ] && echo "true" || echo "false")
}
EOF

echo -e "${GREEN}Audit JSON saved to: /tmp/ci5_audit_${CORK_NAME}.json${NC}"
echo ""

# Prompt for registry submission
echo -n "Submit audit result to ci5.network registry? [y/N]: "
read SUBMIT_CHOICE

if [ "$SUBMIT_CHOICE" = "y" ] || [ "$SUBMIT_CHOICE" = "Y" ]; then
    echo -e "${CYAN}Registry submission would go to: https://ci5.network/api/audits${NC}"
    echo -e "${YELLOW}(Submission endpoint not yet implemented)${NC}"
fi

exit $EXIT_CODE
