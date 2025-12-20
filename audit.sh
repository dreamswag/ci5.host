#!/bin/sh
# Ci5 Host Auditor (ext4-Optimized) - "CURE"
# Purpose: Detect Host-Infection attempts on non-overlay filesystems.

CORK_NAME=$1
[ -z "$CORK_NAME" ] && { echo "Usage: cork audit [cork-name]"; exit 1; }

# 1. INITIALIZE IDENTITY
USER_ID=$(cat /proc/cpuinfo | grep Serial | awk '{print $3}' | sha256sum | cut -c1-12)
LAB_DIR="/tmp/ci5_lab"
UPPER="$LAB_DIR/upper"
WORK="$LAB_DIR/work"
MERGE="$LAB_DIR/merge"

echo "--- [Ci5 AUDIT: CURE MODE] ---"
echo "ID: $USER_ID | Host: ext4-Sovereign"

# 2. PREPARE RAM-BACKED LABORATORY
# We create a temporary overlay to 'catch' write attempts to /etc
mkdir -p "$UPPER" "$WORK" "$MERGE"
mount -t tmpfs tmpfs "$LAB_DIR" -o size=50M

# Re-create structure on the tmpfs
mkdir -p "$UPPER" "$WORK" "$MERGE"

# 3. MOUNT THE SHADOW BONE-MARROW
# This maps your real /etc (lower) to a RAM-disk (upper). 
# Any changes the Cork makes will only exist in RAM.
mount -t overlay overlay -o lowerdir=/etc,upperdir="$UPPER",workdir="$WORK" "$MERGE"

echo "[*] Shadow-Mount created. Host /etc is now protected."

# 4. RUN THE CORK IN THE LAB
# We bind-mount our SHADOW /etc instead of the REAL /etc
docker run -d \
  --name "audit_$CORK_NAME" \
  -v "$MERGE":/etc:rw \
  --network bridge \
  "$CORK_NAME" > /dev/null

echo "--- SUBJECT IS LIVE IN SHADOW-NET ---"
echo "Monitoring for 30 seconds (or Ctrl+C)..."

# Monitoring Loop
i=0; while [ $i -lt 30 ]; do sleep 1; i=$((i+1)); printf "."; done
echo ""

# 5. THE REVEAL (The Forensic Diff)
echo "--- [TANGIBLE CHANGE REPORT] ---"

# A. Internal Changes (Inside Docker)
echo "[Internal Cork Changes]"
docker diff "audit_$CORK_NAME" | head -n 10

# B. Host Infection Attempts (The "CURE" Check)
# If the 'upper' directory in our RAM overlay has files, 
# it means the Cork tried to modify /etc on your host.
echo "[Host Breakout Attempts]"
BREAKOUTS=$(find "$UPPER" -type f)

if [ -z "$BREAKOUTS" ]; then
    echo " > CLEAN: No host configuration changes detected."
    RESULT="SAFE"
else
    echo " > DANGER: Cork attempted to modify these host files:"
    echo "$BREAKOUTS" | sed "s|$UPPER| /etc|g"
    RESULT="MALICIOUS"
fi

# 6. CLEANUP (Decontamination)
echo "[*] Decontaminating..."
docker stop "audit_$CORK_NAME" > /dev/null
docker rm "audit_$CORK_NAME" > /dev/null
umount "$MERGE"
umount "$LAB_DIR"
rm -rf "$LAB_DIR"

echo "--- [AUDIT COMPLETE] ---"
echo "Result: $RESULT"
echo "Log to ci5.network/cert? (y/n)"