#!/bin/sh
# Ci5 Host Auditor - "The Lab"
# Purpose: Isolated forensic analysis of Community Corks

CORK_NAME=$1
if [ -z "$CORK_NAME" ]; then
    echo "Usage: cork audit [cork-name]"
    exit 1
fi

# 1. GENERATE SOVEREIGN IDENTITY
HW_HASH=$(cat /proc/cpuinfo | grep Serial | awk '{print $3}')
USER_ID=$(sha256sum <<EOF | cut -c1-12
$HW_HASH-ci5-auditor
EOF
)

echo "--- [Ci5 AUDIT INITIALIZED] ---"
echo "Identity: $USER_ID"
echo "Subject:  $CORK_NAME"

# 2. SNAPSHOT "BONE MARROW" (Core OS)
echo "[*] Snapshotting filesystem state..."
BEFORE_FILES=$(find /overlay/upper -type f | sort)
BEFORE_CONF=$(ls -l /etc/config/ | sha256sum)

# 3. CREATE ISOLATED CRUMPLE ZONE (Network)
echo "[*] Constructing Isolation Bridge (br-audit)..."
docker network create \
  --driver bridge \
  --opt "com.docker.network.bridge.name"="br-audit" \
  --internal \
  ci5_audit_net > /dev/null

# 4. RUN CORK IN THE LAB
echo "[*] Launching Subject in Laboratory Mode..."
# Note: We use --internal to block external WAN access by default unless monitored
docker run -d \
  --name "audit_$CORK_NAME" \
  --network ci5_audit_net \
  --label "ci5.audit.id=$USER_ID" \
  "$CORK_NAME" > /dev/null

echo "--- SUBJECT IS LIVE ---"
echo "Monitoring for 60 seconds (Press Ctrl+C to finish early)..."

# 5. REAL-TIME MONITORING (Simple loop)
# In a full build, this would pipe conntrack/tcpdump logs here
count=0
while [ $count -lt 60 ]; do
    sleep 1
    count=$((count+1))
    printf "."
done
echo ""

# 6. REVEAL TANGIBLE CHANGES
echo "--- [AUDIT REPORT: $CORK_NAME] ---"

echo "[Filesystem Changes]"
AFTER_FILES=$(find /overlay/upper -type f | sort)
DIFF=$(echo "$BEFORE_FILES" "$AFTER_FILES" | tr ' ' '\n' | sort | uniq -u)

if [ -z "$DIFF" ]; then
    echo " > No files created on host overlay."
else
    echo "$DIFF" | sed 's/^/ + /'
fi

echo "[Network Telemetry]"
# Check conntrack for the container's IP
CONT_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "audit_$CORK_NAME")
echo " > Subject IP: $CONT_IP"
CONNS=$(conntrack -L | grep "$CONT_IP")
if [ -z "$CONNS" ]; then
    echo " > Zero outbound attempts detected."
else
    echo "$CONNS" | awk '{print " + Attemted: " $6}'
fi

# 7. CLEANUP
echo "[*] Decontaminating Lab..."
docker stop "audit_$CORK_NAME" > /dev/null
docker rm "audit_$CORK_NAME" > /dev/null
docker network rm ci5_audit_net > /dev/null

echo "--- [AUDIT COMPLETE] ---"
echo "Submit result to ci5.network? (y/n)"