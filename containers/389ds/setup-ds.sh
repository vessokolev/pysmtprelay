#!/bin/bash
set -e

INSTANCE_NAME="localhost"
SUFFIX="dc=example,dc=com"
DM_PASSWORD="${DS_DM_PASSWORD:-changeme}"

# CRITICAL: Kill ALL existing ns-slapd processes FIRST (before anything else)
# This prevents "already running" conflicts when container restarts
echo "Cleaning up any existing ns-slapd processes..."
if command -v pgrep >/dev/null 2>&1; then
    for PID in $(pgrep -f "ns-slapd" 2>/dev/null); do
        echo "Killing ns-slapd process (PID: $PID)"
        kill -9 $PID 2>/dev/null || true
    done
    sleep 2
    # Double-check - kill any remaining
    pkill -9 -f "ns-slapd" 2>/dev/null || true
    sleep 1
fi

# Create run directory for socket and fix permissions (MUST be done before server starts)
mkdir -p /var/run/dirsrv
mkdir -p /run/dirsrv
# Server runs as dirsrv user - set permissions so it can write
chown -R dirsrv:dirsrv /var/run/dirsrv 2>/dev/null || chmod 777 /var/run/dirsrv
chown -R dirsrv:dirsrv /run/dirsrv 2>/dev/null || chmod 777 /run/dirsrv
# Clean up any stale PID files or sockets from previous runs (CRITICAL - must be done as root before dirsrv user runs)
rm -f /var/run/dirsrv/*.pid /var/run/dirsrv/*.socket
rm -f /run/dirsrv/*.pid /run/dirsrv/*.socket
# Also clean up PID files in instance directory
if [ -d "/etc/dirsrv/slapd-${INSTANCE_NAME}" ]; then
    rm -f /var/lib/dirsrv/slapd-${INSTANCE_NAME}/server.pid
    rm -f /var/lib/dirsrv/slapd-${INSTANCE_NAME}/*.lock
    # Clean up any socket files that might exist
    find /var/lib/dirsrv/slapd-${INSTANCE_NAME} -name "*socket" -delete 2>/dev/null || true
    
    # CRITICAL: Clean up 389 DS lock directory (where it stores PID files for conflict detection)
    # The lockdir is typically /run/lock/dirsrv/slapd-${INSTANCE_NAME}
    LOCKDIR=$(grep "^nsslapd-lockdir:" /etc/dirsrv/slapd-${INSTANCE_NAME}/dse.ldif 2>/dev/null | awk '{print $2}' || echo "/run/lock/dirsrv/slapd-${INSTANCE_NAME}")
    if [ -n "$LOCKDIR" ]; then
        echo "Cleaning up lock directory: $LOCKDIR"
        # Create lock directory if it doesn't exist (389 DS needs it)
        mkdir -p "$LOCKDIR"/server "$LOCKDIR"/imports "$LOCKDIR"/exports 2>/dev/null || true
        # Set permissions so dirsrv user can write
        chown -R dirsrv:dirsrv "$LOCKDIR" 2>/dev/null || chmod -R 777 "$LOCKDIR" 2>/dev/null || true
        # Remove all PID files in server/, imports/, exports/ subdirectories
        rm -f "$LOCKDIR"/server/* 2>/dev/null || true
        rm -f "$LOCKDIR"/imports/* 2>/dev/null || true
        rm -f "$LOCKDIR"/exports/* 2>/dev/null || true
        # Remove the main lock file
        rm -f "$LOCKDIR"/lock 2>/dev/null || true
    fi
fi

# Kill anything on port 3389
if command -v fuser >/dev/null 2>&1; then
    fuser -k -9 3389/tcp 2>/dev/null || true
    sleep 1
fi

# Fix socket path and rundir if instance exists but uses wrong path
if [ -d "/etc/dirsrv/slapd-${INSTANCE_NAME}" ]; then
    if grep -q "/data/run" /etc/dirsrv/slapd-localhost/dse.ldif 2>/dev/null; then
        echo "Fixing socket path..."
        sed -i 's|/data/run|/var/run/dirsrv|g' /etc/dirsrv/slapd-localhost/dse.ldif 2>/dev/null || true
    fi
    # Fix rundir to use /var/run/dirsrv (which we create and have permissions for)
    if grep -q "nsslapd-rundir: /run/dirsrv" /etc/dirsrv/slapd-localhost/dse.ldif 2>/dev/null; then
        echo "Fixing rundir path..."
        sed -i 's|nsslapd-rundir: /run/dirsrv|nsslapd-rundir: /var/run/dirsrv|g' /etc/dirsrv/slapd-localhost/dse.ldif 2>/dev/null || true
    fi
fi

# Check if instance already exists
if [ -d "/etc/dirsrv/slapd-${INSTANCE_NAME}" ]; then
    echo "Instance ${INSTANCE_NAME} already exists"
    
    # FIRST: Kill ALL existing ns-slapd processes for this instance (CRITICAL - prevents conflict detection)
    echo "Checking for existing ns-slapd processes..."
    if command -v pgrep >/dev/null 2>&1; then
        # Find all ns-slapd processes (they might be from previous container start)
        for PID in $(pgrep -f "ns-slapd.*slapd-${INSTANCE_NAME}" 2>/dev/null); do
            echo "Killing existing ns-slapd process (PID: $PID)"
            kill -9 $PID 2>/dev/null || true
        done
        sleep 2
        # Verify they're gone
        REMAINING=$(pgrep -f "ns-slapd.*slapd-${INSTANCE_NAME}" 2>/dev/null | wc -l)
        if [ "$REMAINING" -gt 0 ]; then
            echo "WARNING: Still found $REMAINING ns-slapd processes, forcing kill..."
            pkill -9 -f "ns-slapd.*slapd-${INSTANCE_NAME}" 2>/dev/null || true
            sleep 2
        fi
    fi
    
    # Clean up ALL PID files, socket files, and lock files (CRITICAL - prevents conflict detection)
    rm -f /var/run/dirsrv/slapd-${INSTANCE_NAME}.pid
    rm -f /var/run/dirsrv/slapd-${INSTANCE_NAME}.socket
    rm -f /run/dirsrv/slapd-${INSTANCE_NAME}.pid
    rm -f /run/dirsrv/slapd-${INSTANCE_NAME}.socket
    rm -f /var/lib/dirsrv/slapd-${INSTANCE_NAME}/server.pid
    rm -f /var/lib/dirsrv/slapd-${INSTANCE_NAME}/*.lock
    # Clean up any socket files in the rundir
    find /var/run/dirsrv -name "*socket" -delete 2>/dev/null || true
    find /run/dirsrv -name "*socket" -delete 2>/dev/null || true
    
    # CRITICAL: Clean up 389 DS lock directory (where it stores PID files for conflict detection)
    # The lockdir is typically /run/lock/dirsrv/slapd-${INSTANCE_NAME}
    LOCKDIR=$(grep "^nsslapd-lockdir:" /etc/dirsrv/slapd-${INSTANCE_NAME}/dse.ldif 2>/dev/null | awk '{print $2}' || echo "/run/lock/dirsrv/slapd-${INSTANCE_NAME}")
    if [ -n "$LOCKDIR" ]; then
        echo "Cleaning up lock directory: $LOCKDIR"
        # Create lock directory if it doesn't exist (389 DS needs it)
        mkdir -p "$LOCKDIR"/server "$LOCKDIR"/imports "$LOCKDIR"/exports 2>/dev/null || true
        # Set permissions so dirsrv user can write
        chown -R dirsrv:dirsrv "$LOCKDIR" 2>/dev/null || chmod -R 777 "$LOCKDIR" 2>/dev/null || true
        # Remove all PID files in server/, imports/, exports/ subdirectories
        rm -f "$LOCKDIR"/server/* 2>/dev/null || true
        rm -f "$LOCKDIR"/imports/* 2>/dev/null || true
        rm -f "$LOCKDIR"/exports/* 2>/dev/null || true
        # Remove the main lock file
        rm -f "$LOCKDIR"/lock 2>/dev/null || true
    fi
    
    # Kill anything on port 3389
    if command -v fuser >/dev/null 2>&1; then
        fuser -k -9 3389/tcp 2>/dev/null || true
        sleep 2
    fi
    
    # Wait for port to be free
    for i in {1..10}; do
        if command -v ss >/dev/null 2>&1; then
            if ! ss -tlnp 2>/dev/null | grep -q ":3389 "; then
                break
            fi
        fi
        sleep 1
    done
    
    # Check if server is already running and responding
    if ldapsearch -x -H ldap://localhost:3389 -b "" -s base -LLL dn >/dev/null 2>&1; then
        echo "Server is already running and responding - keeping container alive"
        exec tail -f /var/log/dirsrv/slapd-${INSTANCE_NAME}/access
    fi
    
    
    # Wait for port to be released and verify it's free (wait longer for TIME_WAIT to clear)
    echo "Waiting for port 3389 to be released..."
    PORT_FREE=false
    for i in {1..20}; do
        if command -v ss >/dev/null 2>&1; then
            if ! ss -tlnp 2>/dev/null | grep -q ":3389 "; then
                echo "Port 3389 is free (attempt $i)"
                PORT_FREE=true
                break
            fi
        elif command -v netstat >/dev/null 2>&1; then
            if ! netstat -tlnp 2>/dev/null | grep -q ":3389 "; then
                echo "Port 3389 is free (attempt $i)"
                PORT_FREE=true
                break
            fi
        else
            # If neither ss nor netstat available, just wait
            PORT_FREE=true
            break
        fi
        echo "Port 3389 still in use, waiting... (attempt $i/20)"
        sleep 2
    done
    
    if [ "$PORT_FREE" = "false" ]; then
        echo "WARNING: Port 3389 may still be in use, but proceeding anyway"
    fi
    
    # Verify port is actually free before starting
    if command -v ss >/dev/null 2>&1; then
        if ss -tlnp 2>/dev/null | grep -q ":3389 "; then
            echo "ERROR: Port 3389 is still in use, cannot start server - exiting to prevent restart loop"
            sleep 5
            exit 1
        fi
    fi
    
    # Server not running, start it in daemon mode and monitor it
    echo "Starting 389 Directory Server..."
    PIDFILE=/var/run/dirsrv/slapd-${INSTANCE_NAME}.pid
    # CRITICAL: Remove socket file IMMEDIATELY before starting (389 DS checks for this)
    rm -f /var/run/dirsrv/slapd-${INSTANCE_NAME}.socket
    rm -f /run/dirsrv/slapd-${INSTANCE_NAME}.socket
    # Ensure PID file doesn't exist
    rm -f $PIDFILE
    # Start server
    /usr/sbin/ns-slapd -D /etc/dirsrv/slapd-${INSTANCE_NAME} -i $PIDFILE
    
    # Wait for PID file and verify server is running
    echo "Waiting for server to start (checking every 2 seconds)..."
    MAX_WAIT=60  # Maximum 60 seconds for PID file
    WAIT_COUNT=0
    while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
        if [ -f "$PIDFILE" ]; then
            SERVER_PID=$(cat $PIDFILE)
            if kill -0 $SERVER_PID 2>/dev/null; then
                echo "Server process started (PID: $SERVER_PID) - waiting for it to be ready..."
                # Wait for server to be responsive (checking every 2 seconds)
                RESPONSIVE_WAIT=0
                MAX_RESPONSIVE=30  # Maximum 30 seconds to become responsive
                while [ $RESPONSIVE_WAIT -lt $MAX_RESPONSIVE ]; do
                    if ldapsearch -x -H ldap://localhost:3389 -b "" -s base -LLL dn >/dev/null 2>&1; then
                        echo "Server is ready and responding (took $((WAIT_COUNT + RESPONSIVE_WAIT)) seconds total)"
                        # Keep container alive by monitoring the process
                        while kill -0 $SERVER_PID 2>/dev/null; do
                            sleep 5
                        done
                        echo "Server process exited"
                        exit 1
                    fi
                    sleep 2
                    RESPONSIVE_WAIT=$((RESPONSIVE_WAIT + 2))
                done
                echo "ERROR: Server process running but not responding after ${MAX_RESPONSIVE} seconds"
                exit 1
            fi
        fi
        sleep 2
        WAIT_COUNT=$((WAIT_COUNT + 2))
    done
    echo "ERROR: Server failed to start - no PID file after ${MAX_WAIT} seconds"
    cat /var/log/dirsrv/slapd-${INSTANCE_NAME}/errors | tail -10
    exit 1
fi

# Instance doesn't exist - create it
echo "Creating 389 Directory Server instance..."

cat > /tmp/ds.inf <<EOF
[general]
full_machine_name = localhost.localdomain
strict_host_checking = False

[slapd]
instance_name = ${INSTANCE_NAME}
root_dn = cn=Directory Manager
root_password = ${DM_PASSWORD}
port = 3389
secure_port = 3636
suffix = ${SUFFIX}
create_suffix_entry = True
create_sample_entries = False
EOF

dscreate from-file /tmp/ds.inf || {
    echo "dscreate failed"
    exit 1
}

# Start server in background for setup (with -i for daemon mode)
echo "Starting 389 Directory Server for setup..."
PIDFILE=/var/run/dirsrv/slapd-${INSTANCE_NAME}.pid
/usr/sbin/ns-slapd -D /etc/dirsrv/slapd-${INSTANCE_NAME} -i $PIDFILE &
SERVER_PID=$!
sleep 5

# Wait for server to be ready
echo "Waiting for server to be ready..."
for i in {1..30}; do
    if ldapsearch -x -H ldap://localhost:3389 -b "" -s base -LLL dn >/dev/null 2>&1; then
        echo "Server is ready"
        break
    fi
    sleep 2
done

# Create backend if it doesn't exist
if ! dsconf localhost backend suffix list 2>/dev/null | grep -q "${SUFFIX}"; then
    echo "Creating backend..."
    dsconf localhost backend create --be-name userRoot --suffix "${SUFFIX}" || true
    sleep 3
fi

# Create base entry if it doesn't exist
if ! ldapsearch -x -H ldap://localhost:3389 -b "${SUFFIX}" -s base -LLL dn >/dev/null 2>&1; then
    echo "Creating base entry..."
    # Extract first dc value for the dc attribute
    FIRST_DC=$(echo ${SUFFIX} | sed -n 's/.*dc=\([^,]*\).*/\1/p' | head -1)
    cat > /tmp/base.ldif <<EOF
dn: ${SUFFIX}
objectClass: top
objectClass: domain
dc: ${FIRST_DC}

dn: ou=users,${SUFFIX}
objectClass: top
objectClass: organizationalUnit
ou: users
EOF
    ldapadd -x -H ldap://localhost:3389 -D "cn=Directory Manager" -w ${DM_PASSWORD} -f /tmp/base.ldif 2>&1 || true
    sleep 2
fi

echo "389 Directory Server setup complete"
# Stop daemon mode server completely
echo "Stopping setup server..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
sleep 3

# Kill any remaining ns-slapd processes for this instance
if command -v pgrep >/dev/null 2>&1; then
    for PID in $(pgrep -f "ns-slapd.*slapd-${INSTANCE_NAME}"); do
        kill -9 $PID 2>/dev/null || true
    done
    sleep 2
fi

# Kill anything on port 3389
if command -v fuser >/dev/null 2>&1; then
    fuser -k -9 3389/tcp 2>/dev/null || true
    sleep 2
fi

rm -f $PIDFILE

# Wait for port to be completely free
echo "Waiting for port 3389 to be released..."
for i in {1..15}; do
    if command -v ss >/dev/null 2>&1; then
        if ! ss -tlnp 2>/dev/null | grep -q ":3389 "; then
            echo "Port 3389 is free"
            break
        fi
    fi
    sleep 2
done

# Start in daemon mode and monitor it
echo "Starting 389 Directory Server..."
PIDFILE=/var/run/dirsrv/slapd-${INSTANCE_NAME}.pid
# CRITICAL: Remove socket file IMMEDIATELY before starting (389 DS checks for this)
rm -f /var/run/dirsrv/slapd-${INSTANCE_NAME}.socket
rm -f /run/dirsrv/slapd-${INSTANCE_NAME}.socket
# Ensure PID file doesn't exist
rm -f $PIDFILE
# Start server
/usr/sbin/ns-slapd -D /etc/dirsrv/slapd-${INSTANCE_NAME} -i $PIDFILE

# Wait for PID file and verify server is running
echo "Waiting for server to start..."
for i in {1..30}; do
    if [ -f "$PIDFILE" ]; then
        SERVER_PID=$(cat $PIDFILE)
        if kill -0 $SERVER_PID 2>/dev/null; then
            echo "Server started (PID: $SERVER_PID)"
            # Wait for server to be responsive
            for j in {1..15}; do
                if ldapsearch -x -H ldap://localhost:3389 -b "" -s base -LLL dn >/dev/null 2>&1; then
                    echo "Server is ready and responding"
                    break
                fi
                sleep 1
            done
            # Keep container alive by monitoring the process
            while kill -0 $SERVER_PID 2>/dev/null; do
                sleep 5
            done
            echo "Server process exited"
            exit 1
        fi
    fi
    sleep 1
done
echo "ERROR: Server failed to start"
exit 1
