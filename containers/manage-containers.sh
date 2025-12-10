#!/bin/bash
# Management script for SMTP Relay Server containers
# Uses Podman in rootless mode

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if podman is installed
if ! command -v podman &> /dev/null; then
    echo -e "${RED}Error: podman is not installed${NC}"
    echo "Install with: dnf install podman podman-compose"
    exit 1
fi

# Check if podman-compose is available
if ! command -v podman-compose &> /dev/null && ! podman compose version &> /dev/null; then
    echo -e "${YELLOW}Warning: podman-compose not found. Using podman compose instead.${NC}"
    COMPOSE_CMD="podman compose"
else
    COMPOSE_CMD="podman-compose"
fi

# Functions
start_containers() {
    echo -e "${GREEN}Starting containers...${NC}"
    $COMPOSE_CMD up -d
    echo -e "${GREEN}Containers started${NC}"
    echo ""
    echo "LDAP Server:"
    echo "  - LDAP: ldap://localhost:3389"
    echo "  - LDAPS: ldaps://localhost:3636"
    echo ""
    echo "OAuth2 Server:"
    echo "  - HTTP: http://localhost:9000"
    echo "  - Authorization: http://localhost:9000/oauth2/authorize"
    echo ""
    show_status
}

stop_containers() {
    echo -e "${YELLOW}Stopping containers...${NC}"
    $COMPOSE_CMD down
    echo -e "${GREEN}Containers stopped${NC}"
}

restart_containers() {
    echo -e "${YELLOW}Restarting containers...${NC}"
    $COMPOSE_CMD restart
    echo -e "${GREEN}Containers restarted${NC}"
    show_status
}

show_status() {
    echo -e "${GREEN}Container Status:${NC}"
    podman ps --filter "name=smtp-relay" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""
}

show_logs() {
    local service=${1:-""}
    if [ -z "$service" ]; then
        echo -e "${GREEN}Showing logs for all containers...${NC}"
        $COMPOSE_CMD logs -f
    else
        echo -e "${GREEN}Showing logs for $service...${NC}"
        $COMPOSE_CMD logs -f "$service"
    fi
}

build_containers() {
    echo -e "${GREEN}Building containers...${NC}"
    $COMPOSE_CMD build --no-cache
    echo -e "${GREEN}Containers built${NC}"
}

remove_containers() {
    echo -e "${RED}Removing containers and volumes...${NC}"
    read -p "This will delete all data. Continue? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        $COMPOSE_CMD down -v
        echo -e "${GREEN}Containers and volumes removed${NC}"
    else
        echo "Cancelled"
    fi
}

setup_ldap() {
    echo -e "${GREEN}Setting up LDAP with initial data...${NC}"
    
    # Wait for LDAP to be ready (container uses port 389 internally)
    echo "Waiting for LDAP server to be ready..."
    MAX_WAIT=120
    WAIT_COUNT=0
    while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
        if podman exec smtp-relay-ldap ldapsearch -x -H ldap://localhost:3389 -b "dc=example,dc=com" -D "cn=Directory Manager" -w changeme -LLL dn 2>/dev/null | grep -q "dc=example,dc=com"; then
            echo "LDAP server is ready"
            break
        fi
        sleep 2
        WAIT_COUNT=$((WAIT_COUNT + 2))
        echo -n "."
    done
    echo ""
    
    if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
        echo -e "${RED}LDAP did not become ready${NC}"
        return 1
    fi
    
    # Check if backend exists
    BACKEND_EXISTS=$(podman exec smtp-relay-ldap dsconf localhost backend suffix list 2>/dev/null | grep -c "dc=example,dc=com" || echo "0")
    
    if [ "$BACKEND_EXISTS" -eq "0" ]; then
        echo "Creating LDAP backend..."
        podman exec smtp-relay-ldap dsconf localhost backend create --suffix "dc=example,dc=com" --be-name "userRoot" 2>&1 || true
        sleep 2
    fi
    
    # Add organizational units
    echo "Adding organizational structure..."
    podman exec -i smtp-relay-ldap ldapadd -x -H ldap://localhost:3389 -D "cn=Directory Manager" -w changeme 2>&1 <<EOF || true
dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: ou=users,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: users
EOF
    
    echo -e "${GREEN}LDAP setup complete${NC}"
}

test_ldap() {
    echo -e "${GREEN}Testing LDAP connection...${NC}"
    echo "Testing from inside container (container port 389):"
    podman exec smtp-relay-ldap ldapsearch -x -H ldap://localhost:3389 -b "dc=example,dc=com" -D "cn=Directory Manager" -w changeme -LLL dn 2>/dev/null | head -10 || echo "Connection failed"
    echo ""
    echo "Testing from host (host port 3389 -> container 389):"
    ldapsearch -x -H ldap://localhost:3389 -b "dc=example,dc=com" -D "cn=Directory Manager" -w changeme -LLL dn 2>/dev/null | head -10 || echo "Note: Install openldap-clients on host to test from outside container"
}

# Main menu
case "${1:-}" in
    start)
        start_containers
        ;;
    stop)
        stop_containers
        ;;
    restart)
        restart_containers
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "$2"
        ;;
    build)
        build_containers
        ;;
    remove)
        remove_containers
        ;;
    setup-ldap)
        setup_ldap
        ;;
    test-ldap)
        test_ldap
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|build|remove|setup-ldap|test-ldap}"
        echo ""
        echo "Commands:"
        echo "  start              - Start all containers"
        echo "  stop               - Stop all containers"
        echo "  restart            - Restart all containers"
        echo "  status             - Show container status"
        echo "  logs [service]     - Show logs (optionally for specific service)"
        echo "  build              - Build containers"
        echo "  remove             - Remove containers and volumes"
        echo "  setup-ldap         - Initialize LDAP backend and base entry"
        echo "  test-ldap          - Test LDAP connection"
        exit 1
        ;;
esac

