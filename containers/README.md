# Container Setup for SMTP Relay Server

This directory contains containerized infrastructure components for the SMTP Relay Server:
- **389 Directory Server**: LDAP server for user authentication
- **Keycloak**: OAuth2/OIDC provider for token-based authentication

Both services run in **rootless Podman** containers for security and ease of management.

## Prerequisites

### Install Podman

```bash
# RHEL/CentOS/Fedora
sudo dnf install podman podman-compose

# Ubuntu/Debian
sudo apt-get install podman podman-compose
```

### Verify Podman Installation

```bash
podman --version
podman info
```

### Enable Rootless Podman (if needed)

```bash
# Enable user namespaces
echo "kernel.unprivileged_userns_clone=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Configure subuid/subgid (usually done automatically)
# Check with: cat /etc/subuid
```

## Quick Start

1. **Start containers:**
   ```bash
   cd containers
   ./manage-containers.sh start
   ```

2. **Wait for services to initialize (~2 seconds for LDAP, ~30 seconds for Keycloak), then setup:**
   ```bash
   ./manage-containers.sh status
   ./manage-containers.sh setup-all
   ```

3. **Verify setup:**
   ```bash
   ./manage-containers.sh test-ldap
   ./manage-containers.sh test-keycloak
   ```

## Port Configuration

**Important**: All host ports are unprivileged (>= 1024) for rootless Podman:

- **LDAP**: Host port `3389` → Container port `389` (standard LDAP)
- **LDAPS**: Host port `3636` → Container port `636` (standard LDAPS)
- **Keycloak HTTP**: Host port `8080` → Container port `8080`
- **Keycloak HTTPS**: Host port `8443` → Container port `8443`

**Container-to-container communication** (Keycloak → LDAP):
- Uses container hostname: `ldap:3389` (container network, container port)

3. **Register a test user (LDAP + Keycloak):**
   ```bash
   ./register-user.sh john.doe@example.com "SecurePass123" "John" "Doe"
   ```

4. **Verify services:**
   ```bash
   ./manage-containers.sh test-ldap
   ./manage-containers.sh test-keycloak
   ```

## Container Details

### 389 Directory Server (LDAP)

**Container Name:** `smtp-relay-ldap`

**Ports:**
- `3389`: LDAP (plain) - official 389ds container default port
- `3636`: LDAPS (TLS) - official 389ds container default port

**Default Credentials:**
- Root DN: `cn=Directory Manager`
- Password: `changeme` (**WARNING: Change in production!**)
- Base DN: `dc=example,dc=com`

**Data Volume:** `ldap-data` (persistent)

**Access:**
```bash
# LDAP search (from host)
ldapsearch -x -H ldap://localhost:3389 \
  -b "dc=example,dc=com" \
  -D "cn=Directory Manager" \
  -w changeme

# LDAPS search (from host)
ldapsearch -x -H ldaps://localhost:3636 \
  -b "dc=example,dc=com" \
  -D "cn=Directory Manager" \
  -w changeme
```

### Keycloak (OAuth2/OIDC)

**Container Name:** `smtp-relay-keycloak`

**Ports:**
- `8080`: HTTP
- `8443`: HTTPS

**Default Credentials:**
- Admin username: `admin`
- Admin password: `admin123` (**WARNING: Change in production!**)
- Realm: `smtp-relay`

**Data Volume:** `keycloak-data` (persistent)

**Access:**
- Admin Console: http://localhost:8080/admin
- Realm: `smtp-relay`
- Client ID: `smtp-relay-client`
- Client Secret: `smtp-relay-secret`

**OAuth2 Endpoints:**
- Authorization: `http://localhost:8080/realms/smtp-relay/protocol/openid-connect/auth`
- Token: `http://localhost:8080/realms/smtp-relay/protocol/openid-connect/token`
- User Info: `http://localhost:8080/realms/smtp-relay/protocol/openid-connect/userinfo`

## Management Scripts

### manage-containers.sh

The `manage-containers.sh` script provides easy container management:

```bash
./manage-containers.sh start          # Start all containers
./manage-containers.sh stop           # Stop all containers
./manage-containers.sh restart       # Restart all containers
./manage-containers.sh status        # Show container status
./manage-containers.sh logs [service] # Show logs
./manage-containers.sh build          # Build containers (Keycloak only, LDAP uses official image)
./manage-containers.sh remove         # Remove containers and volumes
./manage-containers.sh setup-ldap         # Initialize LDAP backend and base entry
./manage-containers.sh setup-keycloak-ldap  # Configure Keycloak to use LDAP
./manage-containers.sh setup-all            # Run both setup-ldap and setup-keycloak-ldap
./manage-containers.sh test-ldap           # Test LDAP connection
./manage-containers.sh test-keycloak       # Test Keycloak connection
```

### register-user.sh

The `register-user.sh` script registers users in both LDAP and Keycloak for multi-domain support:

```bash
# Register a user
./register-user.sh <email> <password> <first_name> <last_name>

# Examples:
./register-user.sh john.doe@example.com "SecurePass123" "John" "Doe"
./register-user.sh jane.smith@company.com "SecurePass456" "Jane" "Smith"
```

**What it does:**
1. Extracts domain from email address
2. Creates LDAP backend for domain if it doesn't exist
3. Creates organizational unit `ou=users` for the domain
4. Adds user to LDAP with proper attributes
5. Registers user in Keycloak realm `smtp-relay`
6. Assigns roles: `user` and `smtp-send`

**Multi-Domain Support:**
- Automatically creates domain structure in LDAP: `dc=example,dc=com` or `dc=company,dc=com`
- Users are organized by domain in LDAP: `ou=users,dc=<domain>`
- Keycloak users are identified by email (domain extracted from email)
- SMTP server validates domain matches authenticated user's domain

## Integration with SMTP Relay Server

### LDAP Integration

The SMTP server can authenticate users against 389 Directory Server:

**LDAP Configuration:**
```python
LDAP_SERVER = "ldap://localhost:3389"  # Official 389ds container port
LDAP_BASE_DN = "dc=example,dc=com"
LDAP_BIND_DN = "cn=Directory Manager"
LDAP_BIND_PASSWORD = "changeme"
LDAP_USER_SEARCH_BASE = "ou=users,dc=example,dc=com"
LDAP_USER_FILTER = "(mail={email})"
```

**User Authentication:**
- Users are stored in `ou=users,dc=example,dc=com`
- Email addresses are stored in the `mail` attribute
- Passwords are stored in `userPassword` (hashed)

### Keycloak Integration

The SMTP server can validate OAuth2 tokens from Keycloak:

**Keycloak Configuration:**
```python
KEYCLOAK_SERVER = "http://localhost:8080"
KEYCLOAK_REALM = "smtp-relay"
KEYCLOAK_CLIENT_ID = "smtp-relay-client"
KEYCLOAK_CLIENT_SECRET = "smtp-relay-secret"
KEYCLOAK_TOKEN_ENDPOINT = f"{KEYCLOAK_SERVER}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
KEYCLOAK_USERINFO_ENDPOINT = f"{KEYCLOAK_SERVER}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
```

**OAuth2 Flow:**
1. Client authenticates with Keycloak (username/password or client credentials)
2. Keycloak issues access token
3. Client uses token in SMTP `AUTH XOAUTH2` command
4. SMTP server validates token with Keycloak
5. SMTP server extracts user/domain from token claims

### LDAP User Federation (Keycloak reads users from LDAP)

To make Keycloak see and authenticate users from LDAP:

1. **Setup LDAP backend:**
   ```bash
   ./manage-containers.sh setup-ldap
   ```

2. **Configure Keycloak LDAP Federation:**
   ```bash
   ./manage-containers.sh setup-keycloak-ldap
   ```

   Or run both at once:
   ```bash
   ./manage-containers.sh setup-all
   ```

**What this does:**
- Configures Keycloak to connect to LDAP at `ldap:3389` (container network)
- Maps LDAP users from `ou=users,dc=example,dc=com` to Keycloak realm
- Enables user import from LDAP
- Syncs existing LDAP users into Keycloak

**After setup:**
- LDAP users will be visible in Keycloak admin console
- Users can authenticate via OAuth2 using their LDAP credentials
- New users added to LDAP can be synced to Keycloak

**Manual sync:**
- In Keycloak admin console: Realm → User Federation → 389-ds → Synchronize all users

## Sample LDAP Data

After running `./manage-containers.sh setup-ldap`, the following users are created:

**User 1:**
- Email: `user1@example.com`
- Password: `password1`
- DN: `cn=user1,ou=users,dc=example,dc=com`

**User 2:**
- Email: `user2@example.com`
- Password: `password2`
- DN: `cn=user2,ou=users,dc=example,dc=com`

## Security Considerations

### Production Deployment

**WARNING:** These containers use default passwords and are configured for development/testing only.

**Before production deployment:**

1. **Change all default passwords:**
   - LDAP: Update `ds-setup.inf` and `manage-containers.sh`
   - Keycloak: Change admin password via web console

2. **Enable TLS/SSL:**
   - LDAP: Use LDAPS (port 636) with proper certificates
   - Keycloak: Enable HTTPS (port 8443) with proper certificates

3. **Network Security:**
   - Use firewall rules to restrict access
   - Consider using Podman networks for internal communication only
   - Expose ports only to necessary services

4. **Data Persistence:**
   - Backup volumes regularly
   - Use encrypted volumes for sensitive data
   - Store credentials in secrets management system

5. **Keycloak Configuration:**
   - Use production database (PostgreSQL/MySQL) instead of dev-file
   - Enable proper CORS settings
   - Configure token expiration policies
   - Set up proper client secrets

## Troubleshooting

### Containers won't start

```bash
# Check Podman status
podman info

# Check logs
./manage-containers.sh logs

# Check if ports are in use
sudo netstat -tulpn | grep -E '389|636|8080|8443'
```

### LDAP connection issues

```bash
# Test LDAP from host
ldapsearch -x -H ldap://localhost:3389 \
  -b "dc=example,dc=com" \
  -D "cn=Directory Manager" \
  -w changeme

# Check LDAP logs
./manage-containers.sh logs ldap

# Create backend if missing
podman exec smtp-relay-ldap dsconf localhost backend create --suffix="dc=example,dc=com" --be-name="userRoot"
```

### Keycloak connection issues

```bash
# Test Keycloak health
curl http://localhost:8080/health/ready

# Check Keycloak logs
./manage-containers.sh logs keycloak

# Access admin console
# http://localhost:8080/admin
```

### Permission issues (rootless Podman)

```bash
# Check user namespaces
cat /etc/subuid
cat /etc/subgid

# Check Podman rootless setup
podman unshare cat /proc/self/uid_map
```

## Network Configuration

Containers are connected via a Podman bridge network (`smtp-relay-net`):
- Subnet: `172.20.0.0/16`
- Containers can communicate using service names (`ldap`, `keycloak`)

## Volumes

**LDAP Data:** `ldap-data`
- Location: Managed by Podman
- Contains: Directory Server instance data, databases, logs

**Keycloak Data:** `keycloak-data`
- Location: Managed by Podman
- Contains: Realm configurations, user data, keys

**List volumes:**
```bash
podman volume ls
```

**Backup volumes:**
```bash
# Backup LDAP
podman run --rm -v ldap-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/ldap-backup.tar.gz /data

# Backup Keycloak
podman run --rm -v keycloak-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/keycloak-backup.tar.gz /data
```

## Next Steps

1. **Integrate with SMTP Server:**
   - Update `multidomain_auth_handler.py` to use LDAP
   - Update `oauth2_multidomain_provider.py` to validate tokens with Keycloak

2. **Add More Users:**
   - Use LDAP tools to add users
   - Or use Keycloak admin console

3. **Configure Multi-Domain:**
   - Set up multiple LDAP organizational units per domain
   - Configure Keycloak realm mappings

4. **Production Hardening:**
   - Set up proper certificates
   - Configure firewalls
   - Enable monitoring and logging
   - Set up backups

