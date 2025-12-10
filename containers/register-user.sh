#!/bin/bash
# register-user.sh - Register user in both LDAP and Keycloak for multi-domain SMTP relay

set -e

if [ $# -lt 4 ]; then
    echo "Usage: $0 <email> <password> <first_name> <last_name>"
    echo "Example: $0 john.doe@example.com 'SecurePass123' 'John' 'Doe'"
    exit 1
fi

EMAIL=$1
PASSWORD=$2
FIRST_NAME=$3
LAST_NAME=$4

# Extract domain and username from email
DOMAIN=$(echo $EMAIL | cut -d@ -f2)
USERNAME=$(echo $EMAIL | cut -d@ -f1)

# Convert domain to LDAP DN format (example.com -> dc=example,dc=com)
LDAP_DN=$(echo $DOMAIN | sed 's/\./,dc=/g' | sed 's/^/dc=/')

echo "Registering user: $EMAIL"
echo "Domain: $DOMAIN"
echo "LDAP DN: $LDAP_DN"
echo ""

# 1. Register in LDAP (389 Directory Server)
echo "Step 1: Registering in LDAP..."

# Check if domain backend exists, create if not
if ! podman exec smtp-relay-ldap dsconf localhost backend suffix list 2>&1 | grep -q "$LDAP_DN"; then
    echo "Creating backend for domain: $LDAP_DN"
    podman exec smtp-relay-ldap dsconf localhost backend create --suffix="$LDAP_DN" --be-name="userRoot_${DOMAIN//./_}"
    sleep 2
    
    # Create base entry (container uses port 389 internally)
    podman exec -i smtp-relay-ldap ldapadd -x -H ldap://localhost:3389 \
        -D "cn=Directory Manager" \
        -w changeme <<EOF
dn: $LDAP_DN
objectClass: domain
$(echo $LDAP_DN | sed 's/dc=\([^,]*\),*/dc: \1\n/g' | head -1)
EOF
    
    # Create users OU (container uses port 389 internally)
    podman exec -i smtp-relay-ldap ldapadd -x -H ldap://localhost:3389 \
        -D "cn=Directory Manager" \
        -w changeme <<EOF
dn: ou=users,$LDAP_DN
objectClass: organizationalUnit
ou: users
EOF
fi

# Get next UID
LAST_UID=$(podman exec smtp-relay-ldap ldapsearch -x -H ldap://localhost:3389 \
    -b "ou=users,$LDAP_DN" \
    -D "cn=Directory Manager" \
    -w changeme 2>/dev/null | grep uidNumber | awk '{print $2}' | sort -n | tail -1)

if [ -z "$LAST_UID" ]; then
    NEXT_UID=1000
else
    NEXT_UID=$((LAST_UID + 1))
fi

# Add user to LDAP
podman exec -i smtp-relay-ldap ldapadd -x -H ldap://localhost:3389 \
    -D "cn=Directory Manager" \
    -w changeme <<EOF
dn: cn=${USERNAME},ou=users,$LDAP_DN
objectClass: inetOrgPerson
objectClass: posixAccount
cn: ${USERNAME}
sn: ${LAST_NAME}
givenName: ${FIRST_NAME}
uid: ${USERNAME}
mail: ${EMAIL}
userPassword: ${PASSWORD}
uidNumber: ${NEXT_UID}
gidNumber: 1000
homeDirectory: /home/${USERNAME}
EOF

echo "  [OK] User added to LDAP"
echo ""

# 2. Register in Keycloak for OAuth2
echo "Step 2: Registering in Keycloak..."

# Get admin access token
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
    -d "grant_type=password" \
    -d "client_id=admin-cli" \
    -d "username=admin" \
    -d "password=admin123" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" == "None" ]; then
    echo "  [ERROR] Failed to get admin token. Is Keycloak running?"
    exit 1
fi

# Create user in Keycloak
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST http://localhost:8080/admin/realms/smtp-relay/users \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"username\": \"${EMAIL}\",
        \"email\": \"${EMAIL}\",
        \"firstName\": \"${FIRST_NAME}\",
        \"lastName\": \"${LAST_NAME}\",
        \"enabled\": true,
        \"emailVerified\": true,
        \"credentials\": [{
            \"type\": \"password\",
            \"value\": \"${PASSWORD}\",
            \"temporary\": false
        }],
        \"realmRoles\": [\"user\", \"smtp-send\"]
    }")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" == "201" ]; then
    echo "  [OK] User added to Keycloak"
elif [ "$HTTP_CODE" == "409" ]; then
    echo "  [WARN] User already exists in Keycloak, updating..."
    # Get user ID and update
    USER_ID=$(curl -s -X GET "http://localhost:8080/admin/realms/smtp-relay/users?username=${EMAIL}" \
        -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -c "import sys, json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)
    
    if [ -n "$USER_ID" ] && [ "$USER_ID" != "None" ]; then
        curl -s -X PUT "http://localhost:8080/admin/realms/smtp-relay/users/${USER_ID}" \
            -H "Authorization: Bearer $ADMIN_TOKEN" \
            -H "Content-Type: application/json" \
            -d "{
                \"email\": \"${EMAIL}\",
                \"firstName\": \"${FIRST_NAME}\",
                \"lastName\": \"${LAST_NAME}\",
                \"enabled\": true,
                \"emailVerified\": true
            }" > /dev/null
        echo "  [OK] User updated in Keycloak"
    fi
else
    echo "  [ERROR] Failed to add user to Keycloak: HTTP $HTTP_CODE"
    echo "$BODY"
    exit 1
fi

echo ""
echo "=== Registration Complete ==="
echo "User: $EMAIL"
echo "Domain: $DOMAIN"
echo ""
echo "LDAP: cn=${USERNAME},ou=users,$LDAP_DN"
echo "Keycloak: Realm 'smtp-relay', Username '${EMAIL}'"
echo ""
echo "Test authentication:"
echo "  LDAP (from host): ldapsearch -x -H ldap://localhost:3389 -b \"$LDAP_DN\" -D \"cn=${USERNAME},ou=users,$LDAP_DN\" -w '${PASSWORD}'"
echo "  OAuth2: curl -X POST http://localhost:8080/realms/smtp-relay/protocol/openid-connect/token -d 'grant_type=password&client_id=smtp-relay-client&client_secret=smtp-relay-secret&username=${EMAIL}&password=${PASSWORD}'"

