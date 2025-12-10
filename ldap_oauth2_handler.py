#!/usr/bin/env python3
"""
LDAP OAuth2 handler for SMTP server.
Wraps LDAPOAuth2Provider for use with SMTP authentication.
"""
from ldap_oauth2_provider import LDAPOAuth2Provider

class LDAPOAuth2Handler:
    """OAuth2 handler that uses LDAP OAuth2 server for token validation."""
    
    def __init__(self, oauth2_server_url: str = "http://localhost:9000"):
        """Initialize LDAP OAuth2 handler."""
        self.oauth2_provider = LDAPOAuth2Provider(oauth2_server_url=oauth2_server_url)
    
    def validate_token(self, token: str):
        """Validate OAuth2 token."""
        return self.oauth2_provider.validate_token(token)

