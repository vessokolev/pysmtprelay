#!/usr/bin/env python3
"""
LDAP OAuth2 provider for SMTP server.
Validates OAuth2 tokens issued by the LDAP OAuth2 authorization server.
"""
import requests
import time
from typing import Optional, Dict, Any

class LDAPOAuth2Provider:
    """OAuth2 provider that validates tokens from LDAP OAuth2 server."""
    
    def __init__(self, oauth2_server_url: str):
        """
        Initialize LDAP OAuth2 provider.
        
        Args:
            oauth2_server_url: Base URL of OAuth2 server (e.g., http://localhost:9000)
        """
        self.oauth2_server_url = oauth2_server_url.rstrip('/')
        self.userinfo_url = f"{self.oauth2_server_url}/oauth2/userinfo"
        
        # Token cache
        self._token_cache = {}  # {token: (info, expires_at)}
        self._cache_ttl = 300  # 5 minutes
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate OAuth2 token from LDAP OAuth2 server.
        
        Returns:
            Token info dict with 'user' (email) and 'domain', or None if invalid
        """
        # Check cache first
        if token in self._token_cache:
            info, expires_at = self._token_cache[token]
            if time.time() < expires_at:
                return info
            else:
                del self._token_cache[token]
        
        # Validate via userinfo endpoint
        try:
            response = requests.get(
                self.userinfo_url,
                headers={'Authorization': f'Bearer {token}'},
                timeout=5
            )
            
            if response.status_code != 200:
                return None
            
            data = response.json()
            email = data.get('email') or data.get('sub')
            
            if not email:
                return None
            
            # Extract domain
            domain = email.split('@', 1)[1].lower() if '@' in email else None
            
            token_info = {
                'user': email,
                'domain': domain,
                'scope': 'smtp.send'
            }
            
            # Cache the result
            self._token_cache[token] = (token_info, time.time() + self._cache_ttl)
            
            return token_info
        except Exception as e:
            return None
    
    def is_domain_enabled(self, domain: str) -> bool:
        """Check if domain is enabled (always true - domain validation is in token)."""
        return True

