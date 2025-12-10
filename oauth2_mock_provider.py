#!/usr/bin/env python3
"""
Simple OAuth2 mock provider for testing SMTP OAuth2 authentication.
This is a primitive infrastructure for testing purposes only.
"""
import json
import time
import hashlib
import secrets
from datetime import datetime, timedelta

import os
import pickle

class OAuth2MockProvider:
    """Simple mock OAuth2 provider for testing."""
    
    TOKEN_STORE_FILE = '/tmp/oauth2_tokens.pkl'
    
    def __init__(self):
        # Store client credentials: {client_id: client_secret}
        self.clients = {
            'test_client_id': 'test_client_secret',
            'smtp_client': 'smtp_secret_key'
        }
        # Store user authorizations: {email: {'client_id': client_id, 'scope': scope}}
        self.authorizations = {
            'testuser@example.com': {
                'client_id': 'test_client_id',
                'scope': 'smtp.send'
            }
        }
        # Load tokens from file (shared between processes)
        self.tokens = self._load_tokens()
    
    def _load_tokens(self):
        """Load tokens from persistent store."""
        if os.path.exists(self.TOKEN_STORE_FILE):
            try:
                with open(self.TOKEN_STORE_FILE, 'rb') as f:
                    return pickle.load(f)
            except:
                return {}
        return {}
    
    def _save_tokens(self):
        """Save tokens to persistent store."""
        try:
            with open(self.TOKEN_STORE_FILE, 'wb') as f:
                pickle.dump(self.tokens, f)
        except Exception as e:
            print(f"Warning: Could not save tokens: {e}")
    
    def generate_access_token(self, email, client_id, client_secret, scope='smtp.send'):
        """Generate an OAuth2 access token."""
        # Verify client credentials
        if client_id not in self.clients or self.clients[client_id] != client_secret:
            return None
        
        # Check if user is authorized
        if email not in self.authorizations:
            return None
        
        # Generate token
        token_data = f"{email}:{client_id}:{scope}:{time.time()}"
        token = hashlib.sha256(token_data.encode()).hexdigest()
        
        # Store token (expires in 1 hour)
        expires_at = datetime.now() + timedelta(hours=1)
        self.tokens[token] = {
            'user': email,
            'client_id': client_id,
            'scope': scope,
            'expires': expires_at.timestamp()
        }
        self._save_tokens()  # Persist to file
        
        return token
    
    def validate_token(self, token):
        """Validate an OAuth2 access token."""
        # Reload tokens from file (in case another process created them)
        self.tokens = self._load_tokens()
        
        if token not in self.tokens:
            return None
        
        token_info = self.tokens[token]
        
        # Check expiration
        if time.time() > token_info['expires']:
            del self.tokens[token]
            self._save_tokens()
            return None
        
        return token_info
    
    def revoke_token(self, token):
        """Revoke a token."""
        if token in self.tokens:
            del self.tokens[token]
            return True
        return False

# Global instance
oauth2_provider = OAuth2MockProvider()

def get_token_for_user(email, client_id='test_client_id', client_secret='test_client_secret'):
    """Helper function to get a token for testing."""
    return oauth2_provider.generate_access_token(email, client_id, client_secret)

if __name__ == "__main__":
    # Test the provider
    provider = OAuth2MockProvider()
    
    # Generate a token
    token = provider.generate_access_token('testuser@example.com', 'test_client_id', 'test_client_secret')
    print(f"Generated token: {token}")
    
    # Validate token
    info = provider.validate_token(token)
    print(f"Token info: {info}")
    
    # Test invalid token
    invalid_info = provider.validate_token('invalid_token')
    print(f"Invalid token result: {invalid_info}")

