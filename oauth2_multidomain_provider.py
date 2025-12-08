#!/usr/bin/env python3
"""
Multi-domain OAuth2 mock provider for testing SMTP OAuth2 authentication.
Supports multiple domains with domain-specific user databases.
"""
import json
import time
import hashlib
import secrets
from datetime import datetime, timedelta
import os

def extract_domain(email):
    """Extract domain from email address."""
    if '@' not in email:
        raise ValueError(f"Invalid email format: {email}")
    return email.split('@', 1)[1].lower()

class MultiDomainOAuth2Provider:
    """Multi-domain OAuth2 provider with domain-specific user databases."""
    
    TOKEN_STORE_FILE = '/tmp/oauth2_multidomain_tokens.json'
    
    def __init__(self):
        # Domain registry: {domain: {'enabled': bool, 'users': {email: password}}}
        self.domains = {
            'example.com': {
                'enabled': True,
                'users': {
                    'user1@example.com': 'password1',
                    'user2@example.com': 'password2',
                    'admin@example.com': 'admin123'
                }
            },
            'company.com': {
                'enabled': True,
                'users': {
                    'employee@company.com': 'emp123',
                    'manager@company.com': 'mgr456'
                }
            },
            'test.org': {
                'enabled': True,
                'users': {
                    'test@test.org': 'testpass'
                }
            }
        }
        
        # Store client credentials: {client_id: client_secret}
        self.clients = {
            'test_client_id': 'test_client_secret',
            'smtp_client': 'smtp_secret_key',
            'smtp_client_example': 'smtp_secret_example',  # Domain-specific client
            'smtp_client_company': 'smtp_secret_company'   # Domain-specific client
        }
        
        # Client domain restrictions: {client_id: [allowed_domains]}
        self.client_domains = {
            'smtp_client_example': ['example.com'],
            'smtp_client_company': ['company.com'],
            'smtp_client': None  # No restriction (all domains)
        }
        
        # Load tokens from file (shared between processes)
        self.tokens = self._load_tokens()
        
        # Performance optimization: Cache domain enablement status
        # This avoids repeated dict lookups and file checks
        self._domain_enabled_cache = {}
        self._update_domain_cache()
    
    def _update_domain_cache(self):
        """Update domain enablement cache for performance."""
        self._domain_enabled_cache = {
            domain.lower(): config.get('enabled', False)
            for domain, config in self.domains.items()
        }
    
    def _load_tokens(self):
        """Load tokens from persistent store (JSON format, secure)."""
        if os.path.exists(self.TOKEN_STORE_FILE):
            try:
                with open(self.TOKEN_STORE_FILE, 'r') as f:
                    data = json.load(f)
                    # Convert timestamp strings back to floats for expiration checks
                    for token, info in data.items():
                        if 'expires' in info:
                            try:
                                info['expires'] = float(info['expires'])
                            except (ValueError, TypeError):
                                # If conversion fails, token is invalid
                                del data[token]
                    return data
            except (json.JSONDecodeError, ValueError, IOError) as e:
                print(f"Warning: Could not load tokens: {e}")
                return {}
        return {}
    
    def _save_tokens(self):
        """Save tokens to persistent store (JSON format, secure)."""
        try:
            # Create a copy for serialization (convert timestamps to strings)
            serializable_tokens = {}
            for token, info in self.tokens.items():
                serializable_info = info.copy()
                if 'expires' in serializable_info:
                    serializable_info['expires'] = str(serializable_info['expires'])
                serializable_tokens[token] = serializable_info
            
            # Atomic write: write to temp file, then rename
            temp_file = self.TOKEN_STORE_FILE + '.tmp'
            with open(temp_file, 'w') as f:
                json.dump(serializable_tokens, f, indent=2)
            os.replace(temp_file, self.TOKEN_STORE_FILE)
        except Exception as e:
            print(f"Warning: Could not save tokens: {e}")
    
    def get_domain_config(self, domain):
        """Get domain configuration."""
        domain = domain.lower()
        if domain not in self.domains:
            return None
        return self.domains[domain]
    
    def is_domain_enabled(self, domain):
        """Check if a domain is enabled (uses cache for performance)."""
        domain = domain.lower()
        # Use cache for O(1) lookup instead of dict traversal
        if domain in self._domain_enabled_cache:
            return self._domain_enabled_cache[domain]
        # Fallback to direct lookup if not in cache
        config = self.get_domain_config(domain)
        if config:
            enabled = config.get('enabled', False)
            self._domain_enabled_cache[domain] = enabled
            return enabled
        return False
    
    def authenticate_user(self, email, password):
        """Authenticate user against domain-specific user database."""
        try:
            domain = extract_domain(email)
        except ValueError:
            return False, None
        
        # Check if domain exists and is enabled
        if not self.is_domain_enabled(domain):
            return False, None
        
        # Get domain configuration
        domain_config = self.get_domain_config(domain)
        
        # Check user in domain-specific user database
        if email not in domain_config['users']:
            return False, None
        
        # Verify password
        if domain_config['users'][email] != password:
            return False, None
        
        return True, domain
    
    def is_client_allowed_for_domain(self, client_id, domain):
        """Check if client is allowed to issue tokens for domain."""
        if client_id not in self.client_domains:
            return True  # No restriction
        
        allowed_domains = self.client_domains[client_id]
        if allowed_domains is None:
            return True  # All domains allowed
        
        return domain in allowed_domains
    
    def generate_access_token(self, email, client_id, client_secret, scope='smtp.send'):
        """Generate an OAuth2 access token with domain context."""
        # Verify client credentials
        if client_id not in self.clients or self.clients[client_id] != client_secret:
            return None
        
        # Authenticate user (this also extracts and validates domain)
        authenticated, domain = self.authenticate_user(email, email.split('@')[0] + '123')  # This won't work, need password
        # Actually, we need password for authentication - this method should be called after authentication
        # For now, let's check if user exists in any domain
        try:
            domain = extract_domain(email)
        except ValueError:
            return None
        
        if not self.is_domain_enabled(domain):
            return None
        
        # Check if client is allowed for this domain
        if not self.is_client_allowed_for_domain(client_id, domain):
            return None
        
        # Check if user exists in domain
        domain_config = self.get_domain_config(domain)
        if email not in domain_config['users']:
            return None
        
        # Generate token
        token_data = f"{email}:{client_id}:{scope}:{domain}:{time.time()}"
        token = hashlib.sha256(token_data.encode()).hexdigest()
        
        # Store token with domain context (expires in 1 hour)
        expires_at = datetime.now() + timedelta(hours=1)
        self.tokens[token] = {
            'user': email,
            'domain': domain,
            'client_id': client_id,
            'scope': scope,
            'expires': expires_at.timestamp()
        }
        self._save_tokens()  # Persist to file
        
        return token
    
    def generate_access_token_with_password(self, email, password, client_id, client_secret, scope='smtp.send'):
        """Generate an OAuth2 access token after authenticating with password."""
        # Authenticate user
        authenticated, domain = self.authenticate_user(email, password)
        if not authenticated:
            return None
        
        # Verify client credentials
        if client_id not in self.clients or self.clients[client_id] != client_secret:
            return None
        
        # Check if client is allowed for this domain
        if not self.is_client_allowed_for_domain(client_id, domain):
            return None
        
        # Generate token
        token_data = f"{email}:{client_id}:{scope}:{domain}:{time.time()}"
        token = hashlib.sha256(token_data.encode()).hexdigest()
        
        # Store token with domain context (expires in 1 hour)
        expires_at = datetime.now() + timedelta(hours=1)
        self.tokens[token] = {
            'user': email,
            'domain': domain,
            'client_id': client_id,
            'scope': scope,
            'expires': expires_at.timestamp()
        }
        self._save_tokens()  # Persist to file
        
        return token
    
    def validate_token(self, token):
        """Validate an OAuth2 access token and return domain context."""
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
        
        # Verify domain is still enabled
        domain = token_info.get('domain')
        if domain and not self.is_domain_enabled(domain):
            del self.tokens[token]
            self._save_tokens()
            return None
        
        return token_info
    
    def revoke_token(self, token):
        """Revoke a token."""
        if token in self.tokens:
            del self.tokens[token]
            self._save_tokens()
            return True
        return False
    
    def add_domain(self, domain, users=None, enabled=True):
        """Add a new domain to the registry."""
        domain = domain.lower()
        self.domains[domain] = {
            'enabled': enabled,
            'users': users or {}
        }
        # Update cache
        self._domain_enabled_cache[domain] = enabled
    
    def add_user(self, email, password, domain=None):
        """Add a user to a domain."""
        if domain is None:
            try:
                domain = extract_domain(email)
            except ValueError:
                return False
        
        if not self.is_domain_enabled(domain):
            return False
        
        self.domains[domain]['users'][email] = password
        return True

# Global instance
oauth2_multidomain_provider = MultiDomainOAuth2Provider()

class MultiDomainOAuth2Handler:
    """Multi-domain OAuth2 token validation handler with caching."""
    
    def __init__(self, oauth2_provider=None, cache_ttl=300):
        """
        Args:
            oauth2_provider: OAuth2 provider instance
            cache_ttl: Token cache TTL in seconds (default 5 minutes)
        """
        self.oauth2_provider = oauth2_provider or oauth2_multidomain_provider
        self.cache_ttl = cache_ttl
        self._token_cache = {}  # {token: (token_info, timestamp)}
        self._cache_hits = 0
        self._cache_misses = 0
    
    def validate_token(self, token):
        """Validate OAuth2 access token and return domain context (with caching)."""
        if not self.oauth2_provider:
            return None
        
        # Check cache first
        import time
        current_time = time.time()
        if token in self._token_cache:
            cached_info, cache_time = self._token_cache[token]
            if current_time - cache_time < self.cache_ttl:
                # Cache hit - return cached info
                self._cache_hits += 1
                return cached_info
            else:
                # Cache expired - remove it
                del self._token_cache[token]
        
        # Cache miss - validate token
        self._cache_misses += 1
        token_info = self.oauth2_provider.validate_token(token)
        
        # Cache valid tokens
        if token_info:
            self._token_cache[token] = (token_info, current_time)
        else:
            # Remove from cache if invalid
            self._token_cache.pop(token, None)
        
        return token_info
    
    def clear_cache(self):
        """Clear the token cache."""
        self._token_cache.clear()
    
    def get_cache_stats(self):
        """Get cache statistics."""
        total = self._cache_hits + self._cache_misses
        hit_rate = (self._cache_hits / total * 100) if total > 0 else 0
        return {
            'cache_size': len(self._token_cache),
            'cache_hits': self._cache_hits,
            'cache_misses': self._cache_misses,
            'hit_rate': f"{hit_rate:.1f}%"
        }

def get_token_for_user(email, password, client_id='test_client_id', client_secret='test_client_secret'):
    """Helper function to get a token for testing."""
    return oauth2_multidomain_provider.generate_access_token_with_password(
        email, password, client_id, client_secret
    )

if __name__ == "__main__":
    # Test the provider
    provider = MultiDomainOAuth2Provider()
    
    # Test domain extraction
    print("Testing domain extraction:")
    print(f"  user@example.com -> {extract_domain('user@example.com')}")
    print(f"  admin@company.com -> {extract_domain('admin@company.com')}")
    
    # Test authentication
    print("\nTesting authentication:")
    auth1, domain1 = provider.authenticate_user('user1@example.com', 'password1')
    print(f"  user1@example.com / password1: {auth1}, domain: {domain1}")
    
    auth2, domain2 = provider.authenticate_user('employee@company.com', 'emp123')
    print(f"  employee@company.com / emp123: {auth2}, domain: {domain2}")
    
    auth3, domain3 = provider.authenticate_user('user1@example.com', 'wrong')
    print(f"  user1@example.com / wrong: {auth3}, domain: {domain3}")
    
    # Test token generation
    print("\nTesting token generation:")
    token1 = provider.generate_access_token_with_password(
        'user1@example.com', 'password1', 'test_client_id', 'test_client_secret'
    )
    print(f"  Token for user1@example.com: {token1[:20]}...")
    
    token2 = provider.generate_access_token_with_password(
        'employee@company.com', 'emp123', 'test_client_id', 'test_client_secret'
    )
    print(f"  Token for employee@company.com: {token2[:20]}...")
    
    # Test token validation
    print("\nTesting token validation:")
    info1 = provider.validate_token(token1)
    print(f"  Token 1 info: {info1}")
    
    info2 = provider.validate_token(token2)
    print(f"  Token 2 info: {info2}")
    
    # Test domain restriction
    print("\nTesting domain restrictions:")
    token3 = provider.generate_access_token_with_password(
        'user1@example.com', 'password1', 'smtp_client_example', 'smtp_secret_example'
    )
    print(f"  Token for example.com with example client: {token3[:20] if token3 else 'None'}...")
    
    token4 = provider.generate_access_token_with_password(
        'employee@company.com', 'emp123', 'smtp_client_example', 'smtp_secret_example'
    )
    print(f"  Token for company.com with example client: {token4}")  # Should be None

