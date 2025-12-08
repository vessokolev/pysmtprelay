#!/usr/bin/env python3
"""
Multi-domain authentication handler for SMTP server.
Supports domain extraction and routing to domain-specific user databases.

Note: In production, authentication will be delegated to LDAP over SSL.
This file-based handler is for development/testing only.
"""
import os

def extract_domain(email):
    """Extract domain from email address."""
    if '@' not in email:
        raise ValueError(f"Invalid email format: {email}")
    return email.split('@', 1)[1].lower()

class MultiDomainUserAuthHandler:
    """Multi-domain authentication handler using domain-specific user files.
    
    Note: For production use, this will be replaced with LDAP integration.
    Passwords are stored in plaintext for development/testing only.
    """
    
    def __init__(self, users_dir="users", default_users_file="users.txt"):
        self.users_dir = users_dir
        self.default_users_file = default_users_file
        self.users = {}  # {email: password}
        self.domain_users = {}  # {domain: {email: password}}
        self._domain_cache = {}  # Performance: Cache domain->users mapping
        os.makedirs(self.users_dir, exist_ok=True)
        self.load_users()
    
    def load_users(self):
        """Load users from domain-specific files."""
        # Load default users file (if exists)
        if os.path.exists(self.default_users_file):
            self._load_users_from_file(self.default_users_file)
        
        # Load domain-specific user files
        if os.path.exists(self.users_dir):
            for filename in os.listdir(self.users_dir):
                if filename.endswith('.txt'):
                    domain = filename[:-4]  # Remove .txt extension
                    filepath = os.path.join(self.users_dir, filename)
                    self._load_domain_users(domain, filepath)
    
    def _load_users_from_file(self, filepath):
        """Load users from a single file."""
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    username, password = line.split(':', 1)
                    self.users[username] = password
                    
                    # Also add to domain-specific storage
                    try:
                        domain = extract_domain(username)
                        if domain not in self.domain_users:
                            self.domain_users[domain] = {}
                        self.domain_users[domain][username] = password
                    except ValueError:
                        pass  # Skip invalid emails
    
    def _load_domain_users(self, domain, filepath):
        """Load users for a specific domain."""
        if domain not in self.domain_users:
            self.domain_users[domain] = {}
        
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    username, password = line.split(':', 1)
                    # Verify username belongs to this domain
                    try:
                        user_domain = extract_domain(username)
                        if user_domain == domain:
                            self.domain_users[domain][username] = password
                            self.users[username] = password
                    except ValueError:
                        pass  # Skip invalid emails
        
        # Update domain cache after loading
        if domain in self.domain_users:
            self._domain_cache[domain] = self.domain_users[domain]
    
    def authenticate(self, email, password):
        """Authenticate user against domain-specific database.
        
        Note: In production, this will delegate to LDAP over SSL.
        
        Optimized with domain cache for O(1) domain lookup.
        
        Args:
            email: User email address
            password: Plaintext password to verify
            
        Returns:
            (bool, domain): (True, domain) if authenticated, (False, None) otherwise
        """
        # Extract domain (cached for performance)
        try:
            domain = extract_domain(email)
        except ValueError:
            return False, None
        
        # Performance: Check domain cache first (O(1) lookup)
        if domain in self._domain_cache:
            domain_users = self._domain_cache[domain]
            if email in domain_users:
                if domain_users[email] == password:
                    return True, domain
        
        # Check if domain has users (fallback, updates cache)
        if domain in self.domain_users:
            # Update cache for next time
            self._domain_cache[domain] = self.domain_users[domain]
            if email in self.domain_users[domain]:
                if self.domain_users[domain][email] == password:
                    return True, domain
        
        # Fallback to global users (for backward compatibility)
        if email in self.users:
            if self.users[email] == password:
                return True, domain
        
        return False, None
    
    def add_user(self, email, password):
        """Add a user to the appropriate domain.
        
        Args:
            email: User email address
            password: Plaintext password
            
        Returns:
            bool: True if user was added successfully
        """
        try:
            domain = extract_domain(email)
        except ValueError:
            return False
        
        # Add to global users
        self.users[email] = password
        
        # Add to domain-specific storage
        if domain not in self.domain_users:
            self.domain_users[domain] = {}
        self.domain_users[domain][email] = password
        
        # Save to domain-specific file
        domain_file = os.path.join(self.users_dir, f"{domain}.txt")
        with open(domain_file, 'a') as f:
            f.write(f"{email}:{password}\n")
        
        return True
