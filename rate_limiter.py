#!/usr/bin/env python3
"""
Rate limiting module for SMTP server.
Prevents brute force attacks by limiting authentication attempts.
"""
import time
from collections import defaultdict
from typing import Optional, Tuple

class RateLimiter:
    """Rate limiter for authentication attempts.
    
    Supports multiple rate limit strategies:
    - Per IP address
    - Per email/username
    - Per domain
    """
    
    def __init__(self, 
                 max_attempts_per_minute: int = 5,
                 max_attempts_per_hour: int = 20,
                 window_seconds: int = 60,
                 block_duration_seconds: int = 300):
        """
        Args:
            max_attempts_per_minute: Maximum attempts allowed per minute window
            max_attempts_per_hour: Maximum attempts allowed per hour
            window_seconds: Time window for rate limiting (default 60 seconds)
            block_duration_seconds: How long to block after exceeding limits (default 5 minutes)
        """
        self.max_attempts_per_minute = max_attempts_per_minute
        self.max_attempts_per_hour = max_attempts_per_hour
        self.window_seconds = window_seconds
        self.block_duration_seconds = block_duration_seconds
        
        # Track attempts: {identifier: [(timestamp, success), ...]}
        self.attempts = defaultdict(list)
        
        # Track blocked identifiers: {identifier: block_until_timestamp}
        self.blocked = {}
    
    def _cleanup_old_attempts(self, identifier: str, current_time: float):
        """Remove attempts older than 1 hour."""
        cutoff = current_time - 3600  # 1 hour ago
        self.attempts[identifier] = [
            (ts, success) for ts, success in self.attempts[identifier]
            if ts > cutoff
        ]
    
    def _is_blocked(self, identifier: str, current_time: float) -> bool:
        """Check if identifier is currently blocked."""
        if identifier in self.blocked:
            if current_time < self.blocked[identifier]:
                return True
            else:
                # Block expired, remove it
                del self.blocked[identifier]
        return False
    
    def _check_rate_limit(self, identifier: str, current_time: float) -> Tuple[bool, Optional[str]]:
        """Check if identifier has exceeded rate limits.
        
        Returns:
            (allowed, reason): (True, None) if allowed, (False, reason) if blocked
        """
        # Check if currently blocked
        if self._is_blocked(identifier, current_time):
            remaining = int(self.blocked[identifier] - current_time)
            return False, f"Blocked for {remaining} more seconds"
        
        # Cleanup old attempts
        self._cleanup_old_attempts(identifier, current_time)
        
        # Count attempts in last minute
        minute_cutoff = current_time - self.window_seconds
        recent_attempts = [
            ts for ts, _ in self.attempts[identifier]
            if ts > minute_cutoff
        ]
        
        if len(recent_attempts) >= self.max_attempts_per_minute:
            # Block for block_duration_seconds
            self.blocked[identifier] = current_time + self.block_duration_seconds
            return False, f"Rate limit exceeded: {len(recent_attempts)} attempts in last {self.window_seconds} seconds"
        
        # Count attempts in last hour
        hour_cutoff = current_time - 3600
        hour_attempts = [
            ts for ts, _ in self.attempts[identifier]
            if ts > hour_cutoff
        ]
        
        if len(hour_attempts) >= self.max_attempts_per_hour:
            # Block for block_duration_seconds
            self.blocked[identifier] = current_time + self.block_duration_seconds
            return False, f"Rate limit exceeded: {len(hour_attempts)} attempts in last hour"
        
        return True, None
    
    def record_attempt(self, identifier: str, success: bool = False):
        """Record an authentication attempt.
        
        Args:
            identifier: IP address, email, or domain
            success: Whether authentication was successful
        """
        current_time = time.time()
        self.attempts[identifier].append((current_time, success))
    
    def check_allowed(self, ip_address: str, email: Optional[str] = None, 
                     domain: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Check if authentication attempt is allowed.
        
        Checks rate limits for IP, email, and domain.
        
        Args:
            ip_address: Client IP address
            email: User email (optional)
            domain: User domain (optional)
            
        Returns:
            (allowed, reason): (True, None) if allowed, (False, reason) if blocked
        """
        current_time = time.time()
        
        # Check IP address rate limit
        allowed, reason = self._check_rate_limit(ip_address, current_time)
        if not allowed:
            return False, f"IP {ip_address}: {reason}"
        
        # Check email rate limit (if provided)
        if email:
            allowed, reason = self._check_rate_limit(email, current_time)
            if not allowed:
                return False, f"Email {email}: {reason}"
        
        # Check domain rate limit (if provided)
        if domain:
            allowed, reason = self._check_rate_limit(domain, current_time)
            if not allowed:
                return False, f"Domain {domain}: {reason}"
        
        return True, None
    
    def get_stats(self, identifier: str) -> dict:
        """Get rate limit statistics for an identifier.
        
        Returns:
            dict with attempt counts and block status
        """
        current_time = time.time()
        self._cleanup_old_attempts(identifier, current_time)
        
        minute_cutoff = current_time - self.window_seconds
        hour_cutoff = current_time - 3600
        
        attempts = self.attempts.get(identifier, [])
        recent_attempts = [ts for ts, _ in attempts if ts > minute_cutoff]
        hour_attempts = [ts for ts, _ in attempts if ts > hour_cutoff]
        
        is_blocked = self._is_blocked(identifier, current_time)
        block_until = self.blocked.get(identifier, None)
        
        return {
            'identifier': identifier,
            'attempts_last_minute': len(recent_attempts),
            'attempts_last_hour': len(hour_attempts),
            'total_attempts': len(attempts),
            'is_blocked': is_blocked,
            'block_until': block_until,
            'max_per_minute': self.max_attempts_per_minute,
            'max_per_hour': self.max_attempts_per_hour
        }

