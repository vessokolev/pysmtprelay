#!/usr/bin/env python3
"""
Audit logging module for SMTP server.
Logs authentication attempts, security events, and important actions.

Performance optimized with async logging to avoid blocking SMTP operations.
"""
import json
import os
import asyncio
import aiofiles
from datetime import datetime
from typing import Optional, Dict, Any

class AuditLogger:
    """Audit logger for security events and authentication attempts.
    
    Uses async I/O to avoid blocking SMTP operations.
    """
    
    def __init__(self, log_file: str = '/var/log/smtp_audit.log', 
                 log_dir: str = 'logs', enable_async: bool = True):
        """
        Args:
            log_file: Path to audit log file
            log_dir: Directory for log files (fallback if log_file not writable)
            enable_async: Use async I/O (default True for performance)
        """
        self.log_file = log_file
        self.log_dir = log_dir
        self.enable_async = enable_async
        
        # Try to use specified log file, fallback to log_dir
        if not self._can_write(self.log_file):
            os.makedirs(self.log_dir, exist_ok=True)
            self.log_file = os.path.join(self.log_dir, 'smtp_audit.log')
    
    def _can_write(self, filepath: str) -> bool:
        """Check if we can write to a file path."""
        try:
            # Try to create/write to the file
            with open(filepath, 'a') as f:
                f.write('')
            return True
        except (IOError, OSError, PermissionError):
            return False
    
    async def _write_log_async(self, event_type: str, details: Dict[str, Any]):
        """Write a log entry asynchronously (non-blocking)."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': event_type,
            **details
        }
        
        try:
            async with aiofiles.open(self.log_file, 'a') as f:
                await f.write(json.dumps(log_entry) + '\n')
        except Exception:
            # Silently fail to avoid breaking SMTP operations
            pass
    
    def _write_log_sync(self, event_type: str, details: Dict[str, Any]):
        """Write a log entry synchronously (fallback)."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': event_type,
            **details
        }
        
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception:
            # Silently fail to avoid breaking SMTP operations
            pass
    
    def _write_log(self, event_type: str, details: Dict[str, Any]):
        """Write a log entry (async if enabled, sync otherwise)."""
        if self.enable_async:
            # Schedule async write (fire and forget)
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Event loop is running, schedule async write
                    asyncio.create_task(self._write_log_async(event_type, details))
                else:
                    # No event loop, use sync fallback
                    self._write_log_sync(event_type, details)
            except RuntimeError:
                # No event loop available, use sync fallback
                self._write_log_sync(event_type, details)
        else:
            self._write_log_sync(event_type, details)
    
    def log_auth_attempt(self, email: str, ip_address: str, 
                        method: str, success: bool, domain: Optional[str] = None,
                        reason: Optional[str] = None):
        """Log an authentication attempt.
        
        Args:
            email: User email address
            ip_address: Client IP address
            method: Authentication method (PLAIN, XOAUTH2)
            success: Whether authentication succeeded
            domain: User domain (if known)
            reason: Failure reason (if authentication failed)
        """
        details = {
            'email': email,
            'ip_address': ip_address,
            'method': method,
            'success': success,
        }
        
        if domain:
            details['domain'] = domain
        
        if not success and reason:
            details['failure_reason'] = reason
        
        self._write_log('auth_attempt', details)
    
    def log_rate_limit(self, identifier: str, ip_address: str, 
                      reason: str, email: Optional[str] = None):
        """Log a rate limit event.
        
        Args:
            identifier: What was rate limited (IP, email, domain)
            ip_address: Client IP address
            reason: Why it was rate limited
            email: User email (if known)
        """
        details = {
            'identifier': identifier,
            'ip_address': ip_address,
            'reason': reason,
        }
        
        if email:
            details['email'] = email
        
        self._write_log('rate_limit', details)
    
    def log_domain_mismatch(self, email: str, ip_address: str,
                           authenticated_domain: str, mail_from_domain: str):
        """Log a domain mismatch event (security violation).
        
        Args:
            email: User email
            ip_address: Client IP address
            authenticated_domain: Domain user authenticated with
            mail_from_domain: Domain in MAIL FROM command
        """
        details = {
            'email': email,
            'ip_address': ip_address,
            'authenticated_domain': authenticated_domain,
            'mail_from_domain': mail_from_domain,
            'security_violation': True,
        }
        
        self._write_log('domain_mismatch', details)
    
    def log_token_validation(self, token: str, ip_address: str,
                            success: bool, user: Optional[str] = None,
                            reason: Optional[str] = None):
        """Log OAuth2 token validation.
        
        Args:
            token: Token hash (first 16 chars for logging)
            ip_address: Client IP address
            success: Whether validation succeeded
            user: User email (if validation succeeded)
            reason: Failure reason (if validation failed)
        """
        # Only log token prefix for security
        token_prefix = token[:16] + '...' if len(token) > 16 else token
        
        details = {
            'token_prefix': token_prefix,
            'ip_address': ip_address,
            'success': success,
        }
        
        if user:
            details['user'] = user
        
        if not success and reason:
            details['failure_reason'] = reason
        
        self._write_log('token_validation', details)
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log a custom security event.
        
        Args:
            event_type: Type of security event
            details: Event details
        """
        self._write_log(f'security_{event_type}', details)

