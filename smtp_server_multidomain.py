#!/usr/bin/env python3
"""
Multi-domain SMTP Relay Server with OAuth2 support.

This is an SMTP relay server that:
1. Authenticates users (PLAIN or OAuth2/XOAUTH2)
2. Accepts messages from authenticated users
3. Relays messages to a backend SMTP server for final delivery

Supports domain extraction and routing to domain-specific authentication.
"""
import asyncio
import ssl
import os
import base64
import hashlib
import json
import aiofiles
from datetime import datetime
from email import message_from_bytes
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message
from aiosmtpd.smtp import SMTP

# Import multi-domain handlers
from multidomain_auth_handler import MultiDomainUserAuthHandler, extract_domain
from oauth2_multidomain_provider import oauth2_multidomain_provider, MultiDomainOAuth2Handler
from rate_limiter import RateLimiter
from audit_logger import AuditLogger

class OptimizedMessageHandler(Message):
    """Message handler for SMTP relay server.
    
    NOTE: Currently stores messages locally for testing.
    In production, this should relay messages to a backend SMTP server.
    
    TODO: Implement relay functionality to forward messages to backend SMTP server.
    """
    
    def __init__(self, messages_dir="messages", enable_async=True):
        super().__init__()
        self.messages_dir = messages_dir
        self.enable_async = enable_async
        os.makedirs(self.messages_dir, exist_ok=True)
    
    async def handle_message_async(self, message):
        """Store message asynchronously to local file (testing only).
        
        TODO: Replace with relay to backend SMTP server.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        msg_bytes = bytes(message)
        msg_hash = hashlib.md5(msg_bytes).hexdigest()[:8]
        filename = f"{timestamp}_{msg_hash}.eml"
        filepath = os.path.join(self.messages_dir, filename)
        
        try:
            async with aiofiles.open(filepath, 'wb') as f:
                await f.write(msg_bytes)
            return filepath
        except Exception as e:
            print(f"Error saving message: {e}")
            return None
    
    def handle_message(self, message):
        """Store message to local file."""
        if self.enable_async:
            asyncio.create_task(self.handle_message_async(message))
            return None
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            msg_bytes = bytes(message)
            msg_hash = hashlib.md5(msg_bytes).hexdigest()[:8]
            filename = f"{timestamp}_{msg_hash}.eml"
            filepath = os.path.join(self.messages_dir, filename)
            with open(filepath, 'wb') as f:
                f.write(msg_bytes)
            return filepath

# MultiDomainOAuth2Handler is imported from oauth2_multidomain_provider
# It includes token caching for performance

class MultiDomainAuthenticatedSMTP(SMTP):
    """SMTP server with multi-domain authentication (PLAIN and OAuth2)."""
    
    def __init__(self, handler, auth_handler=None, oauth2_handler=None, 
                 rate_limiter=None, audit_logger=None, require_tls_for_auth=True, *args, **kwargs):
        kwargs.setdefault('auth_require_tls', require_tls_for_auth)
        kwargs.setdefault('auth_required', False)
        super().__init__(handler, *args, **kwargs)
        self.auth_handler = auth_handler
        self.oauth2_handler = oauth2_handler
        self.rate_limiter = rate_limiter
        self.audit_logger = audit_logger
        self.authenticated = False
        self.username = None
        self.user_domain = None  # Store authenticated user's domain
        self.require_tls_for_auth = require_tls_for_auth
    
    def _get_client_ip(self):
        """Get client IP address from session."""
        try:
            if self.session and hasattr(self.session, 'peer'):
                peer = self.session.peer
                if isinstance(peer, tuple) and len(peer) >= 1:
                    return peer[0]  # IP address is first element
                elif isinstance(peer, str):
                    # Sometimes peer is just the IP string
                    return peer
            # Fallback: try to get from transport
            if hasattr(self, 'transport') and self.transport:
                if hasattr(self.transport, 'get_extra_info'):
                    peername = self.transport.get_extra_info('peername')
                    if peername and isinstance(peername, tuple):
                        return peername[0]
        except Exception:
            pass
        return 'unknown'
    
    async def auth_PLAIN(self, server, args):
        """Handle AUTH PLAIN mechanism with multi-domain support."""
        from aiosmtpd.smtp import AuthResult, MISSING
        
        if not self.auth_handler:
            await self.push("535 5.7.8 Authentication mechanism not available")
            return AuthResult(success=False, handled=True)
        
        # Get client IP for rate limiting and audit logging
        client_ip = self._get_client_ip()
        username = None
        domain = None
        auth_success = False
        failure_reason = None
        
        login_and_password = None
        if len(args) == 1:
            login_and_password = await self.challenge_auth("")
            if login_and_password is MISSING:
                return AuthResult(success=False)
        else:
            try:
                login_and_password = base64.b64decode(args[1].encode(), validate=True)
            except Exception:
                await self.push("501 5.5.2 Can't decode base64")
                failure_reason = "Invalid base64 encoding"
                if self.audit_logger:
                    self.audit_logger.log_auth_attempt(
                        email="unknown", ip_address=client_ip, method="PLAIN",
                        success=False, reason=failure_reason
                    )
                return AuthResult(success=False, handled=True)
        
        try:
            _, login, password = login_and_password.split(b"\x00")
            username = login.decode('utf-8')
            password_str = password.decode('utf-8')
            
            # Rate limiting check
            if self.rate_limiter:
                allowed, rate_limit_reason = self.rate_limiter.check_allowed(
                    ip_address=client_ip,
                    email=username,
                    domain=extract_domain(username) if '@' in username else None
                )
                if not allowed:
                    await self.push(f"535 5.7.8 {rate_limit_reason}")
                    if self.audit_logger:
                        self.audit_logger.log_rate_limit(
                            identifier=client_ip, ip_address=client_ip,
                            reason=rate_limit_reason, email=username
                        )
                    return AuthResult(success=False, handled=True)
            
            # Authenticate against domain-specific database
            authenticated, domain = self.auth_handler.authenticate(username, password_str)
            auth_success = authenticated
            
            if authenticated:
                self.authenticated = True
                self.username = username
                self.user_domain = domain
                await self.push("235 2.7.0 Authentication successful")
                
                # Record successful attempt in rate limiter
                if self.rate_limiter:
                    self.rate_limiter.record_attempt(client_ip, success=True)
                    self.rate_limiter.record_attempt(username, success=True)
                    if domain:
                        self.rate_limiter.record_attempt(domain, success=True)
                
                # Audit log success
                if self.audit_logger:
                    self.audit_logger.log_auth_attempt(
                        email=username, ip_address=client_ip, method="PLAIN",
                        success=True, domain=domain
                    )
                
                return AuthResult(success=True, auth_data=username)
            else:
                failure_reason = "Invalid credentials"
        except (ValueError, UnicodeDecodeError) as e:
            await self.push("501 5.5.2 Can't split auth value")
            failure_reason = f"Invalid auth format: {str(e)}"
            if self.audit_logger:
                self.audit_logger.log_auth_attempt(
                    email=username or "unknown", ip_address=client_ip, method="PLAIN",
                    success=False, reason=failure_reason
                )
            return AuthResult(success=False, handled=True)
        
        # Authentication failed
        await self.push("535 5.7.8 Authentication failed")
        
        # Record failed attempt in rate limiter
        if self.rate_limiter:
            self.rate_limiter.record_attempt(client_ip, success=False)
            if username:
                self.rate_limiter.record_attempt(username, success=False)
            if domain:
                self.rate_limiter.record_attempt(domain, success=False)
        
        # Audit log failure
        if self.audit_logger:
            self.audit_logger.log_auth_attempt(
                email=username or "unknown", ip_address=client_ip, method="PLAIN",
                success=False, domain=domain, reason=failure_reason or "Invalid credentials"
            )
        
        return AuthResult(success=False, handled=True)
    
    async def auth_XOAUTH2(self, server, args):
        """Handle AUTH XOAUTH2 mechanism with multi-domain support."""
        from aiosmtpd.smtp import AuthResult, MISSING
        
        if not self.oauth2_handler or not self.oauth2_handler.oauth2_provider:
            await self.push("535 5.7.8 OAuth2 not supported")
            return AuthResult(success=False, handled=True)
        
        # Get client IP for rate limiting and audit logging
        client_ip = self._get_client_ip()
        user_email = None
        token_domain = None
        failure_reason = None
        
        oauth2_data = None
        if len(args) == 1:
            oauth2_data = await self.challenge_auth("")
            if oauth2_data is MISSING:
                return AuthResult(success=False)
        else:
            try:
                oauth2_data = base64.b64decode(args[1].encode(), validate=True)
            except Exception:
                await self.push("501 5.5.2 Can't decode base64")
                failure_reason = "Invalid base64 encoding"
                if self.audit_logger:
                    self.audit_logger.log_auth_attempt(
                        email="unknown", ip_address=client_ip, method="XOAUTH2",
                        success=False, reason=failure_reason
                    )
                return AuthResult(success=False, handled=True)
        
        try:
            oauth2_json = json.loads(oauth2_data.decode('utf-8'))
            user_email = oauth2_json.get('user')
            auth_token = oauth2_json.get('authToken')
            auth_method = oauth2_json.get('authMethod', 'XOAUTH2')
            
            if not user_email or not auth_token:
                await self.push("535 5.7.8 Invalid OAuth2 credentials")
                failure_reason = "Missing user or token"
                if self.audit_logger:
                    self.audit_logger.log_auth_attempt(
                        email="unknown", ip_address=client_ip, method="XOAUTH2",
                        success=False, reason=failure_reason
                    )
                return AuthResult(success=False, handled=True)
            
            if auth_method != 'XOAUTH2':
                await self.push("535 5.7.8 Invalid auth method")
                failure_reason = f"Invalid auth method: {auth_method}"
                if self.audit_logger:
                    self.audit_logger.log_auth_attempt(
                        email=user_email, ip_address=client_ip, method="XOAUTH2",
                        success=False, reason=failure_reason
                    )
                return AuthResult(success=False, handled=True)
            
            # Rate limiting check
            if self.rate_limiter:
                domain = extract_domain(user_email) if '@' in user_email else None
                allowed, rate_limit_reason = self.rate_limiter.check_allowed(
                    ip_address=client_ip,
                    email=user_email,
                    domain=domain
                )
                if not allowed:
                    await self.push(f"535 5.7.8 {rate_limit_reason}")
                    if self.audit_logger:
                        self.audit_logger.log_rate_limit(
                            identifier=client_ip, ip_address=client_ip,
                            reason=rate_limit_reason, email=user_email
                        )
                    return AuthResult(success=False, handled=True)
            
            # Validate token (returns domain context)
            token_info = self.oauth2_handler.validate_token(auth_token)
            
            # Audit log token validation
            if self.audit_logger:
                token_prefix = auth_token[:16] + '...' if len(auth_token) > 16 else auth_token
                self.audit_logger.log_token_validation(
                    token=token_prefix, ip_address=client_ip,
                    success=token_info is not None,
                    user=user_email if token_info else None,
                    reason=None if token_info else "Invalid or expired token"
                )
            
            if not token_info:
                await self.push("535 5.7.8 Invalid or expired token")
                failure_reason = "Invalid or expired token"
                if self.rate_limiter:
                    self.rate_limiter.record_attempt(client_ip, success=False)
                    self.rate_limiter.record_attempt(user_email, success=False)
                if self.audit_logger:
                    self.audit_logger.log_auth_attempt(
                        email=user_email, ip_address=client_ip, method="XOAUTH2",
                        success=False, reason=failure_reason
                    )
                return AuthResult(success=False, handled=True)
            
            # Verify token user matches provided email
            token_user = token_info.get('user')
            if token_user != user_email:
                await self.push("535 5.7.8 Token user mismatch")
                failure_reason = "Token user mismatch"
                if self.rate_limiter:
                    self.rate_limiter.record_attempt(client_ip, success=False)
                    self.rate_limiter.record_attempt(user_email, success=False)
                if self.audit_logger:
                    self.audit_logger.log_auth_attempt(
                        email=user_email, ip_address=client_ip, method="XOAUTH2",
                        success=False, reason=failure_reason
                    )
                return AuthResult(success=False, handled=True)
            
            # Extract domain from token
            token_domain = token_info.get('domain')
            if token_domain:
                # Verify domain is still enabled
                if not self.oauth2_handler.oauth2_provider.is_domain_enabled(token_domain):
                    await self.push("535 5.7.8 Domain disabled")
                    failure_reason = "Domain disabled"
                    if self.rate_limiter:
                        self.rate_limiter.record_attempt(client_ip, success=False)
                        self.rate_limiter.record_attempt(user_email, success=False)
                    if self.audit_logger:
                        self.audit_logger.log_auth_attempt(
                            email=user_email, ip_address=client_ip, method="XOAUTH2",
                            success=False, domain=token_domain, reason=failure_reason
                        )
                    return AuthResult(success=False, handled=True)
            
            # Authentication successful
            self.authenticated = True
            self.username = user_email
            self.user_domain = token_domain or extract_domain(user_email)
            await self.push("235 2.7.0 Authentication successful")
            
            # Record successful attempt in rate limiter
            if self.rate_limiter:
                self.rate_limiter.record_attempt(client_ip, success=True)
                self.rate_limiter.record_attempt(user_email, success=True)
                if token_domain:
                    self.rate_limiter.record_attempt(token_domain, success=True)
            
            # Audit log success
            if self.audit_logger:
                self.audit_logger.log_auth_attempt(
                    email=user_email, ip_address=client_ip, method="XOAUTH2",
                    success=True, domain=token_domain
                )
            
            return AuthResult(success=True, auth_data=user_email)
            
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as e:
            await self.push("535 5.7.8 Invalid OAuth2 format")
            failure_reason = f"Invalid OAuth2 format: {str(e)}"
            if self.audit_logger:
                self.audit_logger.log_auth_attempt(
                    email=user_email or "unknown", ip_address=client_ip, method="XOAUTH2",
                    success=False, reason=failure_reason
                )
            return AuthResult(success=False, handled=True)
    
    async def smtp_EHLO(self, arg):
        """Override EHLO to advertise AUTH mechanisms."""
        result = await super().smtp_EHLO(arg)
        # Advertise AUTH mechanisms (always, not just with SSL)
        await self.push("250-AUTH PLAIN XOAUTH2")
        return result
    
    async def smtp_MAIL(self, arg):
        """Override MAIL to require authentication and validate domain."""
        if not self.authenticated:
            await self.push('530 5.7.0 Authentication required')
            return
        
        # Extract MAIL FROM address and validate domain
        # Note: aiosmtpd passes the part after "MAIL " as arg
        # So arg is "FROM:<user@domain.com>" or "FROM:user@domain.com"
        
        if self.user_domain:  # Only validate if we have a user domain
            try:
                # Format: arg is "FROM:<user@domain.com>" or "FROM:user@domain.com"
                from_addr = None
                if arg:
                    # Remove "FROM:" prefix if present
                    from_addr = arg.strip()
                    if from_addr.upper().startswith('FROM:'):
                        from_addr = from_addr[5:].strip()  # Remove "FROM:"
                    
                    # Remove angle brackets if present
                    if from_addr.startswith('<') and from_addr.endswith('>'):
                        from_addr = from_addr[1:-1].strip()
                    
                    # Remove any additional parameters (SP mail-parameters in extended SMTP)
                    # Format might be: "<user@domain.com> SIZE=1234" or "user@domain.com SIZE=1234"
                    if ' ' in from_addr:
                        from_addr = from_addr.split()[0].strip()
                
                if from_addr:
                    from_domain = extract_domain(from_addr)
                    
                    # Verify authenticated user's domain matches MAIL FROM domain
                    if from_domain != self.user_domain:
                        # Audit log domain mismatch (security violation)
                        if self.audit_logger:
                            client_ip = self._get_client_ip()
                            self.audit_logger.log_domain_mismatch(
                                email=self.username or "unknown",
                                ip_address=client_ip,
                                authenticated_domain=self.user_domain,
                                mail_from_domain=from_domain
                            )
                        await self.push(f'550 5.7.1 Domain mismatch: authenticated domain ({self.user_domain}) does not match MAIL FROM domain ({from_domain})')
                        return None  # Explicitly return None to prevent parent method from being called
            except (ValueError, IndexError):
                # If we can't parse, still allow (for compatibility with edge cases)
                # In production, consider logging this for security monitoring
                pass
        # Note: If user_domain is None, we skip validation (shouldn't happen after auth)
        
        # Call parent implementation (will handle the actual MAIL FROM command)
        result = await super().smtp_MAIL(arg)
        return result
    
    async def smtp_RCPT(self, arg):
        """Override RCPT to require authentication."""
        if not self.authenticated:
            await self.push('530 5.7.0 Authentication required')
            return
        result = await super().smtp_RCPT(arg)
        return result
    
    async def smtp_DATA(self, arg):
        """Override DATA to require authentication."""
        if not self.authenticated:
            await self.push('530 5.7.0 Authentication required')
            return
        result = await super().smtp_DATA(arg)
        return result

def create_ssl_context(certfile='server.crt', keyfile='server.key'):
    """Create SSL context for TLS."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    
    # Try to load certificates if they exist
    if os.path.exists(certfile) and os.path.exists(keyfile):
        try:
            context.load_cert_chain(certfile, keyfile)
        except Exception as e:
            print(f"Warning: Could not load certificates: {e}")
            # Fall back to no verification
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    else:
        # No certificates - use no verification (for testing only)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    
    # Set ciphers
    try:
        context.set_ciphers('AES256-GCM-SHA384')
    except:
        pass  # Cipher might not be available
    
    return context

class MultiDomainAuthenticatedController(Controller):
    """Controller for multi-domain authenticated SMTP server."""
    
    def __init__(self, handler, auth_handler=None, oauth2_handler=None, 
                 rate_limiter=None, audit_logger=None, require_tls_for_auth=True, *args, **kwargs):
        self._auth_handler = auth_handler
        self._oauth2_handler = oauth2_handler
        self._rate_limiter = rate_limiter
        self._audit_logger = audit_logger
        self._require_tls_for_auth = require_tls_for_auth
        
        # Extract SSL contexts if provided (for SMTPS or STARTTLS)
        ssl_context = kwargs.pop('ssl_context', None)
        tls_context = kwargs.pop('tls_context', None)
        
        # If no SSL context provided, ensure it's None to prevent SSL wrapping
        if ssl_context is None and tls_context is None:
            kwargs.setdefault('ssl_context', None)
        else:
            # Pass SSL context for SMTPS (ssl_context) or STARTTLS (tls_context)
            if ssl_context:
                kwargs['ssl_context'] = ssl_context
            if tls_context:
                kwargs['tls_context'] = tls_context
        
        super().__init__(handler, *args, **kwargs)
        
        # Only set ssl_context to None if we're not using SSL at all
        if ssl_context is None and tls_context is None:
            self.ssl_context = None
    
    def factory(self):
        """Factory method to create authenticated SMTP instances."""
        # Include tls_context in allowed_kwargs for STARTTLS support
        allowed_kwargs = {'loop', 'decode_data', 'enable_SMTPUTF8', 'tls_context',
                         'hostname', 'ident', 'timeout', 'auth_required', 'auth_require_tls'}
        kwargs = {k: v for k, v in self.SMTP_kwargs.items() 
                 if k in allowed_kwargs}
        # Don't pass ssl_context to SMTP instance (only tls_context for STARTTLS)
        kwargs.pop('ssl_context', None)
        return MultiDomainAuthenticatedSMTP(
            self.handler,
            auth_handler=self._auth_handler,
            oauth2_handler=self._oauth2_handler,
            rate_limiter=self._rate_limiter,
            audit_logger=self._audit_logger,
            require_tls_for_auth=self._require_tls_for_auth,
            **kwargs
        )

def main():
    """Main function to start multi-domain SMTP server."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Multi-domain SMTP server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port-465', type=int, default=8465, help='Port for SMTPS (default 8465)')
    parser.add_argument('--port-587', type=int, default=8587, help='Port for STARTTLS (default 8587)')
    parser.add_argument('--certfile', default='certs/server-cert.pem', help='Server certificate file')
    parser.add_argument('--keyfile', default='certs/server-key.pem', help='Server private key file')
    parser.add_argument('--no-ssl', action='store_true', help='Start without SSL (testing only)')
    parser.add_argument('--no-rate-limit', action='store_true', help='Disable rate limiting')
    parser.add_argument('--no-audit-log', action='store_true', help='Disable audit logging')
    parser.add_argument('--rate-limit-per-minute', type=int, default=5, help='Max attempts per minute (default 5)')
    parser.add_argument('--rate-limit-per-hour', type=int, default=20, help='Max attempts per hour (default 20)')
    parser.add_argument('--audit-log-file', default='/var/log/smtp_audit.log', help='Audit log file path')
    
    args = parser.parse_args()
    
    # Create multi-domain auth handler
    auth_handler = MultiDomainUserAuthHandler(users_dir="users")
    
    # Create OAuth2 handler
    oauth2_handler = MultiDomainOAuth2Handler()
    
    # Create rate limiter (if not disabled)
    rate_limiter = None
    if not args.no_rate_limit:
        rate_limiter = RateLimiter(
            max_attempts_per_minute=args.rate_limit_per_minute,
            max_attempts_per_hour=args.rate_limit_per_hour
        )
        print("✅ Rate limiting enabled")
    
    # Create audit logger (if not disabled)
    audit_logger = None
    if not args.no_audit_log:
        audit_logger = AuditLogger(log_file=args.audit_log_file)
        print(f"✅ Audit logging enabled: {audit_logger.log_file}")
    
    # Create message handler
    message_handler = OptimizedMessageHandler()
    
    controllers = []
    
    if args.no_ssl:
        # Plain SMTP for testing (no SSL)
        print("Starting multi-domain SMTP server (NO SSL - testing only)...")
        controller_465 = MultiDomainAuthenticatedController(
            message_handler,
            auth_handler=auth_handler,
            oauth2_handler=oauth2_handler,
            rate_limiter=rate_limiter,
            audit_logger=audit_logger,
            require_tls_for_auth=False,
            hostname=args.host,
            port=args.port_465
        )
        controller_465.start()
        controllers.append(controller_465)
        print(f"  SMTP (port {args.port_465}): Ready (NO SSL)")
    else:
        # Check if certificates exist
        if not os.path.exists(args.certfile) or not os.path.exists(args.keyfile):
            print(f"Error: Certificate files not found: {args.certfile}, {args.keyfile}")
            print("Please run generate_certificates.py first or use --no-ssl for testing")
            return
        
        # Create SSL context
        ssl_context = create_ssl_context(args.certfile, args.keyfile)
        
        # Start SMTPS server (port 8465) - SSL from the start
        print("Starting multi-domain SMTP server...")
        print(f"  SMTPS (port {args.port_465}): Starting...")
        controller_465 = MultiDomainAuthenticatedController(
            message_handler,
            auth_handler=auth_handler,
            oauth2_handler=oauth2_handler,
            rate_limiter=rate_limiter,
            audit_logger=audit_logger,
            require_tls_for_auth=False,
            hostname=args.host,
            port=args.port_465,
            ssl_context=ssl_context
        )
        controller_465.start()
        controllers.append(controller_465)
        print(f"  SMTPS (port {args.port_465}): Ready")
        
        # Start STARTTLS server (port 8587) - TLS upgrade after connection
        print(f"  STARTTLS (port {args.port_587}): Starting...")
        controller_587 = MultiDomainAuthenticatedController(
            message_handler,
            auth_handler=auth_handler,
            oauth2_handler=oauth2_handler,
            rate_limiter=rate_limiter,
            audit_logger=audit_logger,
            require_tls_for_auth=True,  # Require STARTTLS before authentication
            hostname=args.host,
            port=args.port_587,
            tls_context=ssl_context  # Use tls_context for STARTTLS
        )
        controller_587.start()
        controllers.append(controller_587)
        print(f"  STARTTLS (port {args.port_587}): Ready")
    
    print("\nSupported domains:")
    for domain in auth_handler.domain_users.keys():
        user_count = len(auth_handler.domain_users[domain])
        print(f"  {domain}: {user_count} users")
    
    print("\nAuthentication methods: PLAIN, XOAUTH2")
    print("Press Ctrl+C to stop...")
    
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        for controller in controllers:
            controller.stop()

if __name__ == "__main__":
    main()

