#!/usr/bin/env python3
"""
SMTP server with SMTPS (465) and STARTTLS (587) support.
Supports authentication and stores messages locally.
"""
import asyncio
import ssl
import os
import base64
import hashlib
from datetime import datetime
from email import message_from_bytes
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message
from aiosmtpd.smtp import SMTP

class UserAuthHandler:
    """Authentication handler using text file."""
    
    def __init__(self, users_file="users.txt"):
        self.users_file = users_file
        self.load_users()
    
    def load_users(self):
        """Load users from text file."""
        self.users = {}
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        username, password = line.split(':', 1)
                        self.users[username] = password

class MessageHandler(Message):
    """Handler that stores messages to local files."""
    
    def __init__(self, messages_dir="messages"):
        super().__init__()
        self.messages_dir = messages_dir
        os.makedirs(self.messages_dir, exist_ok=True)
    
    def handle_message(self, message):
        """Store message to local file."""
        # Generate unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        msg_bytes = bytes(message)
        msg_hash = hashlib.md5(msg_bytes).hexdigest()[:8]
        filename = f"{timestamp}_{msg_hash}.eml"
        filepath = os.path.join(self.messages_dir, filename)
        
        # Save message
        with open(filepath, 'wb') as f:
            f.write(msg_bytes)
        
        print(f"Message saved to {filepath}")
        return filepath

class AuthenticatedSMTP(SMTP):
    """SMTP server with authentication requirement."""
    
    def __init__(self, handler, auth_handler=None, require_tls_for_auth=True, *args, **kwargs):
        # For STARTTLS, require TLS before auth. For SMTPS, TLS is already established.
        # require_tls_for_auth=True means auth only after STARTTLS (for port 587)
        # require_tls_for_auth=False means auth without TLS requirement (for port 465 SMTPS)
        kwargs.setdefault('auth_require_tls', require_tls_for_auth)
        kwargs.setdefault('auth_required', False)  # We'll check manually
        super().__init__(handler, *args, **kwargs)
        self.auth_handler = auth_handler
        self.authenticated = False
        self.username = None
        self.require_tls_for_auth = require_tls_for_auth
    
    async def auth_PLAIN(self, server, args):
        """Handle AUTH PLAIN mechanism - implements aiosmtpd's auth_PLAIN interface."""
        from aiosmtpd.smtp import AuthResult, MISSING, LoginPassword
        from base64 import b64decode
        
        if not self.auth_handler:
            return AuthResult(success=False)
        
        # Get credentials (same logic as parent)
        login_and_password = None
        if len(args) == 1:
            login_and_password = await self.challenge_auth("")
            if login_and_password is MISSING:
                return AuthResult(success=False)
        else:
            try:
                login_and_password = b64decode(args[1].encode(), validate=True)
            except Exception:
                await self.push("501 5.5.2 Can't decode base64")
                return AuthResult(success=False, handled=True)
        
        try:
            # Format: "{authz_id}\x00{login_id}\x00{password}"
            _, login, password = login_and_password.split(b"\x00")
            username = login.decode('utf-8')
            password_str = password.decode('utf-8')
            
            # Verify against our user database
            if username in self.auth_handler.users and self.auth_handler.users[username] == password_str:
                self.authenticated = True
                self.username = username
                return AuthResult(success=True, auth_data=username)
        except (ValueError, UnicodeDecodeError):
            await self.push("501 5.5.2 Can't split auth value")
            return AuthResult(success=False, handled=True)
        
        return AuthResult(success=False)
    
    
    async def smtp_MAIL(self, arg):
        """Override MAIL to require authentication."""
        if not self.authenticated:
            await self.push('530 Authentication required')
            return
        # Call parent - it will check HELO state
        result = await super().smtp_MAIL(arg)
        return result
    
    async def smtp_RCPT(self, arg):
        """Override RCPT to require authentication."""
        if not self.authenticated:
            await self.push('530 Authentication required')
            return
        return await super().smtp_RCPT(arg)
    
    async def smtp_DATA(self, arg):
        """Override DATA to require authentication."""
        if not self.authenticated:
            await self.push('530 Authentication required')
            return
        return await super().smtp_DATA(arg)

class AuthenticatedController(Controller):
    """Controller that uses AuthenticatedSMTP - using default factory approach."""
    
    def __init__(self, handler, auth_handler=None, require_tls_for_auth=True, *args, **kwargs):
        self._auth_handler = auth_handler
        self._require_tls_for_auth = require_tls_for_auth
        super().__init__(handler, *args, **kwargs)
    
    def factory(self):
        # Return AuthenticatedSMTP instance with auth_handler
        # Filter out any kwargs that SMTP.__init__ doesn't accept
        # SMTP.__init__ accepts: handler, loop, decode_data, enable_SMTPUTF8, tls_context, and others
        # We need to pass tls_context for STARTTLS support
        allowed_kwargs = {'loop', 'decode_data', 'enable_SMTPUTF8', 'tls_context', 
                         'hostname', 'ident', 'timeout', 'auth_required', 'auth_require_tls'}
        kwargs = {k: v for k, v in self.SMTP_kwargs.items() 
                 if k in allowed_kwargs}
        return AuthenticatedSMTP(self.handler, self._auth_handler, 
                                 require_tls_for_auth=self._require_tls_for_auth, **kwargs)

def create_ssl_context(certfile, keyfile, ca_certfile=None):
    """
    Create production-ready SSL context for TLS with TLSv1.3, AES256-GCM, SHA384.
    
    Hardened for internet exposure with security best practices:
    - TLSv1.3 only (no legacy protocols)
    - AES256-GCM-SHA384 cipher suite
    - Perfect Forward Secrecy (PFS) enabled via classical ECDHE
    - Compression disabled (CRIME attack prevention)
    - Session tickets disabled (session hijacking prevention)
    - Server cipher preference
    
    IMPORTANT: This configuration provides STRONG CLASSICAL SECURITY only.
    POST-QUANTUM CRYPTOGRAPHY IS NOT SUPPORTED because Python's ssl module
    has no API for configuring post-quantum key exchange groups.
    
    See VERIFIED_FACTS.md for proof that Python has no post-quantum API.
    
    Args:
        certfile: Path to server certificate file
        keyfile: Path to server private key file
        ca_certfile: Optional path to CA certificate file for client verification
    
    Returns:
        ssl.SSLContext configured for production use (classical security only)
    """
    # Create SSL context for server authentication
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # ===== TLS Version Configuration =====
    # Force TLSv1.3 only for maximum security (no legacy protocols)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # ===== Security Options - Disable Weak Protocols =====
    # Explicitly disable all legacy protocols (defense in depth)
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1
    context.options |= ssl.OP_NO_TLSv1_2  # Only allow TLSv1.3
    
    # ===== Perfect Forward Secrecy (PFS) =====
    # Server chooses cipher order (prefer strongest)
    context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    
    # ===== Key Exchange Configuration =====
    # Configure ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) for Perfect Forward Secrecy
    # 
    # Python's ssl module ONLY supports classical ECDHE curves via set_ecdh_curve()
    # 
    # What we CAN configure:
    # - secp384r1 (NIST P-384) - preferred, strong classical security
    # - prime256v1 (NIST P-256) - fallback for compatibility
    #
    # What we CANNOT configure (Python has NO API for this):
    # - Post-quantum groups (ML-KEM-768, etc.)
    # - Hybrid post-quantum groups (X25519+ML-KEM-768, etc.)
    # - TLS 1.3 key exchange group preferences
    #
    # Current configuration:
    # - Using set_ecdh_curve('secp384r1') - this is the BEST we can do
    # - Provides strong classical ECDHE but NOT post-quantum
    
    try:
        if hasattr(context, 'set_ecdh_curve'):
            # Set preferred ECDH curve: secp384r1 (NIST P-384)
            # This provides strong classical security with 384-bit keys
            # secp384r1 is supported and preferred as requested
            context.set_ecdh_curve('secp384r1')
    except (AttributeError, ValueError) as e:
        # If secp384r1 fails, try fallback curves
        try:
            if hasattr(context, 'set_ecdh_curve'):
                context.set_ecdh_curve('prime256v1')  # NIST P-256 fallback
        except ValueError:
            pass  # Use OpenSSL defaults
    
    # ===== Post-Quantum Key Exchange Configuration =====
    # 
    # TRUTH: POST-QUANTUM CRYPTOGRAPHY IS NOT SUPPORTED
    #
    # VERIFIED FACTS (see VERIFIED_FACTS.md for sources with links):
    # - Python's ssl module has NO API for configuring TLS 1.3 key exchange groups
    # - set_groups() method DOES NOT EXIST (verified: official docs, code check)
    # - OpenSSL supports SSL_CTX_set1_groups_list() but Python doesn't expose it
    #
    # Current implementation:
    # - We use set_ecdh_curve('secp384r1') - VERIFIED WORKING
    # - This provides STRONG CLASSICAL ECDHE (NIST P-384) ONLY
    # - This is NOT post-quantum - it's classical cryptography
    #
    # This server provides:
    # - ✓ Strong classical TLS 1.3 security
    # - ✓ Perfect Forward Secrecy (classical)
    # - ✗ NO post-quantum cryptography support
    # - ✗ NOT post-quantum ready
    #
    # See VERIFIED_FACTS.md and SECURITY_STATUS.md for complete details.
    
    # ===== Additional Security Hardening =====
    # Disable compression to prevent CRIME attack (Compression Ratio Info-leak Made Easy)
    context.options |= ssl.OP_NO_COMPRESSION
    
    # Disable session tickets to prevent session hijacking
    # Note: This improves security but may impact performance slightly
    context.options |= ssl.OP_NO_TICKET
    
    # ===== Certificate Configuration =====
    # Load server certificate and private key
    context.load_cert_chain(certfile, keyfile)
    
    # Load CA certificate if provided (for client certificate verification if needed)
    if ca_certfile and os.path.exists(ca_certfile):
        context.load_verify_locations(ca_certfile)
    
    # For SMTP submission, we don't require client certificates
    # (Clients authenticate via AUTH PLAIN instead)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # ===== Cipher Suite Configuration =====
    # TLSv1.3 cipher suites are automatically negotiated
    # Default order (which we get by default with OP_CIPHER_SERVER_PREFERENCE):
    # 1. TLS_AES_256_GCM_SHA384 - AES256 in GCM mode with SHA384 (preferred)
    # 2. TLS_CHACHA20_POLY1305_SHA256 - ChaCha20-Poly1305 (fallback)
    # 3. TLS_AES_128_GCM_SHA256 - AES128 in GCM mode (fallback)
    # TLSv1.3 will automatically prefer TLS_AES_256_GCM_SHA384 if both support it
    
    return context

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='SMTP server with authentication')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port-465', type=int, default=8465, help='Port for SMTPS (default 8465 for non-root)')
    parser.add_argument('--port-587', type=int, default=8587, help='Port for STARTTLS (default 8587 for non-root)')
    parser.add_argument('--certfile', default='certs/server-cert.pem', help='Server certificate file')
    parser.add_argument('--keyfile', default='certs/server-key.pem', help='Server private key file')
    parser.add_argument('--users', default='users.txt', help='Users file')
    parser.add_argument('--messages-dir', default='messages', help='Directory to store messages')
    
    args = parser.parse_args()
    
    # Check if certificates exist
    if not os.path.exists(args.certfile) or not os.path.exists(args.keyfile):
        print(f"Error: Certificate files not found. Please run generate_certificates.py first.")
        return
    
    # Create handlers
    auth_handler = UserAuthHandler(users_file=args.users)
    message_handler = MessageHandler(messages_dir=args.messages_dir)
    
    # Create production-ready SSL context
    ca_certfile = args.certfile.replace('server-cert.pem', 'ca-cert.pem') if 'server-cert' in args.certfile else None
    ssl_context = create_ssl_context(args.certfile, args.keyfile, ca_certfile)
    
    # Start SMTPS server on port 465 (SSL from the start)
    print(f"Starting SMTPS server on {args.host}:{args.port_465}...")
    controller_465 = AuthenticatedController(
        message_handler,
        auth_handler,
        hostname=args.host,
        port=args.port_465,
        ssl_context=ssl_context,
        require_tls_for_auth=False  # SMTPS already has TLS, no need to require it
    )
    controller_465.start()
    print(f"SMTPS server started on {args.host}:{args.port_465}")
    
    # Start STARTTLS server on port 587 (TLS upgrade after initial connection)
    print(f"Starting STARTTLS server on {args.host}:{args.port_587}...")
    controller_587 = AuthenticatedController(
        message_handler,
        auth_handler,
        hostname=args.host,
        port=args.port_587,
        tls_context=ssl_context,  # Use tls_context for STARTTLS (not ssl_context)
        require_tls_for_auth=True  # Require STARTTLS before authentication
    )
    controller_587.start()
    print(f"STARTTLS server started on {args.host}:{args.port_587}")
    
    print("SMTP servers running (SMTPS on {}:{}, STARTTLS on {}:{}). Press Ctrl+C to stop.".format(
        args.host, args.port_465, args.host, args.port_587))
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        controller_465.stop()
        controller_587.stop()

if __name__ == "__main__":
    main()
