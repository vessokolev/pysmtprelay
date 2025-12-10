#!/usr/bin/env python3
"""
Optimized SMTP server with performance improvements:
1. Async file I/O for message storage
2. Session ticket reuse (performance optimization)
3. Async message processing
4. Reduced blocking operations
"""
import asyncio
import ssl
import os
import base64
import hashlib
import aiofiles
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

class OptimizedMessageHandler(Message):
    """Handler that stores messages asynchronously to local files."""
    
    def __init__(self, messages_dir="messages", enable_async=True):
        super().__init__()
        self.messages_dir = messages_dir
        self.enable_async = enable_async
        os.makedirs(self.messages_dir, exist_ok=True)
    
    async def handle_message_async(self, message):
        """Store message asynchronously to local file."""
        # Generate unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        msg_bytes = bytes(message)
        msg_hash = hashlib.md5(msg_bytes).hexdigest()[:8]
        filename = f"{timestamp}_{msg_hash}.eml"
        filepath = os.path.join(self.messages_dir, filename)
        
        # Save message asynchronously
        try:
            async with aiofiles.open(filepath, 'wb') as f:
                await f.write(msg_bytes)
            # Don't print in production - use logging instead
            # print(f"Message saved to {filepath}")
            return filepath
        except Exception as e:
            # Log error instead of printing
            print(f"Error saving message: {e}")
            return None
    
    def handle_message(self, message):
        """Store message to local file (sync fallback or async wrapper)."""
        if self.enable_async:
            # Schedule async write (fire and forget for performance)
            # This allows the handler to return immediately
            asyncio.create_task(self.handle_message_async(message))
            # Return immediately without waiting
            return None
        else:
            # Synchronous fallback
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            msg_bytes = bytes(message)
            msg_hash = hashlib.md5(msg_bytes).hexdigest()[:8]
            filename = f"{timestamp}_{msg_hash}.eml"
            filepath = os.path.join(self.messages_dir, filename)
            with open(filepath, 'wb') as f:
                f.write(msg_bytes)
            return filepath

class AuthenticatedSMTP(SMTP):
    """SMTP server with authentication requirement."""
    
    def __init__(self, handler, auth_handler=None, require_tls_for_auth=True, *args, **kwargs):
        kwargs.setdefault('auth_require_tls', require_tls_for_auth)
        kwargs.setdefault('auth_required', False)
        super().__init__(handler, *args, **kwargs)
        self.auth_handler = auth_handler
        self.authenticated = False
        self.username = None
        self.require_tls_for_auth = require_tls_for_auth
    
    async def auth_PLAIN(self, server, args):
        """Handle AUTH PLAIN mechanism - optimized version."""
        from aiosmtpd.smtp import AuthResult, MISSING
        
        if not self.auth_handler:
            return AuthResult(success=False)
        
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
                return AuthResult(success=False, handled=True)
        
        try:
            _, login, password = login_and_password.split(b"\x00")
            username = login.decode('utf-8')
            password_str = password.decode('utf-8')
            
            # Fast path: direct dictionary lookup
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
        return await super().smtp_MAIL(arg)
    
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
    """Controller that uses AuthenticatedSMTP."""
    
    def __init__(self, handler, auth_handler=None, require_tls_for_auth=True, *args, **kwargs):
        self._auth_handler = auth_handler
        self._require_tls_for_auth = require_tls_for_auth
        super().__init__(handler, *args, **kwargs)
    
    def factory(self):
        allowed_kwargs = {'loop', 'decode_data', 'enable_SMTPUTF8', 'tls_context', 
                         'hostname', 'ident', 'timeout', 'auth_required', 'auth_require_tls'}
        kwargs = {k: v for k, v in self.SMTP_kwargs.items() 
                 if k in allowed_kwargs}
        return AuthenticatedSMTP(self.handler, self._auth_handler, 
                                 require_tls_for_auth=self._require_tls_for_auth, **kwargs)

def create_ssl_context_optimized(certfile, keyfile, ca_certfile=None, enable_session_tickets=True):
    """
    Create optimized SSL context for maximum performance.
    
    Performance optimizations:
    - Enable session tickets (reduces SSL handshake overhead)
    - Optimized cipher selection
    - Keep security strong while improving performance
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # TLS Version Configuration
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Security Options
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1
    context.options |= ssl.OP_NO_TLSv1_2
    
    # Performance: Server chooses cipher order
    context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    
    # PERFORMANCE OPTIMIZATION: Enable session tickets
    # This allows clients to reuse SSL sessions, avoiding full handshake
    # Trade-off: Slightly less secure but significantly faster
    if enable_session_tickets:
        # Don't disable tickets (default is enabled)
        pass
    else:
        context.options |= ssl.OP_NO_TICKET
    
    # Disable compression (security)
    context.options |= ssl.OP_NO_COMPRESSION
    
    # ECDH curve configuration
    try:
        if hasattr(context, 'set_ecdh_curve'):
            context.set_ecdh_curve('secp384r1')
    except (AttributeError, ValueError):
        try:
            if hasattr(context, 'set_ecdh_curve'):
                context.set_ecdh_curve('prime256v1')
        except ValueError:
            pass
    
    # Load certificates
    context.load_cert_chain(certfile, keyfile)
    
    if ca_certfile and os.path.exists(ca_certfile):
        context.load_verify_locations(ca_certfile)
    
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    return context

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Optimized SMTP server')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port-465', type=int, default=8465, help='Port for SMTPS')
    parser.add_argument('--port-587', type=int, default=8587, help='Port for STARTTLS')
    parser.add_argument('--certfile', default='certs/server-cert.pem', help='Server certificate file')
    parser.add_argument('--keyfile', default='certs/server-key.pem', help='Server private key file')
    parser.add_argument('--users', default='users.txt', help='Users file')
    parser.add_argument('--messages-dir', default='messages', help='Directory to store messages')
    parser.add_argument('--enable-session-tickets', action='store_true', default=True,
                       help='Enable SSL session tickets for performance (default: True)')
    parser.add_argument('--async-io', action='store_true', default=True,
                       help='Use async file I/O (default: True)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.certfile) or not os.path.exists(args.keyfile):
        print(f"Error: Certificate files not found. Please run generate_certificates.py first.")
        return
    
    # Create handlers
    auth_handler = UserAuthHandler(users_file=args.users)
    message_handler = OptimizedMessageHandler(messages_dir=args.messages_dir, 
                                             enable_async=args.async_io)
    
    # Create optimized SSL context
    ca_certfile = args.certfile.replace('server-cert.pem', 'ca-cert.pem') if 'server-cert' in args.certfile else None
    ssl_context = create_ssl_context_optimized(args.certfile, args.keyfile, ca_certfile,
                                              enable_session_tickets=args.enable_session_tickets)
    
    # Start SMTPS server
    print(f"Starting optimized SMTPS server on {args.host}:{args.port_465}...")
    controller_465 = AuthenticatedController(
        message_handler,
        auth_handler,
        hostname=args.host,
        port=args.port_465,
        ssl_context=ssl_context,
        require_tls_for_auth=False
    )
    controller_465.start()
    print(f"SMTPS server started on {args.host}:{args.port_465}")
    
    # Start STARTTLS server
    print(f"Starting optimized STARTTLS server on {args.host}:{args.port_587}...")
    controller_587 = AuthenticatedController(
        message_handler,
        auth_handler,
        hostname=args.host,
        port=args.port_587,
        tls_context=ssl_context,
        require_tls_for_auth=True
    )
    controller_587.start()
    print(f"STARTTLS server started on {args.host}:{args.port_587}")
    
    print("Optimized SMTP servers running. Press Ctrl+C to stop.")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        controller_465.stop()
        controller_587.stop()

if __name__ == "__main__":
    main()

