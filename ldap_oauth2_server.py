#!/usr/bin/env python3
"""
OAuth2 Authorization Server with LDAP authentication.
Provides Gmail-style OAuth2 for email clients (Thunderbird, etc.).

Flow:
1. Email client redirects user to web browser
2. User authenticates against LDAP via web interface
3. OAuth2 token is issued
4. Token is returned to email client
5. Email client uses token for SMTP authentication
"""
import asyncio
import aiohttp
from aiohttp import web
import ldap3
import secrets
import hashlib
import time
import json
import base64
from datetime import datetime, timedelta
from urllib.parse import urlencode, parse_qs
import os

class LDAPOAuth2Server:
    """OAuth2 authorization server with LDAP authentication."""
    
    def __init__(self, ldap_url: str, ldap_base_dn: str, ldap_bind_dn: str, 
                 ldap_bind_password: str, ldap_user_search_base: str = None):
        """
        Initialize OAuth2 server with LDAP.
        
        Args:
            ldap_url: LDAP server URL (e.g., ldap://localhost:3389)
            ldap_base_dn: Base DN (e.g., dc=example,dc=com)
            ldap_bind_dn: Bind DN for LDAP queries (e.g., cn=Directory Manager)
            ldap_bind_password: Bind password
            ldap_user_search_base: User search base (e.g., ou=users,dc=example,dc=com)
        """
        self.ldap_url = ldap_url
        self.ldap_base_dn = ldap_base_dn
        self.ldap_bind_dn = ldap_bind_dn
        self.ldap_bind_password = ldap_bind_password
        self.ldap_user_search_base = ldap_user_search_base or f"ou=users,{ldap_base_dn}"
        
        # OAuth2 clients: {client_id: {'secret': secret, 'redirect_uris': [...]}}
        self.clients = {
            'thunderbird-email-client': {
                'secret': 'thunderbird-secret',
                'redirect_uris': [
                    'urn:ietf:wg:oauth:2.0:oob',  # Out-of-band (manual)
                    'http://127.0.0.1:*',  # Thunderbird local redirect
                    'http://localhost:*',  # Thunderbird local redirect (alternative)
                    'http://127.0.0.1:8080/callback',  # Specific Thunderbird callback
                    'http://localhost:8080/callback'  # Alternative callback
                ]
            },
            'smtp-relay-client': {
                'secret': 'smtp-relay-secret',
                'redirect_uris': ['*']
            }
        }
        
        # Authorization codes: {code: {'client_id': ..., 'email': ..., 'expires': ...}}
        self.auth_codes = {}
        
        # Access tokens: {token: {'email': ..., 'client_id': ..., 'expires': ...}}
        self.access_tokens = {}
        
        # Token TTL
        self.token_ttl = 3600  # 1 hour
    
    def authenticate_ldap_user(self, email: str, password: str) -> bool:
        """Authenticate user against LDAP."""
        try:
            # Connect to LDAP
            server = ldap3.Server(self.ldap_url, get_info=ldap3.NONE)
            conn = ldap3.Connection(server, user=self.ldap_bind_dn, password=self.ldap_bind_password, auto_bind=True)
            
            # Search for user by email (mail attribute)
            search_filter = f"(&(objectClass=inetOrgPerson)(mail={email}))"
            conn.search(self.ldap_user_search_base, search_filter, attributes=['dn', 'mail'])
            
            if not conn.entries:
                conn.unbind()
                return False
            
            user_dn = conn.entries[0].entry_dn
            
            # Try to bind as the user
            user_conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)
            user_conn.unbind()
            conn.unbind()
            
            return True
        except Exception as e:
            return False
    
    def generate_auth_code(self, client_id: str, email: str) -> str:
        """Generate authorization code."""
        code = secrets.token_urlsafe(32)
        self.auth_codes[code] = {
            'client_id': client_id,
            'email': email,
            'expires': time.time() + 600  # 10 minutes
        }
        return code
    
    def _validate_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        """Validate redirect URI against client's allowed URIs."""
        if client_id not in self.clients:
            return False
        
        allowed_uris = self.clients[client_id]['redirect_uris']
        
        # Check exact match
        if redirect_uri in allowed_uris:
            return True
        
        # Check wildcard patterns
        for allowed in allowed_uris:
            if allowed == '*':
                return True
            if allowed.endswith(':*'):
                # Pattern like http://127.0.0.1:*
                base = allowed[:-2]  # Remove ':*'
                if redirect_uri.startswith(base):
                    return True
            elif '*' in allowed:
                # Simple wildcard pattern
                import fnmatch
                if fnmatch.fnmatch(redirect_uri, allowed):
                    return True
        
        return False
    
    def exchange_code_for_token(self, code: str, client_id: str, client_secret: str, redirect_uri: str = None) -> dict:
        """Exchange authorization code for access token."""
        if code not in self.auth_codes:
            return None
        
        code_info = self.auth_codes[code]
        
        # Verify client
        if code_info['client_id'] != client_id:
            return None
        
        if client_id not in self.clients:
            return None
        
        if self.clients[client_id]['secret'] != client_secret:
            return None
        
        # Validate redirect_uri if provided (RFC 6749 section 4.1.3)
        if redirect_uri and not self._validate_redirect_uri(client_id, redirect_uri):
            return None
        
        # Check expiration
        if time.time() > code_info['expires']:
            del self.auth_codes[code]
            return None
        
        # Generate access token
        token_data = f"{code_info['email']}:{client_id}:{time.time()}"
        access_token = hashlib.sha256(token_data.encode()).hexdigest()
        
        # Store token
        self.access_tokens[access_token] = {
            'email': code_info['email'],
            'client_id': client_id,
            'expires': time.time() + self.token_ttl
        }
        
        # Remove used code
        del self.auth_codes[code]
        
        return {
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': self.token_ttl,
            'scope': 'smtp.send'
        }
    
    def validate_token(self, token: str) -> dict:
        """Validate access token and return user info."""
        if token not in self.access_tokens:
            return None
        
        token_info = self.access_tokens[token]
        
        # Check expiration
        if time.time() > token_info['expires']:
            del self.access_tokens[token]
            return None
        
        email = token_info['email']
        domain = email.split('@', 1)[1].lower() if '@' in email else None
        
        return {
            'user': email,
            'domain': domain,
            'client_id': token_info['client_id'],
            'scope': 'smtp.send'
        }
    
    async def authorize_handler(self, request):
        """Handle OAuth2 authorization request."""
        params = request.query
        
        client_id = params.get('client_id')
        redirect_uri = params.get('redirect_uri', 'urn:ietf:wg:oauth:2.0:oob')
        response_type = params.get('response_type', 'code')
        scope = params.get('scope', 'smtp.send')
        state = params.get('state')
        
        if client_id not in self.clients:
            return web.Response(text="Invalid client_id", status=400)
        
        if response_type != 'code':
            return web.Response(text="Only 'code' response_type supported", status=400)
        
        # Validate redirect URI
        if not self._validate_redirect_uri(client_id, redirect_uri):
            return web.Response(text="Invalid redirect_uri", status=400)
        
        # Show login page
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SMTP Relay - OAuth2 Login</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }}
                input {{ width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }}
                button {{ width: 100%; padding: 10px; background: #007bff; color: white; border: none; cursor: pointer; }}
                button:hover {{ background: #0056b3; }}
                .error {{ color: red; }}
            </style>
        </head>
        <body>
            <h2>SMTP Relay Authentication</h2>
            <form method="post" action="/oauth2/authorize">
                <input type="hidden" name="client_id" value="{client_id}">
                <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                <input type="hidden" name="state" value="{state or ''}">
                <input type="hidden" name="scope" value="{scope}">
                <label>Email:</label>
                <input type="email" name="email" required>
                <label>Password:</label>
                <input type="password" name="password" required>
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')
    
    async def authorize_post_handler(self, request):
        """Handle OAuth2 authorization POST (login)."""
        data = await request.post()
        
        email = data.get('email')
        password = data.get('password')
        client_id = data.get('client_id')
        redirect_uri = data.get('redirect_uri', 'urn:ietf:wg:oauth:2.0:oob')
        state = data.get('state')
        scope = data.get('scope', 'smtp.send')
        
        if not email or not password:
            return web.Response(text="Email and password required", status=400)
        
        # Authenticate against LDAP
        if not self.authenticate_ldap_user(email, password):
            html = """
            <!DOCTYPE html>
            <html>
            <head><title>Login Failed</title></head>
            <body>
                <h2>Authentication Failed</h2>
                <p class="error">Invalid email or password.</p>
                <a href="javascript:history.back()">Go Back</a>
            </body>
            </html>
            """
            return web.Response(text=html, content_type='text/html')
        
        # Validate redirect URI
        if not self._validate_redirect_uri(client_id, redirect_uri):
            return web.Response(text="Invalid redirect_uri", status=400)
        
        # Generate authorization code
        code = self.generate_auth_code(client_id, email)
        
        # Redirect with code (Gmail-style automatic flow)
        if redirect_uri == 'urn:ietf:wg:oauth:2.0:oob':
            # Out-of-band - show code to user (fallback for manual entry)
            html = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Authorization Code</title></head>
            <body>
                <h2>Authorization Successful</h2>
                <p>Your authorization code:</p>
                <p><strong>{code}</strong></p>
                <p>Please enter this code in your email client.</p>
            </body>
            </html>
            """
            return web.Response(text=html, content_type='text/html')
        else:
            # Automatic redirect to Thunderbird callback (Gmail-style)
            redirect_url = f"{redirect_uri}?code={code}"
            if state:
                redirect_url += f"&state={state}"
            # Close window script for seamless experience
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authorization Successful</title>
                <script>
                    // Redirect to Thunderbird callback
                    window.location.href = "{redirect_url}";
                    // Close window after 2 seconds if redirect doesn't work
                    setTimeout(function() {{
                        window.close();
                    }}, 2000);
                </script>
            </head>
            <body>
                <h2>Authorization Successful</h2>
                <p>Redirecting to Thunderbird...</p>
                <p>If this window doesn't close automatically, you can close it.</p>
                <script>
                    // Also try immediate redirect
                    window.location.href = "{redirect_url}";
                </script>
            </body>
            </html>
            """
            return web.Response(text=html, content_type='text/html')
    
    async def token_handler(self, request):
        """Handle OAuth2 token request."""
        data = await request.post()
        
        grant_type = data.get('grant_type')
        code = data.get('code')
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        redirect_uri = data.get('redirect_uri')
        
        if grant_type != 'authorization_code':
            return web.json_response({'error': 'unsupported_grant_type'}, status=400)
        
        if not code or not client_id or not client_secret:
            return web.json_response({'error': 'invalid_request'}, status=400)
        
        # Exchange code for token (with redirect_uri validation)
        token_response = self.exchange_code_for_token(code, client_id, client_secret, redirect_uri)
        
        if not token_response:
            return web.json_response({'error': 'invalid_grant'}, status=400)
        
        return web.json_response(token_response)
    
    async def userinfo_handler(self, request):
        """Handle userinfo request (for token validation)."""
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return web.json_response({'error': 'invalid_token'}, status=401)
        
        token = auth_header[7:]
        token_info = self.validate_token(token)
        
        if not token_info:
            return web.json_response({'error': 'invalid_token'}, status=401)
        
        return web.json_response({
            'email': token_info['user'],
            'sub': token_info['user']
        })
    
    def create_app(self):
        """Create aiohttp application."""
        app = web.Application()
        
        app.router.add_get('/oauth2/authorize', self.authorize_handler)
        app.router.add_post('/oauth2/authorize', self.authorize_post_handler)
        app.router.add_post('/oauth2/token', self.token_handler)
        app.router.add_get('/oauth2/userinfo', self.userinfo_handler)
        app.router.add_post('/oauth2/userinfo', self.userinfo_handler)
        
        return app

def main():
    """Start OAuth2 server."""
    import argparse
    
    parser = argparse.ArgumentParser(description='OAuth2 Authorization Server with LDAP')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=9000, help='Port to bind to')
    parser.add_argument('--ldap-url', default='ldap://localhost:3389', help='LDAP server URL')
    parser.add_argument('--ldap-base-dn', default='dc=example,dc=com', help='LDAP base DN')
    parser.add_argument('--ldap-bind-dn', default='cn=Directory Manager', help='LDAP bind DN')
    parser.add_argument('--ldap-bind-password', default='changeme', help='LDAP bind password')
    parser.add_argument('--ldap-user-search-base', default=None, help='LDAP user search base')
    
    args = parser.parse_args()
    
    server = LDAPOAuth2Server(
        ldap_url=args.ldap_url,
        ldap_base_dn=args.ldap_base_dn,
        ldap_bind_dn=args.ldap_bind_dn,
        ldap_bind_password=args.ldap_bind_password,
        ldap_user_search_base=args.ldap_user_search_base
    )
    
    app = server.create_app()
    
    print(f"Starting OAuth2 Authorization Server on {args.host}:{args.port}")
    print(f"LDAP: {args.ldap_url}")
    print(f"Authorization endpoint: http://{args.host}:{args.port}/oauth2/authorize")
    print(f"Token endpoint: http://{args.host}:{args.port}/oauth2/token")
    
    web.run_app(app, host=args.host, port=args.port)

if __name__ == "__main__":
    main()

