#!/usr/bin/env python3
"""
Test client for OAuth2 SMTP authentication using XOAUTH2.
"""
import smtplib
import ssl
import base64
import json
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from oauth2_mock_provider import get_token_for_user, oauth2_provider

def send_via_oauth2(host, port, email, access_token, to_email, subject, body, use_smtps=True):
    """Send email via OAuth2 authentication."""
    protocol = "SMTPS" if use_smtps else "STARTTLS"
    print(f"Connecting to {host}:{port} via {protocol} with OAuth2...")
    
    # Create SSL context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        if use_smtps:
            server = smtplib.SMTP_SSL(host, port, context=context, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls(context=context)
        
        print("Connected. Sending EHLO...")
        server.ehlo()
        
        print("Authenticating with OAuth2...")
        
        # XOAUTH2 format: base64-encoded JSON
        # {"user":"email@example.com","authMethod":"XOAUTH2","authToken":"access_token"}
        oauth2_data = {
            "user": email,
            "authMethod": "XOAUTH2",
            "authToken": access_token
        }
        oauth2_string = json.dumps(oauth2_data)
        oauth2_encoded = base64.b64encode(oauth2_string.encode('utf-8')).decode('utf-8')
        
        # Authenticate using XOAUTH2
        # XOAUTH2 format: AUTH XOAUTH2 <base64-encoded-json>
        try:
            # Send AUTH XOAUTH2 command with base64-encoded JSON
            code, response = server.docmd("AUTH", f"XOAUTH2 {oauth2_encoded}")
            
            # Check response
            if code == 235:
                print("OAuth2 authentication successful")
            elif code == 334:
                # Server is challenging, but XOAUTH2 shouldn't challenge
                # Try to send empty response or the token again
                code2, response2 = server.docmd("")
                if code2 != 235:
                    print(f"OAuth2 authentication failed: {code2} {response2}")
                    server.quit()
                    return False
            else:
                print(f"OAuth2 authentication failed: {code} {response}")
                server.quit()
                return False
        except Exception as e:
            print(f"OAuth2 authentication error: {e}")
            import traceback
            traceback.print_exc()
            server.quit()
            return False
        
        print("OAuth2 authentication successful. Sending message...")
        
        # Create and send message
        msg = MIMEMultipart()
        msg['From'] = email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        server.send_message(msg)
        print(f"Message sent successfully to {to_email}")
        server.quit()
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Test SMTP client with OAuth2')
    parser.add_argument('--host', default='127.0.0.1', help='SMTP server host')
    parser.add_argument('--port', type=int, default=8465, help='SMTP server port')
    parser.add_argument('--email', default='testuser@example.com', help='User email for OAuth2')
    parser.add_argument('--token', default=None, help='OAuth2 access token (auto-generated if not provided)')
    parser.add_argument('--to', default='test@example.org', help='Recipient email address')
    parser.add_argument('--subject', default='OAuth2 Test Message', help='Email subject')
    parser.add_argument('--body', default='This is a test message sent via OAuth2 authentication.', help='Email body')
    parser.add_argument('--smtps', action='store_true', default=True, help='Use SMTPS (default)')
    parser.add_argument('--starttls', action='store_true', help='Use STARTTLS instead of SMTPS')
    
    args = parser.parse_args()
    
    # Get or generate token
    if args.token:
        access_token = args.token
    else:
        print("Generating OAuth2 access token...")
        access_token = get_token_for_user(args.email)
        if not access_token:
            print(f"Error: Could not generate token for {args.email}")
            print("Make sure the email is authorized in oauth2_mock_provider.py")
            return
        print(f"Generated token: {access_token[:20]}...")
    
    use_smtps = args.smtps and not args.starttls
    
    success = send_via_oauth2(
        args.host, args.port, args.email, access_token,
        args.to, args.subject, args.body, use_smtps
    )
    
    if success:
        print("✅ OAuth2 authentication and message sending successful!")
    else:
        print("❌ OAuth2 authentication or message sending failed")

if __name__ == "__main__":
    main()

